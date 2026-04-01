#if canImport(Darwin)
import Darwin
#elseif canImport(Android)
import Android
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WinSDK)
import WinSDK
#endif
import Logging

/// Pure DNS resolver: takes a query byte array, returns a response byte array.
///
/// Extracted from the former DNSChannelHandler. All resolution logic
/// (name lookup, NXDOMAIN, SERVFAIL, referrals) lives here.
public final class DNSResolver: Sendable {
    private let logger: Logger
    private let lookup: NameLookup?

    public init(logger: Logger, lookup: NameLookup? = nil) {
        self.logger = logger
        self.lookup = lookup
    }

    /// Process a raw DNS query and return a raw DNS response.
    /// Returns nil if the query is empty or unparseable.
    public func resolve(query bytes: [UInt8]) -> [UInt8]? {
        guard !bytes.isEmpty else { return nil }

        do {
            let query = try DNSMessage.decode(from: bytes)

            let qname = query.questions.first?.name ?? ""
            let qtype = query.questions.first?.type ?? 0

            let response = resolveQuery(query: query, qname: qname, qtype: qtype)
            return try response.encode()
        } catch {
            return nil
        }
    }

    /// Process a raw DNS query with sender info for logging.
    public func resolve(query bytes: [UInt8], from sender: String) -> [UInt8]? {
        guard !bytes.isEmpty else { return nil }

        do {
            let query = try DNSMessage.decode(from: bytes)

            let qname = query.questions.first?.name ?? ""
            let qtype = query.questions.first?.type ?? 0
            logger.debug("DNS query", metadata: [
                "name": "\(qname)",
                "type": "\(qtype)",
                "from": "\(sender)",
            ])

            let response = resolveQuery(query: query, qname: qname, qtype: qtype)
            return try response.encode()
        } catch {
            logger.warning("Failed to process DNS query", metadata: [
                "error": "\(error)",
                "from": "\(sender)",
            ])
            return nil
        }
    }

    // MARK: - Resolution

    private func resolveQuery(query: DNSMessage, qname: String, qtype: UInt16) -> DNSMessage {
        // No lookup configured — stub NXDOMAIN (for tests)
        guard let lookup = lookup else {
            return nxdomain(for: query, zone: ".")
        }

        // Parse DANE prefix if present (_port._proto.name)
        let dane = ResourceConverter.parseDANEPrefix(qname)
        let effectiveName: String
        if let dane = dane {
            effectiveName = dane.baseFQDN.hasSuffix(".")
                ? String(dane.baseFQDN.dropLast()) : dane.baseFQDN
        } else {
            effectiveName = qname.hasSuffix(".") ? String(qname.dropLast()) : qname
        }
        guard !effectiveName.isEmpty else {
            return nxdomain(for: query, zone: ".")
        }

        // Resolve by trying the full name first, then progressively shorter
        // names. This supports on-chain subdomains (e.g., "hello.uk" has its
        // own NameState) and falls back to a parent for NS referrals.
        let resolved: (name: String, data: [UInt8], isExact: Bool)
        do {
            guard let r = try resolveChainName(effectiveName, lookup: lookup) else {
                return nxdomain(for: query, zone: effectiveName + ".")
            }
            resolved = r
        } catch {
            logger.warning("Name lookup failed", metadata: [
                "name": "\(effectiveName)",
                "error": "\(error)",
            ])
            return servfail(for: query)
        }

        // Decode on-chain resource
        let resource: Resource
        do {
            resource = try Resource.decode(from: resolved.data)
        } catch {
            logger.warning("Failed to decode resource", metadata: [
                "name": "\(resolved.name)",
                "error": "\(error)",
            ])
            return servfail(for: query)
        }

        // Check for inline subdomain records before falling back to referral.
        // If the query was for "free.uk" and we resolved "uk", check if "uk"
        // has a SUB record for "free" and serve those records directly.
        if !resolved.isExact {
            let parent = resolved.name  // e.g., "uk"
            let prefix: String
            if effectiveName.count > parent.count + 1 {
                prefix = String(effectiveName.dropLast(parent.count + 1))
            } else {
                prefix = ""
            }
            // Single-label subdomain match
            if !prefix.isEmpty, !prefix.contains("."),
               let nested = resource.subRecords(for: prefix) {
                let subResource = Resource(records: nested)
                do {
                    let result = try ResourceConverter.toDNS(
                        resource: subResource, tld: effectiveName,
                        qtype: qtype, isReferral: false,
                        danePort: dane?.port, daneProtocol: dane?.protocol
                    )
                    let authoritative = !result.answers.isEmpty || result.authority.isEmpty
                    return DNSMessage.response(
                        for: query, rcode: .noerror, authoritative: authoritative,
                        answers: result.answers, authority: result.authority,
                        additional: result.additional
                    )
                } catch {
                    logger.warning("Failed to convert sub records", metadata: [
                        "name": "\(effectiveName)", "error": "\(error)",
                    ])
                    return servfail(for: query)
                }
            }
        }

        // Determine query type:
        // - DANE prefix → serve matching TLSA from the resolved name
        // - Exact match → authoritative answer
        // - Parent match → referral (NS delegation from parent)
        let isReferral = !resolved.isExact && dane == nil

        // Convert FBD resource to DNS records
        let result: (answers: [DNSRecord], authority: [DNSRecord], additional: [DNSRecord])
        do {
            result = try ResourceConverter.toDNS(
                resource: resource,
                tld: resolved.name,
                qtype: qtype,
                isReferral: isReferral,
                danePort: dane?.port,
                daneProtocol: dane?.protocol
            )
        } catch {
            logger.warning("Failed to convert resource to DNS", metadata: [
                "name": "\(resolved.name)",
                "error": "\(error)",
            ])
            return servfail(for: query)
        }

        // CNAME flattening: if the answer is a CNAME for an A/AAAA query,
        // resolve the target via system DNS and return the addresses directly.
        // This allows names with only a CNAME record to work for browsers and
        // other clients that can't chase cross-zone aliases.
        var answers = result.answers
        if !isReferral,
           (qtype == DNSType.a.rawValue || qtype == DNSType.aaaa.rawValue),
           answers.count == 1, answers[0].type == DNSType.cname.rawValue {
            // Extract CNAME target from the resource (before wire encoding)
            let target = resource.records.compactMap { r -> String? in
                if case .cname(let t) = r { return t }; return nil
            }.first ?? ""
            if !target.isEmpty {
                let family: Int32 = qtype == DNSType.a.rawValue ? AF_INET : AF_INET6
                let resolved = Self.resolveHost(target, family: family)
                    .filter { !Self.isPrivateIP($0) }
                if !resolved.isEmpty {
                    let fqdn = effectiveName + "."
                    answers = resolved.map { ip in
                        qtype == DNSType.a.rawValue
                            ? DNSRecord.a(name: fqdn, ip: ip)
                            : DNSRecord.aaaa(name: fqdn, ip: ip)
                    }
                }
            }
        }

        // Build successful response
        // For referrals (NS in authority), AA=false; for direct answers, AA=true
        let authoritative = !answers.isEmpty || result.authority.isEmpty

        return DNSMessage.response(
            for: query,
            rcode: .noerror,
            authoritative: authoritative,
            answers: answers,
            authority: result.authority,
            additional: result.additional
        )
    }

    // MARK: - Helpers

    /// Resolve a chain name by trying the full name first, then progressively
    /// shorter names (removing leftmost labels). Returns the resolved name,
    /// its resource data, and whether it was an exact match.
    ///
    /// Examples:
    /// - `"hello.uk"` → tries `"hello.uk"` (exact), falls back to `"uk"` (parent)
    /// - `"shop.hello.uk"` → tries `"shop.hello.uk"`, `"hello.uk"`, `"uk"`
    /// - `"uk"` → tries `"uk"` (exact)
    private func resolveChainName(
        _ name: String,
        lookup: NameLookup
    ) throws -> (name: String, data: [UInt8], isExact: Bool)? {
        var current = name
        var isFirst = true
        while !current.isEmpty {
            if let data = try lookup(current) {
                return (name: current, data: data, isExact: isFirst)
            }
            isFirst = false
            guard let dotIdx = current.firstIndex(of: ".") else { break }
            current = String(current[current.index(after: dotIdx)...])
        }
        return nil
    }

    /// Build an NXDOMAIN response with SOA in authority.
    private func nxdomain(for query: DNSMessage, zone: String) -> DNSMessage {
        let soa = (try? DNSRecord.soa(name: zone, serial: 0)) ?? nil
        return DNSMessage.response(
            for: query,
            rcode: .nxdomain,
            authoritative: true,
            answers: [],
            authority: soa.map { [$0] } ?? [],
            additional: []
        )
    }

    /// Build a SERVFAIL response.
    private func servfail(for query: DNSMessage) -> DNSMessage {
        DNSMessage.response(
            for: query,
            rcode: .servfail,
            authoritative: false,
            answers: [],
            authority: [],
            additional: []
        )
    }

    // MARK: - CNAME Flattening

    /// Resolve a hostname via system DNS (getaddrinfo), returning IP address bytes.
    ///
    /// Used for CNAME flattening: when a name has a CNAME pointing to an external
    /// domain, we resolve it and return the A/AAAA records directly.
    static func resolveHost(_ host: String, family: Int32) -> [[UInt8]] {
        let cleaned = host.hasSuffix(".") ? String(host.dropLast()) : host

        #if os(Windows)
        var hints = ADDRINFOA()
        hints.ai_family = family
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<ADDRINFOA>?
        let status = getaddrinfo(cleaned, nil, &hints, &result)
        guard status == 0, let list = result else { return [] }
        defer { freeaddrinfo(list) }

        var addresses = [[UInt8]]()
        var current: UnsafeMutablePointer<ADDRINFOA>? = list
        while let info = current {
            if family == AF_INET, info.pointee.ai_family == AF_INET {
                info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ptr in
                    var ip = ptr.pointee.sin_addr.S_un.S_addr
                    addresses.append(withUnsafeBytes(of: &ip) { Array($0) })
                }
            } else if family == AF_INET6, info.pointee.ai_family == AF_INET6 {
                info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { ptr in
                    var ip = ptr.pointee.sin6_addr
                    addresses.append(withUnsafeBytes(of: &ip) { Array($0) })
                }
            }
            current = info.pointee.ai_next
        }
        #else
        var hints = addrinfo()
        hints.ai_family = family
        #if canImport(Glibc) || canImport(Musl)
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #else
        hints.ai_socktype = SOCK_STREAM
        #endif
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(cleaned, nil, &hints, &result)
        guard status == 0, let list = result else { return [] }
        defer { freeaddrinfo(list) }

        var addresses = [[UInt8]]()
        var current: UnsafeMutablePointer<addrinfo>? = list
        while let info = current {
            if family == AF_INET, info.pointee.ai_family == AF_INET {
                let addr = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var ip = addr.sin_addr.s_addr
                addresses.append(withUnsafeBytes(of: &ip) { Array($0) })
            } else if family == AF_INET6, info.pointee.ai_family == AF_INET6 {
                let addr = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var ip = addr.sin6_addr
                addresses.append(withUnsafeBytes(of: &ip) { Array($0) })
            }
            current = info.pointee.ai_next
        }
        #endif
        return addresses
    }

    /// Check if an IP address is private/internal (SSRF protection for CNAME flattening).
    static func isPrivateIP(_ ip: [UInt8]) -> Bool {
        if ip.count == 4 {
            return ip[0] == 10                                       // 10.0.0.0/8
                || (ip[0] == 172 && (ip[1] & 0xF0) == 16)          // 172.16.0.0/12
                || (ip[0] == 192 && ip[1] == 168)                   // 192.168.0.0/16
                || ip[0] == 127                                      // 127.0.0.0/8
                || (ip[0] == 169 && ip[1] == 254)                   // 169.254.0.0/16
                || ip[0] == 0                                        // 0.0.0.0/8
        }
        if ip.count == 16 {
            if ip.dropLast().allSatisfy({ $0 == 0 }) && ip[15] == 1 { return true }  // ::1
            if (ip[0] & 0xFE) == 0xFC { return true }                                 // fc00::/7
            if ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80 { return true }               // fe80::/10
            // IPv4-mapped ::ffff:x.x.x.x
            if ip[10] == 0xFF && ip[11] == 0xFF && ip[0..<10].allSatisfy({ $0 == 0 }) {
                return isPrivateIP(Array(ip[12..<16]))
            }
        }
        return false
    }
}
