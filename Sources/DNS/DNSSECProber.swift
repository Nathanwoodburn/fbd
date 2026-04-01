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
import Base
import ExtCrypto
import Covenants

/// Client-side DNSSEC proof builder.
///
/// Queries live DNS resolvers (with DO bit set) to build complete DNSSEC proof
/// chains for premium name verification. Uses synchronous UDP I/O — DNS queries
/// complete in milliseconds, fine for interactive RPC.
public enum DNSSECProber {

    /// Build a complete DNSSEC proof chain for a premium name.
    ///
    /// Queries from root down: root DNSKEY → TLD DS → TLD DNSKEY → domain DS
    /// → domain DNSKEY → `_fbd.<domain>` TXT. Collects RRsets + RRSIGs at each step.
    ///
    /// - Parameters:
    ///   - name: The FBD name being claimed (e.g., "eskimo").
    ///   - domain: The ICANN domain used as proof (e.g., "eskimo.software").
    ///   - resolver: DNS resolver IP address.
    /// - Returns: Serialized proof bytes.
    public static func buildProof(name: String, domain: String, resolver: String = "8.8.8.8") throws -> [UInt8] {
        let parts = domain.split(separator: ".")
        guard parts.count >= 1, !domain.isEmpty else {
            throw DNSSECProberError.invalidDomain(domain)
        }

        var links = [DNSSECProofLink]()

        // 1. Root DNSKEY
        let rootDNSKEY = try queryRRset(name: ".", type: .dnskey, resolver: resolver)
        links.append(rootDNSKEY)

        if parts.count == 1 {
            // Single-label domain (TLD itself, e.g., "com")
            // Chain: root → TLD DS → TLD DNSKEY → TXT
            let tldDS = try queryRRset(name: "\(domain).", type: .ds, resolver: resolver)
            links.append(tldDS)

            let tldDNSKEY = try queryRRset(name: "\(domain).", type: .dnskey, resolver: resolver)
            links.append(tldDNSKEY)
        } else {
            // Multi-label domain (e.g., "eskimo.software")
            // Chain: root → TLD DS → TLD DNSKEY → domain DS → domain DNSKEY → TXT
            let tld = String(parts.last!)

            let tldDS = try queryRRset(name: "\(tld).", type: .ds, resolver: resolver)
            links.append(tldDS)

            let tldDNSKEY = try queryRRset(name: "\(tld).", type: .dnskey, resolver: resolver)
            links.append(tldDNSKEY)

            let domainDS = try queryRRset(name: "\(domain).", type: .ds, resolver: resolver)
            links.append(domainDS)

            let domainDNSKEY = try queryRRset(name: "\(domain).", type: .dnskey, resolver: resolver)
            links.append(domainDNSKEY)
        }

        // TXT record at _fbd.<domain>
        let txtName = "_fbd.\(domain)."
        let txtLink = try queryRRset(name: txtName, type: .txt, resolver: resolver)
        links.append(txtLink)

        let proof = DNSSECProof(links: links, claimedName: name, domain: domain)
        return proof.serialize()
    }

    // MARK: - DNS Query Engine

    /// Query a specific RRset and its covering RRSIG from a resolver.
    ///
    /// Sets the DO (DNSSEC OK) bit via an OPT record in the additional section.
    private static func queryRRset(name: String, type: DNSType, resolver: String) throws -> DNSSECProofLink {
        let queryData = try buildDNSSECQuery(name: name, type: type)
        let responseData = try sendUDPQuery(data: queryData, resolver: resolver, port: 53)
        let message = try DNSMessage.decode(from: responseData)

        // Check for errors
        guard message.header.rcode == 0 else {
            throw DNSSECProberError.dnsError(name: name, rcode: message.header.rcode)
        }

        // Collect answer records of the requested type
        var records = [DNSSECProofRecord]()
        var rrsigRdata: [UInt8]?

        for record in message.answers {
            if record.type == type.rawValue {
                let wireName = try DNSName.encode(record.name)
                records.append(DNSSECProofRecord(
                    ownerName: wireName,
                    type: record.type,
                    rclass: record.rclass,
                    rdata: record.rdata
                ))
            } else if record.type == DNSType.rrsig.rawValue {
                // Check if this RRSIG covers our requested type
                if record.rdata.count >= 2 {
                    let coveredType = UInt16(record.rdata[0]) << 8 | UInt16(record.rdata[1])
                    if coveredType == type.rawValue {
                        rrsigRdata = record.rdata
                    }
                }
            }
        }

        // Also check authority section (DS records sometimes in authority)
        if records.isEmpty {
            for record in message.authority {
                if record.type == type.rawValue {
                    let wireName = try DNSName.encode(record.name)
                    records.append(DNSSECProofRecord(
                        ownerName: wireName,
                        type: record.type,
                        rclass: record.rclass,
                        rdata: record.rdata
                    ))
                } else if record.type == DNSType.rrsig.rawValue && rrsigRdata == nil {
                    if record.rdata.count >= 2 {
                        let coveredType = UInt16(record.rdata[0]) << 8 | UInt16(record.rdata[1])
                        if coveredType == type.rawValue {
                            rrsigRdata = record.rdata
                        }
                    }
                }
            }
        }

        guard !records.isEmpty else {
            throw DNSSECProberError.noRecords(name: name, type: type.rawValue)
        }
        guard let sig = rrsigRdata else {
            throw DNSSECProberError.noRRSIG(name: name, type: type.rawValue)
        }

        return DNSSECProofLink(records: records, rrsigRdata: sig)
    }

    /// Build a DNS query with DNSSEC OK (DO) bit set.
    private static func buildDNSSECQuery(name: String, type: DNSType) throws -> [UInt8] {
        var header = DNSHeader()
        header.id = UInt16.random(in: 1...UInt16.max)
        header.recursionDesired = true
        // Set AD (Authenticated Data) flag
        header.authenticatedData = true

        let question = DNSQuestion(name: name, type: type.rawValue)

        // OPT record for EDNS0 with DO bit
        let optRdata: [UInt8] = [] // No EDNS options
        // OPT record: name=root, type=OPT(41), class=udp_size(4096), TTL=extended_rcode+flags
        // TTL field for OPT: [extended_rcode:1][version:1][flags:2]
        // DO bit is bit 15 of the flags portion (bit 15 of the 2-byte flags in TTL)
        let optTTL: UInt32 = 0x00008000 // DO bit set
        let optRecord = DNSRecord(
            name: ".",
            type: DNSType.opt.rawValue,
            rclass: 4096, // UDP payload size
            ttl: optTTL,
            rdata: optRdata
        )

        let message = DNSMessage(
            header: header,
            questions: [question],
            additional: [optRecord]
        )
        return try message.encode()
    }

    /// Send a UDP DNS query and receive the response.
    private static func sendUDPQuery(data: [UInt8], resolver: String, port: Int, timeout: Int = 5) throws -> [UInt8] {
        let sock = try SocketHandle.udp()
        defer { sock.close() }

        // Set receive timeout
        #if os(Windows)
        var timeoutMs: Int32 = Int32(timeout * 1000)
        setsockopt(sock.fd, SOL_SOCKET, SO_RCVTIMEO, &timeoutMs, Int32(MemoryLayout<Int32>.size))
        #else
        var tv = timeval()
        tv.tv_sec = timeout
        tv.tv_usec = 0
        setsockopt(sock.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        #endif

        try sock.sendTo(data, host: resolver, port: port)
        let (response, _, _) = try sock.recvFrom()

        guard !response.isEmpty else {
            throw DNSSECProberError.emptyResponse
        }

        return response
    }
}

// MARK: - Prober Errors

public enum DNSSECProberError: Error, CustomStringConvertible, Sendable {
    case invalidDomain(String)
    case dnsError(name: String, rcode: UInt8)
    case noRecords(name: String, type: UInt16)
    case noRRSIG(name: String, type: UInt16)
    case emptyResponse
    case timeout

    public var description: String {
        switch self {
        case .invalidDomain(let d): return "invalid domain: \(d)"
        case .dnsError(let name, let rcode): return "DNS error for \(name): rcode=\(rcode)"
        case .noRecords(let name, let type): return "no records of type \(typeName(type)) for \(name) (is DNSSEC enabled and DS published at parent zone?)"
        case .noRRSIG(let name, let type): return "no RRSIG covering type \(typeName(type)) for \(name)"
        case .emptyResponse: return "empty DNS response"
        case .timeout: return "DNS query timed out"
        }
    }

    private func typeName(_ type: UInt16) -> String {
        switch type {
        case 16: return "TXT"
        case 43: return "DS"
        case 46: return "RRSIG"
        case 48: return "DNSKEY"
        default: return "\(type)"
        }
    }
}
