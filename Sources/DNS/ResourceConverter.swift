import Base

/// Converts FBD on-chain resource records to standard DNS records.
///
/// This module translates the compact FBD resource format stored in the
/// blockchain into DNS wire format records suitable for serving in DNS
/// responses.
public enum ResourceConverter {

    /// Convert an FBD resource to DNS records for a given query.
    ///
    /// - Parameters:
    ///   - resource: The decoded FBD resource.
    ///   - tld: The top-level domain name (e.g., "example").
    ///   - qtype: The DNS query type.
    ///   - isReferral: Whether this is a referral (subdomain query) or authoritative answer.
    /// - Returns: A tuple of (answers, authority, additional) DNS records.
    public static func toDNS(
        resource: Resource,
        tld: String,
        qtype: UInt16,
        isReferral: Bool,
        danePort: UInt16? = nil,
        daneProtocol: UInt8? = nil
    ) throws -> (answers: [DNSRecord], authority: [DNSRecord], additional: [DNSRecord]) {
        let fqdn = tld + "."

        // DANE query: serve matching TLSA records
        if let danePort = danePort, let daneProtocol = daneProtocol {
            let answers = buildTLSARecords(
                resource: resource, fqdn: fqdn,
                danePort: danePort, daneProtocol: daneProtocol
            )
            return (answers: answers, authority: [], additional: [])
        }

        if isReferral {
            return try buildReferral(resource: resource, fqdn: fqdn)
        }

        // Direct TLD query
        //
        // Per RFC 1034 §3.6.2: if a CNAME exists and the query type is not
        // CNAME itself, return the CNAME so the client can chase the alias.
        let hasCNAME = !resource.hasNS && resource.records.contains { if case .cname = $0 { return true }; return false }

        switch qtype {
        case DNSType.ds.rawValue:
            let answers = try buildDSRecords(resource: resource, fqdn: fqdn)
            return (answers: answers, authority: [], additional: [])

        case DNSType.txt.rawValue where !resource.hasNS:
            let answers = buildTXTRecords(resource: resource, fqdn: fqdn)
            return (answers: answers, authority: [], additional: [])

        case DNSType.a.rawValue where !resource.hasNS:
            let answers = buildARecords(resource: resource, fqdn: fqdn)
            if answers.isEmpty && hasCNAME {
                return (answers: try buildCNAMERecords(resource: resource, fqdn: fqdn), authority: [], additional: [])
            }
            return (answers: answers, authority: [], additional: [])

        case DNSType.aaaa.rawValue where !resource.hasNS:
            let answers = buildAAAARecords(resource: resource, fqdn: fqdn)
            if answers.isEmpty && hasCNAME {
                return (answers: try buildCNAMERecords(resource: resource, fqdn: fqdn), authority: [], additional: [])
            }
            return (answers: answers, authority: [], additional: [])

        case DNSType.cname.rawValue where !resource.hasNS:
            let answers = try buildCNAMERecords(resource: resource, fqdn: fqdn)
            return (answers: answers, authority: [], additional: [])

        case DNSType.mx.rawValue where !resource.hasNS:
            let answers = try buildMXRecords(resource: resource, fqdn: fqdn)
            return (answers: answers, authority: [], additional: [])

        case DNSType.tlsa.rawValue where !resource.hasNS:
            let answers = buildTLSARecords(resource: resource, fqdn: fqdn)
            return (answers: answers, authority: [], additional: [])

        case DNSType.caa.rawValue where !resource.hasNS:
            let answers = buildCAARecords(resource: resource, fqdn: fqdn)
            return (answers: answers, authority: [], additional: [])

        default:
            // Return referral for everything else
            return try buildReferral(resource: resource, fqdn: fqdn)
        }
    }

    // MARK: - Referral

    /// Build a referral response (NS + DS + glue).
    private static func buildReferral(
        resource: Resource,
        fqdn: String
    ) throws -> (answers: [DNSRecord], authority: [DNSRecord], additional: [DNSRecord]) {
        var authority = [DNSRecord]()
        var additional = [DNSRecord]()
        var seenNS = Set<String>()

        for record in resource.records {
            switch record {
            case .ns(let nsName):
                if seenNS.insert(nsName).inserted {
                    authority.append(try DNSRecord.ns(name: fqdn, ns: nsName))
                }

            case .glue4(let nsName, let address):
                if seenNS.insert(nsName).inserted {
                    authority.append(try DNSRecord.ns(name: fqdn, ns: nsName))
                }
                additional.append(DNSRecord.a(name: nsName, ip: address))

            case .glue6(let nsName, let address):
                if seenNS.insert(nsName).inserted {
                    authority.append(try DNSRecord.ns(name: fqdn, ns: nsName))
                }
                additional.append(DNSRecord.aaaa(name: nsName, ip: address))

            case .synth4(let address):
                let nsName = synthName(ipv4: address)
                if seenNS.insert(nsName).inserted {
                    authority.append(try DNSRecord.ns(name: fqdn, ns: nsName))
                }
                additional.append(DNSRecord.a(name: nsName, ip: address))

            case .synth6(let address):
                let nsName = synthName(ipv6: address)
                if seenNS.insert(nsName).inserted {
                    authority.append(try DNSRecord.ns(name: fqdn, ns: nsName))
                }
                additional.append(DNSRecord.aaaa(name: nsName, ip: address))

            case .ds(let keyTag, let algorithm, let digestType, let digest):
                authority.append(DNSRecord.ds(
                    name: fqdn,
                    keyTag: keyTag,
                    algorithm: algorithm,
                    digestType: digestType,
                    digest: digest
                ))

            case .txt, .a, .aaaa, .cname, .mx, .tlsa, .caa, .sub, .wallet:
                // These records are not included in referrals
                break
            }
        }

        return (answers: [], authority: authority, additional: additional)
    }

    // MARK: - DS Records

    private static func buildDSRecords(resource: Resource, fqdn: String) throws -> [DNSRecord] {
        resource.dsRecords.compactMap { record -> DNSRecord? in
            guard case .ds(let keyTag, let algorithm, let digestType, let digest) = record else {
                return nil
            }
            return DNSRecord.ds(
                name: fqdn,
                keyTag: keyTag,
                algorithm: algorithm,
                digestType: digestType,
                digest: digest
            )
        }
    }

    // MARK: - TXT Records

    private static func buildTXTRecords(resource: Resource, fqdn: String) -> [DNSRecord] {
        resource.txtRecords.compactMap { record -> DNSRecord? in
            guard case .txt(let strings) = record else {
                return nil
            }
            return DNSRecord.txt(name: fqdn, strings: strings)
        }
    }

    // MARK: - A Records

    private static func buildARecords(resource: Resource, fqdn: String) -> [DNSRecord] {
        resource.records.compactMap { record -> DNSRecord? in
            guard case .a(let address) = record else { return nil }
            return DNSRecord.a(name: fqdn, ip: address)
        }
    }

    // MARK: - AAAA Records

    private static func buildAAAARecords(resource: Resource, fqdn: String) -> [DNSRecord] {
        resource.records.compactMap { record -> DNSRecord? in
            guard case .aaaa(let address) = record else { return nil }
            return DNSRecord.aaaa(name: fqdn, ip: address)
        }
    }

    // MARK: - CNAME Records

    private static func buildCNAMERecords(resource: Resource, fqdn: String) throws -> [DNSRecord] {
        try resource.records.compactMap { record -> DNSRecord? in
            guard case .cname(let target) = record else { return nil }
            return try DNSRecord.cname(name: fqdn, target: target)
        }
    }

    // MARK: - MX Records

    private static func buildMXRecords(resource: Resource, fqdn: String) throws -> [DNSRecord] {
        try resource.records.compactMap { record -> DNSRecord? in
            guard case .mx(let preference, let exchange) = record else { return nil }
            return try DNSRecord.mx(name: fqdn, preference: preference, exchange: exchange)
        }
    }

    // MARK: - TLSA Records

    /// Build TLSA records, optionally filtered by port/protocol from a DANE query.
    ///
    /// When `danePort` and `daneProtocol` are provided (from a `_port._proto.name` query),
    /// only matching TLSA records are returned. Otherwise all TLSA records are returned.
    private static func buildTLSARecords(
        resource: Resource,
        fqdn: String,
        danePort: UInt16? = nil,
        daneProtocol: UInt8? = nil
    ) -> [DNSRecord] {
        resource.records.compactMap { record -> DNSRecord? in
            guard case .tlsa(let port, let proto, let usage, let selector, let matchingType, let certificate) = record else { return nil }
            // Filter by port/protocol if specified
            if let dp = danePort, dp != port { return nil }
            if let dpr = daneProtocol, dpr != proto { return nil }
            let ownerName = "_\(port)._\(protocolLabel(proto)).\(fqdn)"
            return DNSRecord.tlsa(name: ownerName, usage: usage, selector: selector, matchingType: matchingType, certificate: certificate)
        }
    }

    /// Convert IANA protocol number to DNS label.
    private static func protocolLabel(_ proto: UInt8) -> String {
        switch proto {
        case 6:   return "tcp"
        case 17:  return "udp"
        case 132: return "sctp"
        default:  return "\(proto)"
        }
    }

    /// Parse a DANE prefix from a query name.
    ///
    /// `_443._tcp.uk.` → (port: 443, protocol: 6, baseName: "uk.")
    /// Returns nil if the name doesn't have a valid DANE prefix.
    public static func parseDANEPrefix(_ qname: String) -> (port: UInt16, protocol: UInt8, baseFQDN: String)? {
        let name = qname.hasSuffix(".") ? qname : qname + "."
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        // Need at least 3 labels: _port, _proto, name, "" (trailing dot)
        guard labels.count >= 4 else { return nil }
        guard labels[0].hasPrefix("_"), labels[1].hasPrefix("_") else { return nil }

        let portStr = String(labels[0].dropFirst())
        guard let port = UInt16(portStr) else { return nil }

        let protoStr = String(labels[1].dropFirst()).lowercased()
        let proto: UInt8
        switch protoStr {
        case "tcp":  proto = 6
        case "udp":  proto = 17
        case "sctp": proto = 132
        default: return nil
        }

        let baseFQDN = labels[2...].joined(separator: ".")
        guard !baseFQDN.isEmpty, baseFQDN != "." else { return nil }
        return (port: port, protocol: proto, baseFQDN: baseFQDN)
    }

    // MARK: - CAA Records

    private static func buildCAARecords(resource: Resource, fqdn: String) -> [DNSRecord] {
        resource.records.compactMap { record -> DNSRecord? in
            guard case .caa(let flags, let tag, let value) = record else { return nil }
            return DNSRecord.caa(name: fqdn, flags: flags, tag: tag, value: value)
        }
    }

    // MARK: - Synthetic Names

    /// Generate a synthetic NS name from an IPv4 address.
    ///
    /// Format: `_<base32hex(address)>._synth.`
    public static func synthName(ipv4 address: [UInt8]) -> String {
        let encoded = base32HexEncode(address)
        return "_\(encoded)._synth."
    }

    /// Generate a synthetic NS name from an IPv6 address.
    public static func synthName(ipv6 address: [UInt8]) -> String {
        let encoded = base32HexEncode(address)
        return "_\(encoded)._synth."
    }

    /// Decode an IPv4 address from a synthetic name.
    public static func decodeSynth4(_ name: String) -> [UInt8]? {
        guard name.hasSuffix("._synth.") || name.hasSuffix("._synth") else { return nil }
        let parts = name.split(separator: ".")
        guard parts.count >= 2, parts[0].hasPrefix("_") else { return nil }
        let encoded = String(parts[0].dropFirst()) // remove "_"
        guard let decoded = base32HexDecode(encoded), decoded.count == 4 else { return nil }
        return decoded
    }

    /// Decode an IPv6 address from a synthetic name.
    public static func decodeSynth6(_ name: String) -> [UInt8]? {
        guard name.hasSuffix("._synth.") || name.hasSuffix("._synth") else { return nil }
        let parts = name.split(separator: ".")
        guard parts.count >= 2, parts[0].hasPrefix("_") else { return nil }
        let encoded = String(parts[0].dropFirst())
        guard let decoded = base32HexDecode(encoded), decoded.count == 16 else { return nil }
        return decoded
    }

    // MARK: - Base32hex (RFC 4648)

    private static let base32HexChars = Array("0123456789abcdefghijklmnopqrstuv")

    /// Encode bytes to base32hex (lowercase, no padding).
    public static func base32HexEncode(_ data: [UInt8]) -> String {
        var result = [Character]()
        var buffer: UInt64 = 0
        var bits = 0

        for byte in data {
            buffer = (buffer << 8) | UInt64(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                let index = Int((buffer >> bits) & 0x1F)
                result.append(base32HexChars[index])
            }
        }

        if bits > 0 {
            let index = Int((buffer << (5 - bits)) & 0x1F)
            result.append(base32HexChars[index])
        }

        return String(result)
    }

    /// Decode base32hex (lowercase, no padding) to bytes.
    public static func base32HexDecode(_ string: String) -> [UInt8]? {
        var result = [UInt8]()
        var buffer: UInt64 = 0
        var bits = 0

        for ch in string.lowercased() {
            let value: UInt64
            switch ch {
            case "0"..."9": value = UInt64(ch.asciiValue! - 48)
            case "a"..."v": value = UInt64(ch.asciiValue! - 97 + 10)
            default: return nil
            }
            buffer = (buffer << 5) | value
            bits += 5
            if bits >= 8 {
                bits -= 8
                result.append(UInt8((buffer >> bits) & 0xFF))
            }
        }

        return result
    }
}
