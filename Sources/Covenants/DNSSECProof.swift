import Base
import ExtCrypto

/// A single DNS record within a proof link (owner name + type + class + rdata).
public struct DNSSECProofRecord: Sendable, Equatable {
    public let ownerName: [UInt8]  // DNS wire format
    public let type: UInt16
    public let rclass: UInt16
    public let rdata: [UInt8]

    public init(ownerName: [UInt8], type: UInt16, rclass: UInt16, rdata: [UInt8]) {
        self.ownerName = ownerName
        self.type = type
        self.rclass = rclass
        self.rdata = rdata
    }
}

/// One link in the DNSSEC proof chain: an RRset + its covering RRSIG.
public struct DNSSECProofLink: Sendable, Equatable {
    public let records: [DNSSECProofRecord]
    public let rrsigRdata: [UInt8]

    public init(records: [DNSSECProofRecord], rrsigRdata: [UInt8]) {
        self.records = records
        self.rrsigRdata = rrsigRdata
    }
}

/// A complete DNSSEC proof chain for premium name verification.
///
/// Contains the chain of trust from the DNS root to the TXT record proving
/// ICANN domain ownership for a premium name.
public struct DNSSECProof: Sendable, Equatable {
    /// Proof format version.
    public static let currentVersion: UInt8 = 0x01

    /// The chain of proof links from root to leaf.
    public let links: [DNSSECProofLink]

    /// The claimed FBD name (e.g., "eskimo").
    public let claimedName: String

    /// The ICANN domain used as proof (e.g., "eskimo.software").
    public let domain: String

    public init(links: [DNSSECProofLink], claimedName: String, domain: String) {
        self.links = links
        self.claimedName = claimedName
        self.domain = domain
    }

    // MARK: - Serialization

    /// Serialize to compact binary format for covenant item storage.
    ///
    /// Format:
    /// ```
    /// [1B] version (0x01)
    /// [1B] link count
    /// Per link:
    ///   [1B] record count
    ///   Per record: [1B name_len][name_wire][2B type][2B class][2B rdata_len][rdata]
    ///   [2B rrsig_rdata_len][rrsig_rdata]
    /// [1B] claimed_name_len + [name UTF-8]
    /// [1B] domain_len + [domain UTF-8]
    /// ```
    public func serialize() -> [UInt8] {
        var data = [UInt8]()
        data.append(Self.currentVersion)
        data.append(UInt8(links.count))

        for link in links {
            data.append(UInt8(link.records.count))
            for record in link.records {
                // Owner name with length prefix
                let nameLen = UInt8(record.ownerName.count)
                data.append(nameLen)
                data.append(contentsOf: record.ownerName)
                // Type (BE)
                data.append(UInt8(record.type >> 8))
                data.append(UInt8(record.type & 0xFF))
                // Class (BE)
                data.append(UInt8(record.rclass >> 8))
                data.append(UInt8(record.rclass & 0xFF))
                // RDATA with length prefix
                let rdLen = UInt16(record.rdata.count)
                data.append(UInt8(rdLen >> 8))
                data.append(UInt8(rdLen & 0xFF))
                data.append(contentsOf: record.rdata)
            }
            // RRSIG RDATA with length prefix
            let sigLen = UInt16(link.rrsigRdata.count)
            data.append(UInt8(sigLen >> 8))
            data.append(UInt8(sigLen & 0xFF))
            data.append(contentsOf: link.rrsigRdata)
        }

        // Claimed name
        let nameBytes = Array(claimedName.utf8)
        data.append(UInt8(nameBytes.count))
        data.append(contentsOf: nameBytes)

        // Domain
        let domainBytes = Array(domain.utf8)
        data.append(UInt8(domainBytes.count))
        data.append(contentsOf: domainBytes)

        return data
    }

    /// Deserialize from compact binary format.
    public static func deserialize(from data: [UInt8]) throws -> DNSSECProof {
        guard !data.isEmpty else {
            throw DNSSECError.invalidProofFormat("empty proof data")
        }

        var offset = 0

        func readByte() throws -> UInt8 {
            guard offset < data.count else {
                throw DNSSECError.invalidProofFormat("unexpected end of proof at offset \(offset)")
            }
            let b = data[offset]
            offset += 1
            return b
        }

        func readUInt16BE() throws -> UInt16 {
            let hi = try readByte()
            let lo = try readByte()
            return UInt16(hi) << 8 | UInt16(lo)
        }

        func readBytes(_ count: Int) throws -> [UInt8] {
            guard offset + count <= data.count else {
                throw DNSSECError.invalidProofFormat("unexpected end of proof reading \(count) bytes at offset \(offset)")
            }
            let bytes = Array(data[offset..<(offset + count)])
            offset += count
            return bytes
        }

        let version = try readByte()
        guard version == currentVersion else {
            throw DNSSECError.invalidProofFormat("unsupported proof version \(version)")
        }

        let linkCount = Int(try readByte())
        var links = [DNSSECProofLink]()

        for _ in 0..<linkCount {
            let recordCount = Int(try readByte())
            var records = [DNSSECProofRecord]()
            for _ in 0..<recordCount {
                let nameLen = Int(try readByte())
                let ownerName = try readBytes(nameLen)
                let type = try readUInt16BE()
                let rclass = try readUInt16BE()
                let rdLen = Int(try readUInt16BE())
                let rdata = try readBytes(rdLen)
                records.append(DNSSECProofRecord(ownerName: ownerName, type: type, rclass: rclass, rdata: rdata))
            }
            let sigLen = Int(try readUInt16BE())
            let rrsigRdata = try readBytes(sigLen)
            links.append(DNSSECProofLink(records: records, rrsigRdata: rrsigRdata))
        }

        let nameLen = Int(try readByte())
        let nameBytes = try readBytes(nameLen)
        let claimedName = String(decoding: nameBytes, as: UTF8.self)

        let domainLen = Int(try readByte())
        let domainBytes = try readBytes(domainLen)
        let domain = String(decoding: domainBytes, as: UTF8.self)

        return DNSSECProof(links: links, claimedName: claimedName, domain: domain)
    }
}

// MARK: - Proof Validator

/// Validates DNSSEC proof chains for premium name verification.
public enum DNSSECProofValidator {

    // MARK: - Root Trust Anchor

    /// IANA root KSK-20326 DS record.
    /// Key Tag: 20326, Algorithm: 8 (RSA/SHA-256), Digest Type: 2 (SHA-256)
    /// Digest: E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
    private static let rootDSKeyTag: UInt16 = 20326
    private static let rootDSAlgorithm: UInt8 = 8
    private static let rootDSDigestType: UInt8 = 2
    private static let rootDSDigest: [UInt8] = [
        0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39,
        0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
        0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34,
        0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
    ]

    /// DNS record type constants.
    private static let typeDNSKEY: UInt16 = 48
    private static let typeDS: UInt16 = 43
    private static let typeTXT: UInt16 = 16
    private static let typeRRSIG: UInt16 = 46

    /// Validate a serialized DNSSEC proof and extract the binding address.
    ///
    /// Walks the chain of trust from the root to the TXT record, verifying:
    /// 1. Root DNSKEY self-signed by KSK matching hardcoded trust anchor
    /// 2. Each DS → DNSKEY chain for intermediate zones
    /// 3. Final TXT record contains `fbd=<claimedName>:<bech32address>`
    /// 4. RRSIG temporal validity (with grace period)
    ///
    /// The binding address in the TXT record ties the proof to a specific wallet,
    /// preventing replay by third parties who can read the DNS record.
    ///
    /// - Parameters:
    ///   - proofBytes: Serialized proof data.
    ///   - claimedName: The FBD name being claimed.
    ///   - blockTime: Block timestamp for RRSIG temporal checks.
    ///   - gracePeriod: Seconds of slack for RRSIG inception/expiration.
    /// - Returns: The binding address as `(version, hash)` from the bech32 address in the TXT record.
    public static func validateProof(
        _ proofBytes: [UInt8],
        claimedName: String,
        blockTime: UInt64,
        gracePeriod: UInt32 = 3_600,
        expectedAddressHRP: String? = nil
    ) throws -> (version: UInt8, hash: [UInt8]) {
        let proof = try DNSSECProof.deserialize(from: proofBytes)

        // Verify claimed name matches
        guard proof.claimedName.lowercased() == claimedName.lowercased() else {
            throw DNSSECError.txtRecordMismatch("claimed name mismatch: proof says '\(proof.claimedName)', expected '\(claimedName)'")
        }

        // Verify domain TLD is in the qualifying list
        let domainParts = proof.domain.lowercased().split(separator: ".")
        guard let tld = domainParts.last.map(String.init),
              NameParams.qualifyingTLDs.contains(tld) else {
            throw CovenantsError.invalidPremiumTLD(proof.domain)
        }

        // Verify the domain's SLD (second-level label) matches the claimed name.
        // e.g. for "eskimo.software", the SLD "eskimo" must equal claimedName.
        guard domainParts.count >= 2 else {
            throw DNSSECError.proofChainBroken("domain must have at least SLD.TLD")
        }
        let sld = String(domainParts[0])
        guard sld == claimedName.lowercased() else {
            throw DNSSECError.txtRecordMismatch("domain SLD '\(sld)' does not match claimed name '\(claimedName)'")
        }

        // Minimum: root DNSKEY, TLD DS, TLD DNSKEY, TXT (4 for TLDs, 6+ for deeper domains)
        guard proof.links.count >= 4 else {
            throw DNSSECError.proofChainBroken("proof chain too short: \(proof.links.count) links, need at least 4")
        }

        // Step 1: Validate root DNSKEY RRset
        let rootDNSKEYLink = proof.links[0]
        guard !rootDNSKEYLink.records.isEmpty else {
            throw DNSSECError.proofChainBroken("empty root DNSKEY link")
        }
        guard rootDNSKEYLink.records[0].type == typeDNSKEY else {
            throw DNSSECError.proofChainBroken("first link must be DNSKEY, got type \(rootDNSKEYLink.records[0].type)")
        }

        // Find the root KSK that matches our trust anchor
        let rootKSK = try findMatchingKSK(
            records: rootDNSKEYLink.records,
            dsKeyTag: rootDSKeyTag, dsAlgorithm: rootDSAlgorithm,
            dsDigestType: rootDSDigestType, dsDigest: rootDSDigest
        )
        guard let ksk = rootKSK else {
            throw DNSSECError.proofChainBroken("no root DNSKEY matches trust anchor DS")
        }

        // Verify root DNSKEY RRSIG is self-signed by root KSK
        let rootRRSIG = try DNSSECVerifier.parseRRSIG(rootDNSKEYLink.rrsigRdata)
        try checkRRSIGTemporal(rrsig: rootRRSIG, blockTime: blockTime, gracePeriod: gracePeriod)

        let rootRRset = rootDNSKEYLink.records.map { rec in
            (ownerName: rec.ownerName, type: rec.type, rclass: rec.rclass, rdata: rec.rdata)
        }
        guard try DNSSECVerifier.verifyRRSIG(rrsig: rootRRSIG, rrset: rootRRset, dnskey: ksk) else {
            throw DNSSECError.proofChainBroken("root DNSKEY RRSIG verification failed")
        }

        // Step 2: Walk the chain
        // Pattern: DNSKEY (link 0) → DS (link 1) → DNSKEY (link 2) → DS (link 3) → DNSKEY (link 4) → TXT (link 5)
        // For deeper domains: add more DS → DNSKEY pairs
        var currentDNSKEYs = rootDNSKEYLink.records

        var linkIdx = 1
        while linkIdx < proof.links.count {
            let link = proof.links[linkIdx]
            guard !link.records.isEmpty else {
                throw DNSSECError.proofChainBroken("empty link at index \(linkIdx)")
            }

            let recordType = link.records[0].type

            if recordType == typeDS {
                // DS link: verify it's signed by a ZSK from current DNSKEY set
                let dsRRSIG = try DNSSECVerifier.parseRRSIG(link.rrsigRdata)
                try checkRRSIGTemporal(rrsig: dsRRSIG, blockTime: blockTime, gracePeriod: gracePeriod)

                guard let zsk = findSigningKey(keyTag: dsRRSIG.keyTag, records: currentDNSKEYs) else {
                    throw DNSSECError.proofChainBroken("no ZSK with tag \(dsRRSIG.keyTag) for DS at link \(linkIdx)")
                }

                let dsRRset = link.records.map { rec in
                    (ownerName: rec.ownerName, type: rec.type, rclass: rec.rclass, rdata: rec.rdata)
                }
                guard try DNSSECVerifier.verifyRRSIG(rrsig: dsRRSIG, rrset: dsRRset, dnskey: zsk) else {
                    throw DNSSECError.proofChainBroken("DS RRSIG verification failed at link \(linkIdx)")
                }

                // Next link must be a DNSKEY that matches one of these DS records
                linkIdx += 1
                guard linkIdx < proof.links.count else {
                    throw DNSSECError.proofChainBroken("DS link at \(linkIdx - 1) has no following DNSKEY")
                }

                let dnskeyLink = proof.links[linkIdx]
                guard !dnskeyLink.records.isEmpty, dnskeyLink.records[0].type == typeDNSKEY else {
                    throw DNSSECError.proofChainBroken("expected DNSKEY after DS at link \(linkIdx)")
                }

                // Find a KSK in the DNSKEY set that matches a DS record
                var matchedKSK: DNSKEYData?
                for dsRecord in link.records {
                    let ds = try DNSSECVerifier.parseDS(dsRecord.rdata)
                    if let matched = try findMatchingKSK(
                        records: dnskeyLink.records,
                        dsKeyTag: ds.keyTag, dsAlgorithm: ds.algorithm,
                        dsDigestType: ds.digestType, dsDigest: ds.digest
                    ) {
                        matchedKSK = matched
                        break
                    }
                }

                guard let validKSK = matchedKSK else {
                    throw DNSSECError.proofChainBroken("no DNSKEY matches DS at link \(linkIdx)")
                }

                // Verify DNSKEY RRSIG is signed by matching KSK
                let dnskeyRRSIG = try DNSSECVerifier.parseRRSIG(dnskeyLink.rrsigRdata)
                try checkRRSIGTemporal(rrsig: dnskeyRRSIG, blockTime: blockTime, gracePeriod: gracePeriod)

                let dnskeyRRset = dnskeyLink.records.map { rec in
                    (ownerName: rec.ownerName, type: rec.type, rclass: rec.rclass, rdata: rec.rdata)
                }
                guard try DNSSECVerifier.verifyRRSIG(rrsig: dnskeyRRSIG, rrset: dnskeyRRset, dnskey: validKSK) else {
                    throw DNSSECError.proofChainBroken("DNSKEY RRSIG verification failed at link \(linkIdx)")
                }

                currentDNSKEYs = dnskeyLink.records

            } else if recordType == typeTXT {
                // Final TXT link: verify it's signed by a ZSK from current DNSKEY set
                let txtRRSIG = try DNSSECVerifier.parseRRSIG(link.rrsigRdata)
                try checkRRSIGTemporal(rrsig: txtRRSIG, blockTime: blockTime, gracePeriod: gracePeriod)

                guard let zsk = findSigningKey(keyTag: txtRRSIG.keyTag, records: currentDNSKEYs) else {
                    throw DNSSECError.proofChainBroken("no ZSK with tag \(txtRRSIG.keyTag) for TXT at link \(linkIdx)")
                }

                let txtRRset = link.records.map { rec in
                    (ownerName: rec.ownerName, type: rec.type, rclass: rec.rclass, rdata: rec.rdata)
                }
                guard try DNSSECVerifier.verifyRRSIG(rrsig: txtRRSIG, rrset: txtRRset, dnskey: zsk) else {
                    throw DNSSECError.proofChainBroken("TXT RRSIG verification failed at link \(linkIdx)")
                }

                // Verify TXT contains fbd=<claimedName>:<bech32address>
                let prefix = "fbd=\(claimedName.lowercased()):"
                var bindingAddress: (version: UInt8, hash: [UInt8])?
                for record in link.records {
                    let txtStrings = parseTXTRdata(record.rdata)
                    for txt in txtStrings {
                        let lower = txt.lowercased()
                        if lower.hasPrefix(prefix) {
                            let addrString = String(txt.dropFirst(prefix.count))
                            guard !addrString.isEmpty else {
                                throw DNSSECError.txtRecordMismatch("TXT record has empty address after '\(prefix)'")
                            }
                            guard let (hrp, data5bit) = Bech32.decode(addrString) else {
                                throw DNSSECError.txtRecordMismatch("invalid bech32 address in TXT record: \(addrString)")
                            }
                            if let expected = expectedAddressHRP, hrp != expected {
                                // Wrong network — skip this record, don't fail
                                continue
                            }
                            guard !data5bit.isEmpty else {
                                throw DNSSECError.txtRecordMismatch("bech32 address has no data")
                            }
                            let version = data5bit[0]
                            guard let hash = Bech32.convertBits(from: 5, to: 8, data: Array(data5bit.dropFirst()), pad: false) else {
                                throw DNSSECError.txtRecordMismatch("invalid bech32 witness program")
                            }
                            bindingAddress = (version: version, hash: hash)
                            break
                        }
                    }
                    if bindingAddress != nil { break }
                }
                guard let binding = bindingAddress else {
                    throw DNSSECError.txtRecordMismatch("TXT record does not contain '\(prefix)<address>'")
                }

                return binding

            } else {
                throw DNSSECError.proofChainBroken("unexpected record type \(recordType) at link \(linkIdx)")
            }

            linkIdx += 1
        }

        throw DNSSECError.proofChainBroken("proof chain ended without TXT record")
    }

    // MARK: - Helpers

    /// Find a DNSKEY in the RRset that matches a DS record's digest.
    private static func findMatchingKSK(
        records: [DNSSECProofRecord],
        dsKeyTag: UInt16,
        dsAlgorithm: UInt8,
        dsDigestType: UInt8,
        dsDigest: [UInt8]
    ) throws -> DNSKEYData? {
        let ds = DSData(keyTag: dsKeyTag, algorithm: dsAlgorithm, digestType: dsDigestType, digest: dsDigest)

        for record in records where record.type == typeDNSKEY {
            let dnskey = try DNSSECVerifier.parseDNSKEY(record.rdata)
            guard dnskey.algorithm == dsAlgorithm else { continue }

            let keyTag = DNSSECVerifier.computeKeyTag(dnskeyRdata: record.rdata)
            guard keyTag == dsKeyTag else { continue }

            // Verify the DS digest matches
            if try DNSSECVerifier.verifyDS(ds: ds, ownerName: record.ownerName, dnskeyRdata: record.rdata) {
                return dnskey
            }
        }
        return nil
    }

    /// Find a zone key (ZSK) in the DNSKEY RRset matching a key tag.
    private static func findSigningKey(keyTag: UInt16, records: [DNSSECProofRecord]) -> DNSKEYData? {
        for record in records where record.type == typeDNSKEY {
            let computedTag = DNSSECVerifier.computeKeyTag(dnskeyRdata: record.rdata)
            if computedTag == keyTag {
                if let dnskey = try? DNSSECVerifier.parseDNSKEY(record.rdata), dnskey.isZoneKey {
                    return dnskey
                }
            }
        }
        return nil
    }

    /// Check RRSIG temporal validity using UInt64 arithmetic to prevent overflow.
    private static func checkRRSIGTemporal(rrsig: RRSIGData, blockTime: UInt64, gracePeriod: UInt32) throws {
        let bt = blockTime
        let grace = UInt64(gracePeriod)
        if bt + grace < UInt64(rrsig.inception) {
            throw DNSSECError.signatureNotYetValid
        }
        if bt > UInt64(rrsig.expiration) + grace {
            throw DNSSECError.signatureExpired
        }
    }

    /// Parse TXT RDATA into an array of strings.
    ///
    /// TXT RDATA is one or more length-prefixed character strings.
    private static func parseTXTRdata(_ rdata: [UInt8]) -> [String] {
        var strings = [String]()
        var offset = 0
        while offset < rdata.count {
            let len = Int(rdata[offset])
            offset += 1
            guard offset + len <= rdata.count else { break }
            let s = String(decoding: rdata[offset..<(offset + len)], as: UTF8.self)
            strings.append(s)
            offset += len
        }
        return strings
    }
}
