import Crypto
import _CryptoExtras
import Base

// MARK: - DNSSEC Algorithm Types

/// DNSSEC algorithm identifiers (RFC 4034 Appendix A.1).
public enum DNSSECAlgorithm: UInt8, Sendable {
    case rsaSHA1    = 5
    case rsaSHA256  = 8
    case rsaSHA512  = 10
    case ecdsaP256  = 13
    case ecdsaP384  = 14
}

/// DNSSEC digest type identifiers (RFC 4034 Appendix A.2).
public enum DNSSECDigestType: UInt8, Sendable {
    case sha1   = 1
    case sha256 = 2
    case sha384 = 4
}

// MARK: - Parsed DNSSEC Data Structures

/// Parsed DNSKEY RDATA (RFC 4034 Section 2).
public struct DNSKEYData: Sendable {
    public let flags: UInt16
    public let protocolField: UInt8
    public let algorithm: UInt8
    public let publicKey: [UInt8]

    /// Whether this is a zone key (bit 7 of flags, counting from bit 0 at the right).
    public var isZoneKey: Bool { (flags & 0x0100) != 0 }

    /// Whether this is a Secure Entry Point (KSK) — bit 15.
    public var isSEP: Bool { (flags & 0x0001) != 0 }
}

/// Parsed RRSIG RDATA (RFC 4034 Section 3).
public struct RRSIGData: Sendable {
    public let typeCovered: UInt16
    public let algorithm: UInt8
    public let labels: UInt8
    public let originalTTL: UInt32
    public let expiration: UInt32
    public let inception: UInt32
    public let keyTag: UInt16
    public let signerName: [UInt8]  // Wire format
    public let signature: [UInt8]
}

/// Parsed DS RDATA (RFC 4034 Section 5).
public struct DSData: Sendable {
    public let keyTag: UInt16
    public let algorithm: UInt8
    public let digestType: UInt8
    public let digest: [UInt8]

    public init(keyTag: UInt16, algorithm: UInt8, digestType: UInt8, digest: [UInt8]) {
        self.keyTag = keyTag
        self.algorithm = algorithm
        self.digestType = digestType
        self.digest = digest
    }
}

// MARK: - DNSSEC Verifier

/// Low-level DNSSEC cryptographic verification.
///
/// Works with raw byte arrays — no DNS module dependency.
public enum DNSSECVerifier {

    /// Parse DNSKEY RDATA.
    public static func parseDNSKEY(_ rdata: [UInt8]) throws -> DNSKEYData {
        guard rdata.count >= 4 else {
            throw DNSSECError.malformedRecord("DNSKEY RDATA too short")
        }
        let flags = UInt16(rdata[0]) << 8 | UInt16(rdata[1])
        let proto = rdata[2]
        let algo = rdata[3]
        let pubKey = Array(rdata[4...])
        return DNSKEYData(flags: flags, protocolField: proto, algorithm: algo, publicKey: pubKey)
    }

    /// Parse RRSIG RDATA.
    public static func parseRRSIG(_ rdata: [UInt8]) throws -> RRSIGData {
        guard rdata.count >= 18 else {
            throw DNSSECError.malformedRecord("RRSIG RDATA too short")
        }
        let typeCovered = UInt16(rdata[0]) << 8 | UInt16(rdata[1])
        let algorithm = rdata[2]
        let labels = rdata[3]
        let originalTTL = readUInt32BE(rdata, offset: 4)
        let expiration = readUInt32BE(rdata, offset: 8)
        let inception = readUInt32BE(rdata, offset: 12)
        let keyTag = UInt16(rdata[16]) << 8 | UInt16(rdata[17])

        // Parse signer name in wire format starting at offset 18
        var offset = 18
        let signerNameStart = offset
        while offset < rdata.count {
            let len = Int(rdata[offset])
            if len == 0 { offset += 1; break }
            offset += 1 + len
        }
        guard offset <= rdata.count else {
            throw DNSSECError.malformedRecord("RRSIG signer name overflows")
        }
        let signerName = Array(rdata[signerNameStart..<offset])
        let signature = Array(rdata[offset...])

        return RRSIGData(
            typeCovered: typeCovered, algorithm: algorithm, labels: labels,
            originalTTL: originalTTL, expiration: expiration, inception: inception,
            keyTag: keyTag, signerName: signerName, signature: signature
        )
    }

    /// Parse DS RDATA.
    public static func parseDS(_ rdata: [UInt8]) throws -> DSData {
        guard rdata.count >= 4 else {
            throw DNSSECError.malformedRecord("DS RDATA too short")
        }
        let keyTag = UInt16(rdata[0]) << 8 | UInt16(rdata[1])
        let algorithm = rdata[2]
        let digestType = rdata[3]
        let digest = Array(rdata[4...])
        return DSData(keyTag: keyTag, algorithm: algorithm, digestType: digestType, digest: digest)
    }

    /// Compute the key tag for a DNSKEY RDATA (RFC 4034 Appendix B).
    ///
    /// The key tag is computed over the full DNSKEY RDATA (flags + protocol + algorithm + public key).
    public static func computeKeyTag(dnskeyRdata: [UInt8]) -> UInt16 {
        var ac: UInt32 = 0
        for (i, byte) in dnskeyRdata.enumerated() {
            if i & 1 == 0 {
                ac += UInt32(byte) << 8
            } else {
                ac += UInt32(byte)
            }
        }
        ac += (ac >> 16) & 0xFFFF
        return UInt16(ac & 0xFFFF)
    }

    /// Verify an RRSIG signature over an RRset.
    ///
    /// Constructs the signed data per RFC 4035 Section 5.3.2:
    /// `RRSIG_RDATA (minus signature) || canonically sorted RRset`
    ///
    /// - Parameters:
    ///   - rrsig: Parsed RRSIG data.
    ///   - rrset: Array of (ownerName wire format, type, class, rdata) tuples.
    ///   - dnskey: Parsed DNSKEY data for the signing key.
    /// - Returns: `true` if signature verifies.
    public static func verifyRRSIG(
        rrsig: RRSIGData,
        rrset: [(ownerName: [UInt8], type: UInt16, rclass: UInt16, rdata: [UInt8])],
        dnskey: DNSKEYData
    ) throws -> Bool {
        // Build the signed data
        var signedData = [UInt8]()

        // RRSIG RDATA fields (everything except the signature itself)
        signedData.append(UInt8(rrsig.typeCovered >> 8))
        signedData.append(UInt8(rrsig.typeCovered & 0xFF))
        signedData.append(rrsig.algorithm)
        signedData.append(rrsig.labels)
        appendUInt32BE(&signedData, rrsig.originalTTL)
        appendUInt32BE(&signedData, rrsig.expiration)
        appendUInt32BE(&signedData, rrsig.inception)
        signedData.append(UInt8(rrsig.keyTag >> 8))
        signedData.append(UInt8(rrsig.keyTag & 0xFF))
        signedData.append(contentsOf: rrsig.signerName)

        // Build canonical RRset entries and sort
        var rrEntries = [[UInt8]]()
        for rr in rrset {
            var entry = [UInt8]()
            // Owner name (canonical/lowercase wire format)
            entry.append(contentsOf: lowercaseWireName(rr.ownerName))
            // Type
            entry.append(UInt8(rr.type >> 8))
            entry.append(UInt8(rr.type & 0xFF))
            // Class
            entry.append(UInt8(rr.rclass >> 8))
            entry.append(UInt8(rr.rclass & 0xFF))
            // Original TTL from RRSIG
            appendUInt32BE(&entry, rrsig.originalTTL)
            // RDATA length
            let rdlen = UInt16(rr.rdata.count)
            entry.append(UInt8(rdlen >> 8))
            entry.append(UInt8(rdlen & 0xFF))
            // RDATA
            entry.append(contentsOf: rr.rdata)
            rrEntries.append(entry)
        }

        // Sort canonically (RFC 4034 Section 6.3)
        rrEntries.sort { a, b in
            for i in 0..<min(a.count, b.count) {
                if a[i] != b[i] { return a[i] < b[i] }
            }
            return a.count < b.count
        }

        for entry in rrEntries {
            signedData.append(contentsOf: entry)
        }

        // Verify based on algorithm
        guard let algo = DNSSECAlgorithm(rawValue: dnskey.algorithm) else {
            throw DNSSECError.unsupportedAlgorithm(dnskey.algorithm)
        }

        switch algo {
        case .rsaSHA256:
            return try verifyRSASHA256(signature: rrsig.signature, data: signedData, publicKey: dnskey.publicKey)
        case .rsaSHA512:
            return try verifyRSASHA512(signature: rrsig.signature, data: signedData, publicKey: dnskey.publicKey)
        case .rsaSHA1:
            return try verifyRSASHA1(signature: rrsig.signature, data: signedData, publicKey: dnskey.publicKey)
        case .ecdsaP256:
            return try verifyECDSAP256(signature: rrsig.signature, data: signedData, publicKey: dnskey.publicKey)
        case .ecdsaP384:
            return try verifyECDSAP384(signature: rrsig.signature, data: signedData, publicKey: dnskey.publicKey)
        }
    }

    /// Verify a DS record against a DNSKEY.
    ///
    /// Computes `digest(owner_wire_name || dnskey_rdata)` and compares to the DS digest.
    ///
    /// - Parameters:
    ///   - ds: Parsed DS data.
    ///   - ownerName: The owner name in DNS wire format (canonical lowercase).
    ///   - dnskeyRdata: The full DNSKEY RDATA bytes.
    /// - Returns: `true` if the DS digest matches.
    public static func verifyDS(ds: DSData, ownerName: [UInt8], dnskeyRdata: [UInt8]) throws -> Bool {
        let input = lowercaseWireName(ownerName) + dnskeyRdata

        guard let digestType = DNSSECDigestType(rawValue: ds.digestType) else {
            throw DNSSECError.unsupportedDigestType(ds.digestType)
        }

        let computed: [UInt8]
        switch digestType {
        case .sha1:
            computed = Array(Insecure.SHA1.hash(data: input))
        case .sha256:
            computed = Array(SHA256.hash(data: input))
        case .sha384:
            computed = Array(SHA384.hash(data: input))
        }

        return computed == ds.digest
    }

    // MARK: - RSA Verification

    /// Convert DNSKEY RSA public key bytes to DER-encoded SubjectPublicKeyInfo.
    ///
    /// DNSKEY RSA format:
    /// - If first byte > 0: `[exp_len:1][exponent][modulus]`
    /// - If first byte == 0: `[0][exp_len:2 BE][exponent][modulus]`
    static func rsaPublicKeyToDER(keyBytes: [UInt8]) throws -> [UInt8] {
        guard !keyBytes.isEmpty else {
            throw DNSSECError.malformedKey("empty RSA key")
        }

        let expLen: Int
        let expStart: Int
        if keyBytes[0] != 0 {
            expLen = Int(keyBytes[0])
            expStart = 1
        } else {
            guard keyBytes.count >= 3 else {
                throw DNSSECError.malformedKey("RSA key too short for 2-byte exp length")
            }
            expLen = Int(keyBytes[1]) << 8 | Int(keyBytes[2])
            expStart = 3
        }

        guard expStart + expLen <= keyBytes.count else {
            throw DNSSECError.malformedKey("RSA exponent overflows key data")
        }

        let exponent = Array(keyBytes[expStart..<(expStart + expLen)])
        let modulus = Array(keyBytes[(expStart + expLen)...])

        guard !modulus.isEmpty else {
            throw DNSSECError.malformedKey("RSA modulus is empty")
        }

        // Build DER: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { SEQUENCE { INTEGER modulus, INTEGER exponent } } }
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

        let modInteger = derInteger(modulus)
        let expInteger = derInteger(exponent)
        let innerSeq = derSequence(modInteger + expInteger)
        let bitString = derBitString(innerSeq)
        let algoSeq = derSequence(rsaOID)
        let outerSeq = derSequence(algoSeq + bitString)

        return outerSeq
    }

    private static func verifyRSASHA256(signature: [UInt8], data: [UInt8], publicKey: [UInt8]) throws -> Bool {
        let derKey = try rsaPublicKeyToDER(keyBytes: publicKey)
        guard derKey.count >= 128 else {
            throw DNSSECError.malformedKey("RSA key too small (DER length \(derKey.count), minimum 128)")
        }
        // Use unsafeDERRepresentation to allow 1024-bit keys (common in TLD ZSKs)
        let rsaKey = try _RSA.Signing.PublicKey(unsafeDERRepresentation: derKey)
        let rsaSig = _RSA.Signing.RSASignature(rawRepresentation: signature)
        // Pre-hash with SHA-256 before passing to isValidSignature
        let digest = SHA256.hash(data: data)
        return rsaKey.isValidSignature(rsaSig, for: digest, padding: .insecurePKCS1v1_5)
    }

    private static func verifyRSASHA512(signature: [UInt8], data: [UInt8], publicKey: [UInt8]) throws -> Bool {
        let derKey = try rsaPublicKeyToDER(keyBytes: publicKey)
        guard derKey.count >= 128 else {
            throw DNSSECError.malformedKey("RSA key too small (DER length \(derKey.count), minimum 128)")
        }
        let rsaKey = try _RSA.Signing.PublicKey(unsafeDERRepresentation: derKey)
        let rsaSig = _RSA.Signing.RSASignature(rawRepresentation: signature)
        let digest = SHA512.hash(data: data)
        return rsaKey.isValidSignature(rsaSig, for: digest, padding: .insecurePKCS1v1_5)
    }

    private static func verifyRSASHA1(signature: [UInt8], data: [UInt8], publicKey: [UInt8]) throws -> Bool {
        let derKey = try rsaPublicKeyToDER(keyBytes: publicKey)
        guard derKey.count >= 128 else {
            throw DNSSECError.malformedKey("RSA key too small (DER length \(derKey.count), minimum 128)")
        }
        let rsaKey = try _RSA.Signing.PublicKey(unsafeDERRepresentation: derKey)
        let rsaSig = _RSA.Signing.RSASignature(rawRepresentation: signature)
        let digest = Insecure.SHA1.hash(data: data)
        return rsaKey.isValidSignature(rsaSig, for: digest, padding: .insecurePKCS1v1_5)
    }

    // MARK: - ECDSA Verification

    /// Verify ECDSA P-256 (algorithm 13).
    ///
    /// DNSKEY format: 64 bytes (x || y, no 0x04 prefix).
    /// Signature format: 64 bytes (r || s, each 32 bytes).
    private static func verifyECDSAP256(signature: [UInt8], data: [UInt8], publicKey: [UInt8]) throws -> Bool {
        guard publicKey.count == 64 else {
            throw DNSSECError.malformedKey("P-256 public key must be 64 bytes, got \(publicKey.count)")
        }
        guard signature.count == 64 else {
            throw DNSSECError.malformedSignature("P-256 signature must be 64 bytes, got \(signature.count)")
        }

        // Add 0x04 uncompressed point prefix
        let uncompressed: [UInt8] = [0x04] + publicKey
        let p256Key = try P256.Signing.PublicKey(x963Representation: uncompressed)

        // Convert r||s to DER
        let r = Array(signature[0..<32])
        let s = Array(signature[32..<64])
        let derSig = ecdsaToDER(r: r, s: s)
        let ecSig = try P256.Signing.ECDSASignature(derRepresentation: derSig)

        let digest = SHA256.hash(data: data)
        return p256Key.isValidSignature(ecSig, for: digest)
    }

    /// Verify ECDSA P-384 (algorithm 14).
    ///
    /// DNSKEY format: 96 bytes (x || y, no 0x04 prefix).
    /// Signature format: 96 bytes (r || s, each 48 bytes).
    private static func verifyECDSAP384(signature: [UInt8], data: [UInt8], publicKey: [UInt8]) throws -> Bool {
        guard publicKey.count == 96 else {
            throw DNSSECError.malformedKey("P-384 public key must be 96 bytes, got \(publicKey.count)")
        }
        guard signature.count == 96 else {
            throw DNSSECError.malformedSignature("P-384 signature must be 96 bytes, got \(signature.count)")
        }

        let uncompressed: [UInt8] = [0x04] + publicKey
        let p384Key = try P384.Signing.PublicKey(x963Representation: uncompressed)

        let r = Array(signature[0..<48])
        let s = Array(signature[48..<96])
        let derSig = ecdsaToDER(r: r, s: s)
        let ecSig = try P384.Signing.ECDSASignature(derRepresentation: derSig)

        let digest = SHA384.hash(data: data)
        return p384Key.isValidSignature(ecSig, for: digest)
    }

    // MARK: - DER Helpers

    /// Encode an integer as a DER INTEGER (with leading 0x00 if high bit set).
    static func derInteger(_ bytes: [UInt8]) -> [UInt8] {
        // Strip leading zeros but keep at least one byte
        var stripped = bytes
        while stripped.count > 1 && stripped[0] == 0 { stripped.removeFirst() }

        // Add leading 0x00 if high bit is set (to keep it positive)
        var content = stripped
        if content[0] & 0x80 != 0 {
            content.insert(0x00, at: 0)
        }

        return [0x02] + derLength(content.count) + content
    }

    /// Encode a DER SEQUENCE wrapper.
    static func derSequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + derLength(content.count) + content
    }

    /// Encode a DER BIT STRING (with 0 unused bits).
    static func derBitString(_ content: [UInt8]) -> [UInt8] {
        [0x03] + derLength(content.count + 1) + [0x00] + content
    }

    /// Encode DER length.
    static func derLength(_ length: Int) -> [UInt8] {
        if length < 0x80 {
            return [UInt8(length)]
        } else if length < 0x100 {
            return [0x81, UInt8(length)]
        } else if length < 0x10000 {
            return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
        } else {
            return [0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
        }
    }

    /// Convert ECDSA (r, s) integers to DER signature format.
    static func ecdsaToDER(r: [UInt8], s: [UInt8]) -> [UInt8] {
        let rInt = derInteger(r)
        let sInt = derInteger(s)
        return derSequence(rInt + sInt)
    }

    // MARK: - Wire Format Helpers

    /// Lowercase all labels in a DNS wire format name (for canonical ordering).
    public static func lowercaseWireName(_ name: [UInt8]) -> [UInt8] {
        var result = name
        var i = 0
        while i < result.count {
            let len = Int(result[i])
            if len == 0 { break }
            for j in (i + 1)...(i + len) where j < result.count {
                if result[j] >= 0x41 && result[j] <= 0x5A {
                    result[j] += 0x20
                }
            }
            i += 1 + len
        }
        return result
    }

    /// Encode a domain name string to DNS wire format.
    public static func nameToWire(_ name: String) -> [UInt8] {
        let cleaned = name.hasSuffix(".") ? String(name.dropLast()) : name
        if cleaned.isEmpty { return [0] }

        var result = [UInt8]()
        let labels = cleaned.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels {
            let bytes = Array(label.utf8)
            result.append(UInt8(bytes.count))
            result.append(contentsOf: bytes)
        }
        result.append(0)
        return result
    }

    // MARK: - Private Helpers

    private static func readUInt32BE(_ data: [UInt8], offset: Int) -> UInt32 {
        UInt32(data[offset]) << 24
        | UInt32(data[offset + 1]) << 16
        | UInt32(data[offset + 2]) << 8
        | UInt32(data[offset + 3])
    }

    private static func appendUInt32BE(_ data: inout [UInt8], _ value: UInt32) {
        data.append(UInt8(value >> 24))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }
}

// MARK: - DNSSEC Errors

public enum DNSSECError: Error, Equatable, Sendable, CustomStringConvertible {
    case malformedRecord(String)
    case malformedKey(String)
    case malformedSignature(String)
    case unsupportedAlgorithm(UInt8)
    case unsupportedDigestType(UInt8)
    case verificationFailed(String)
    case proofChainBroken(String)
    case invalidProofFormat(String)
    case txtRecordMismatch(String)
    case signatureExpired
    case signatureNotYetValid

    public var description: String {
        switch self {
        case .malformedRecord(let s): return "malformed DNSSEC record: \(s)"
        case .malformedKey(let s): return "malformed DNSKEY: \(s)"
        case .malformedSignature(let s): return "malformed RRSIG: \(s)"
        case .unsupportedAlgorithm(let a): return "unsupported DNSSEC algorithm \(a)"
        case .unsupportedDigestType(let d): return "unsupported DS digest type \(d)"
        case .verificationFailed(let s): return "DNSSEC verification failed: \(s)"
        case .proofChainBroken(let s): return "DNSSEC proof chain broken: \(s)"
        case .invalidProofFormat(let s): return "invalid DNSSEC proof format: \(s)"
        case .txtRecordMismatch(let s): return "TXT record mismatch: \(s)"
        case .signatureExpired: return "RRSIG signature has expired"
        case .signatureNotYetValid: return "RRSIG signature is not yet valid"
        }
    }
}
