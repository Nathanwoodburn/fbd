import XCTest
@testable import ExtCrypto
import Base

final class DNSSECVerifierTests: XCTestCase {

    // MARK: - DNSKEY Parsing

    func testParseDNSKEY() throws {
        // Construct a minimal DNSKEY RDATA: flags=256 (ZSK), protocol=3, algorithm=8 (RSA/SHA-256)
        // followed by a dummy public key
        var rdata: [UInt8] = [
            0x01, 0x00, // flags = 256 (zone key, not SEP)
            0x03,       // protocol = 3
            0x08,       // algorithm = 8 (RSA/SHA-256)
        ]
        rdata.append(contentsOf: [UInt8](repeating: 0xAB, count: 32)) // dummy key

        let dnskey = try DNSSECVerifier.parseDNSKEY(rdata)
        XCTAssertEqual(dnskey.flags, 256)
        XCTAssertEqual(dnskey.protocolField, 3)
        XCTAssertEqual(dnskey.algorithm, 8)
        XCTAssertTrue(dnskey.isZoneKey)
        XCTAssertFalse(dnskey.isSEP)
        XCTAssertEqual(dnskey.publicKey.count, 32)
    }

    func testParseDNSKEYSEP() throws {
        // KSK: flags=257 (zone key + SEP)
        let rdata: [UInt8] = [
            0x01, 0x01, // flags = 257 (zone key + SEP)
            0x03,       // protocol = 3
            0x0D,       // algorithm = 13 (ECDSA P-256)
            // 64-byte P-256 public key
        ] + [UInt8](repeating: 0xCD, count: 64)

        let dnskey = try DNSSECVerifier.parseDNSKEY(rdata)
        XCTAssertEqual(dnskey.flags, 257)
        XCTAssertTrue(dnskey.isZoneKey)
        XCTAssertTrue(dnskey.isSEP)
        XCTAssertEqual(dnskey.algorithm, 13)
        XCTAssertEqual(dnskey.publicKey.count, 64)
    }

    func testParseDNSKEYTooShort() {
        let rdata: [UInt8] = [0x01, 0x00, 0x03]
        XCTAssertThrowsError(try DNSSECVerifier.parseDNSKEY(rdata))
    }

    // MARK: - RRSIG Parsing

    func testParseRRSIG() throws {
        // Build an RRSIG RDATA with known values
        var rdata = [UInt8]()
        // typeCovered = 48 (DNSKEY)
        rdata.append(0x00); rdata.append(0x30)
        // algorithm = 8
        rdata.append(0x08)
        // labels = 0 (root)
        rdata.append(0x00)
        // originalTTL = 172800
        rdata.append(0x00); rdata.append(0x02); rdata.append(0xA3); rdata.append(0x00)
        // expiration = 1700000000
        let exp: UInt32 = 1_700_000_000
        rdata.append(UInt8(exp >> 24)); rdata.append(UInt8((exp >> 16) & 0xFF))
        rdata.append(UInt8((exp >> 8) & 0xFF)); rdata.append(UInt8(exp & 0xFF))
        // inception = 1699000000
        let inc: UInt32 = 1_699_000_000
        rdata.append(UInt8(inc >> 24)); rdata.append(UInt8((inc >> 16) & 0xFF))
        rdata.append(UInt8((inc >> 8) & 0xFF)); rdata.append(UInt8(inc & 0xFF))
        // keyTag = 20326
        rdata.append(UInt8(20326 >> 8)); rdata.append(UInt8(20326 & 0xFF))
        // signer name = "." (root, just 0x00)
        rdata.append(0x00)
        // signature = some bytes
        rdata.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF])

        let rrsig = try DNSSECVerifier.parseRRSIG(rdata)
        XCTAssertEqual(rrsig.typeCovered, 48)
        XCTAssertEqual(rrsig.algorithm, 8)
        XCTAssertEqual(rrsig.labels, 0)
        XCTAssertEqual(rrsig.originalTTL, 172800)
        XCTAssertEqual(rrsig.expiration, 1_700_000_000)
        XCTAssertEqual(rrsig.inception, 1_699_000_000)
        XCTAssertEqual(rrsig.keyTag, 20326)
        XCTAssertEqual(rrsig.signerName, [0x00])
        XCTAssertEqual(rrsig.signature, [0xDE, 0xAD, 0xBE, 0xEF])
    }

    // MARK: - DS Parsing

    func testParseDS() throws {
        var rdata = [UInt8]()
        // keyTag = 20326
        rdata.append(UInt8(20326 >> 8)); rdata.append(UInt8(20326 & 0xFF))
        // algorithm = 8
        rdata.append(0x08)
        // digestType = 2 (SHA-256)
        rdata.append(0x02)
        // digest = 32 bytes
        let digest = [UInt8](repeating: 0x42, count: 32)
        rdata.append(contentsOf: digest)

        let ds = try DNSSECVerifier.parseDS(rdata)
        XCTAssertEqual(ds.keyTag, 20326)
        XCTAssertEqual(ds.algorithm, 8)
        XCTAssertEqual(ds.digestType, 2)
        XCTAssertEqual(ds.digest, digest)
    }

    // MARK: - Key Tag Computation

    func testComputeKeyTag() {
        // RFC 4034 Appendix B key tag computation
        // Test with a known DNSKEY RDATA
        let rdata: [UInt8] = [
            0x01, 0x01, // flags = 257
            0x03,       // protocol = 3
            0x08,       // algorithm = 8
            0x01, 0x02, 0x03, 0x04, // dummy key bytes
        ]
        let tag = DNSSECVerifier.computeKeyTag(dnskeyRdata: rdata)
        // Tag is a 16-bit checksum; just verify it's deterministic
        let tag2 = DNSSECVerifier.computeKeyTag(dnskeyRdata: rdata)
        XCTAssertEqual(tag, tag2)
    }

    func testKeyTagDifferentKeys() {
        let rdata1: [UInt8] = [0x01, 0x01, 0x03, 0x08, 0x01, 0x02]
        let rdata2: [UInt8] = [0x01, 0x01, 0x03, 0x08, 0x03, 0x04]
        let tag1 = DNSSECVerifier.computeKeyTag(dnskeyRdata: rdata1)
        let tag2 = DNSSECVerifier.computeKeyTag(dnskeyRdata: rdata2)
        XCTAssertNotEqual(tag1, tag2)
    }

    // MARK: - DS Digest Verification

    func testVerifyDSDigestSHA256() throws {
        // Create a DNSKEY RDATA
        let dnskeyRdata: [UInt8] = [0x01, 0x01, 0x03, 0x08] + [UInt8](repeating: 0xAA, count: 128)
        let ownerName: [UInt8] = [0x00] // root "."

        // Compute the expected SHA-256 digest: SHA256(owner_wire || dnskey_rdata)
        let input = ownerName + dnskeyRdata
        let digest = Array(Crypto.SHA256.hash(data: input))

        let keyTag = DNSSECVerifier.computeKeyTag(dnskeyRdata: dnskeyRdata)
        let ds = DSData(keyTag: keyTag, algorithm: 8, digestType: 2, digest: digest)

        let result = try DNSSECVerifier.verifyDS(ds: ds, ownerName: ownerName, dnskeyRdata: dnskeyRdata)
        XCTAssertTrue(result)
    }

    func testVerifyDSDigestMismatch() throws {
        let dnskeyRdata: [UInt8] = [0x01, 0x01, 0x03, 0x08] + [UInt8](repeating: 0xAA, count: 128)
        let ownerName: [UInt8] = [0x00]

        let wrongDigest = [UInt8](repeating: 0x00, count: 32)
        let ds = DSData(keyTag: 12345, algorithm: 8, digestType: 2, digest: wrongDigest)

        let result = try DNSSECVerifier.verifyDS(ds: ds, ownerName: ownerName, dnskeyRdata: dnskeyRdata)
        XCTAssertFalse(result)
    }

    // MARK: - Wire Name Helpers

    func testNameToWire() {
        let wire = DNSSECVerifier.nameToWire("example.com.")
        // Expected: [7]example[3]com[0]
        XCTAssertEqual(wire, [7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 3, 0x63, 0x6F, 0x6D, 0])
    }

    func testNameToWireRoot() {
        let wire = DNSSECVerifier.nameToWire(".")
        XCTAssertEqual(wire, [0])
    }

    func testLowercaseWireName() {
        // [3]COM[0] → [3]com[0]
        let upper: [UInt8] = [3, 0x43, 0x4F, 0x4D, 0]
        let lower = DNSSECVerifier.lowercaseWireName(upper)
        XCTAssertEqual(lower, [3, 0x63, 0x6F, 0x6D, 0])
    }

    // MARK: - DER Encoding

    func testDERInteger() {
        // Positive byte, no leading zero needed
        let result = DNSSECVerifier.derInteger([0x42])
        XCTAssertEqual(result, [0x02, 0x01, 0x42])
    }

    func testDERIntegerHighBit() {
        // High bit set — needs leading 0x00
        let result = DNSSECVerifier.derInteger([0x80])
        XCTAssertEqual(result, [0x02, 0x02, 0x00, 0x80])
    }

    func testDERIntegerStripLeadingZeros() {
        let result = DNSSECVerifier.derInteger([0x00, 0x00, 0x42])
        XCTAssertEqual(result, [0x02, 0x01, 0x42])
    }

    // MARK: - RSA Key Conversion

    func testRSAPublicKeyToDER() throws {
        // Simple RSA key: exp_len=3, exponent=0x010001, modulus=128 bytes
        var keyBytes: [UInt8] = [3, 0x01, 0x00, 0x01] // exp_len=3, e=65537
        keyBytes.append(contentsOf: [UInt8](repeating: 0xBB, count: 128)) // modulus

        let der = try DNSSECVerifier.rsaPublicKeyToDER(keyBytes: keyBytes)
        // Should be a valid DER SEQUENCE
        XCTAssertEqual(der[0], 0x30) // SEQUENCE tag
        XCTAssertTrue(der.count > 140) // Should be larger than input due to DER overhead
    }

    func testRSAPublicKeyLongExponent() throws {
        // Long exponent format: first byte = 0, then 2-byte length
        var keyBytes: [UInt8] = [0, 0x01, 0x00] // exp_len=256 (big-endian 0x0100)
        keyBytes.append(contentsOf: [UInt8](repeating: 0x42, count: 256)) // exponent
        keyBytes.append(contentsOf: [UInt8](repeating: 0xBB, count: 128)) // modulus

        let der = try DNSSECVerifier.rsaPublicKeyToDER(keyBytes: keyBytes)
        XCTAssertEqual(der[0], 0x30)
    }

    // MARK: - ECDSA DER Conversion

    func testECDSAToDER() {
        let r = [UInt8](repeating: 0x42, count: 32)
        let s = [UInt8](repeating: 0x43, count: 32)
        let der = DNSSECVerifier.ecdsaToDER(r: r, s: s)
        // Should start with SEQUENCE tag
        XCTAssertEqual(der[0], 0x30)
        // Should contain two INTEGERs
        XCTAssertTrue(der.contains(0x02))
    }
}

import Crypto
