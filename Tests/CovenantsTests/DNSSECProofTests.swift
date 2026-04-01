import XCTest
@testable import Covenants
@testable import ExtCrypto
import Base

final class DNSSECProofTests: XCTestCase {

    // MARK: - Serialization Round-Trip

    func testSerializationRoundTrip() throws {
        let link1 = DNSSECProofLink(
            records: [
                DNSSECProofRecord(
                    ownerName: [0x00], // root
                    type: 48, // DNSKEY
                    rclass: 1,
                    rdata: [0x01, 0x01, 0x03, 0x08, 0xAA, 0xBB]
                ),
            ],
            rrsigRdata: [0xDE, 0xAD]
        )

        let link2 = DNSSECProofLink(
            records: [
                DNSSECProofRecord(
                    ownerName: [3, 0x63, 0x6F, 0x6D, 0x00], // com.
                    type: 43, // DS
                    rclass: 1,
                    rdata: [0x01, 0x02, 0x03, 0x04]
                ),
            ],
            rrsigRdata: [0xCA, 0xFE]
        )

        let proof = DNSSECProof(
            links: [link1, link2],
            claimedName: "eskimo",
            domain: "eskimo.software"
        )

        let serialized = proof.serialize()
        let deserialized = try DNSSECProof.deserialize(from: serialized)

        XCTAssertEqual(deserialized.links.count, 2)
        XCTAssertEqual(deserialized.claimedName, "eskimo")
        XCTAssertEqual(deserialized.domain, "eskimo.software")
        XCTAssertEqual(deserialized.links[0].records[0].type, 48)
        XCTAssertEqual(deserialized.links[0].records[0].rdata, [0x01, 0x01, 0x03, 0x08, 0xAA, 0xBB])
        XCTAssertEqual(deserialized.links[0].rrsigRdata, [0xDE, 0xAD])
        XCTAssertEqual(deserialized.links[1].records[0].ownerName, [3, 0x63, 0x6F, 0x6D, 0x00])
    }

    func testSerializationMultipleRecordsPerLink() throws {
        let link = DNSSECProofLink(
            records: [
                DNSSECProofRecord(ownerName: [0x00], type: 48, rclass: 1, rdata: [0x01]),
                DNSSECProofRecord(ownerName: [0x00], type: 48, rclass: 1, rdata: [0x02]),
                DNSSECProofRecord(ownerName: [0x00], type: 48, rclass: 1, rdata: [0x03]),
            ],
            rrsigRdata: [0xFF]
        )

        let proof = DNSSECProof(links: [link], claimedName: "test", domain: "test.com")
        let serialized = proof.serialize()
        let deserialized = try DNSSECProof.deserialize(from: serialized)

        XCTAssertEqual(deserialized.links[0].records.count, 3)
        XCTAssertEqual(deserialized.links[0].records[0].rdata, [0x01])
        XCTAssertEqual(deserialized.links[0].records[1].rdata, [0x02])
        XCTAssertEqual(deserialized.links[0].records[2].rdata, [0x03])
    }

    // MARK: - Invalid Proof Format

    func testDeserializeEmpty() {
        XCTAssertThrowsError(try DNSSECProof.deserialize(from: []))
    }

    func testDeserializeWrongVersion() {
        XCTAssertThrowsError(try DNSSECProof.deserialize(from: [0xFF, 0x00]))
    }

    func testDeserializeTruncated() {
        // Version + link count, but no actual data
        XCTAssertThrowsError(try DNSSECProof.deserialize(from: [0x01, 0x01]))
    }

    // MARK: - Proof Equality

    func testProofEquality() {
        let link = DNSSECProofLink(
            records: [DNSSECProofRecord(ownerName: [0x00], type: 48, rclass: 1, rdata: [0xAA])],
            rrsigRdata: [0xBB]
        )
        let proof1 = DNSSECProof(links: [link], claimedName: "test", domain: "test.com")
        let proof2 = DNSSECProof(links: [link], claimedName: "test", domain: "test.com")
        XCTAssertEqual(proof1, proof2)
    }

    // MARK: - Proof Size

    func testProofSizeReasonable() {
        // A real proof has ~6 links with multiple records each
        // Verify our serialization doesn't explode in size
        var links = [DNSSECProofLink]()
        for _ in 0..<6 {
            var records = [DNSSECProofRecord]()
            for _ in 0..<3 {
                records.append(DNSSECProofRecord(
                    ownerName: [7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x00],
                    type: 48, rclass: 1,
                    rdata: [UInt8](repeating: 0xAA, count: 100)
                ))
            }
            links.append(DNSSECProofLink(records: records, rrsigRdata: [UInt8](repeating: 0xBB, count: 200)))
        }
        let proof = DNSSECProof(links: links, claimedName: "example", domain: "example.com")
        let serialized = proof.serialize()

        // Typical proof should be ~2-4 KB; our mock is ~3.6 KB
        XCTAssertLessThan(serialized.count, 8192, "Proof should be under 8KB")
        XCTAssertGreaterThan(serialized.count, 100, "Proof should be non-trivial")
    }

    // MARK: - TXT Record Parsing (via validator internal)

    func testValidatorRejectsShortChain() {
        // A proof with only 2 links should fail (needs at least 6)
        let link = DNSSECProofLink(
            records: [DNSSECProofRecord(ownerName: [0x00], type: 48, rclass: 1, rdata: [0xAA])],
            rrsigRdata: [0xBB]
        )
        let proof = DNSSECProof(links: [link, link], claimedName: "test", domain: "test.com")
        let proofBytes = proof.serialize()

        XCTAssertThrowsError(try DNSSECProofValidator.validateProof(
            proofBytes, claimedName: "test", blockTime: 1_700_000_000
        )) { error in
            if case DNSSECError.proofChainBroken(let msg) = error {
                XCTAssertTrue(msg.contains("too short"))
            } else {
                XCTFail("Expected proofChainBroken, got \(error)")
            }
        }
    }

    func testValidatorRejectsNameMismatch() {
        // Build a minimal proof with wrong claimed name
        let links = (0..<6).map { _ in
            DNSSECProofLink(
                records: [DNSSECProofRecord(ownerName: [0x00], type: 48, rclass: 1, rdata: [0xAA])],
                rrsigRdata: [0xBB]
            )
        }
        let proof = DNSSECProof(links: links, claimedName: "wrong", domain: "wrong.com")
        let proofBytes = proof.serialize()

        XCTAssertThrowsError(try DNSSECProofValidator.validateProof(
            proofBytes, claimedName: "correct", blockTime: 1_700_000_000
        )) { error in
            if case DNSSECError.txtRecordMismatch = error {
                // Expected
            } else {
                XCTFail("Expected txtRecordMismatch, got \(error)")
            }
        }
    }
}
