import XCTest
@testable import Base

final class CompactSizeTests: XCTestCase {

    // MARK: - Encoding size

    func testEncodedSize() {
        XCTAssertEqual(CompactSize.encodedSize(of: 0), 1)
        XCTAssertEqual(CompactSize.encodedSize(of: 0xFC), 1)
        XCTAssertEqual(CompactSize.encodedSize(of: 0xFD), 3)
        XCTAssertEqual(CompactSize.encodedSize(of: 0xFFFF), 3)
        XCTAssertEqual(CompactSize.encodedSize(of: 0x10000), 5)
        XCTAssertEqual(CompactSize.encodedSize(of: 0xFFFF_FFFF), 5)
        XCTAssertEqual(CompactSize.encodedSize(of: 0x1_0000_0000), 9)
        XCTAssertEqual(CompactSize.encodedSize(of: UInt64.max), 9)
    }

    // MARK: - Known value encoding

    func testEncodeZero() {
        XCTAssertEqual(CompactSize.encode(0), [0x00])
    }

    func testEncodeSingleByte() {
        XCTAssertEqual(CompactSize.encode(100), [100])
        XCTAssertEqual(CompactSize.encode(0xFC), [0xFC])
    }

    func testEncodeTwoBytes() {
        // 0xFD → [0xFD, 0xFD, 0x00]
        XCTAssertEqual(CompactSize.encode(0xFD), [0xFD, 0xFD, 0x00])
        // 0x0104 (260) → [0xFD, 0x04, 0x01]
        XCTAssertEqual(CompactSize.encode(260), [0xFD, 0x04, 0x01])
    }

    func testEncodeFourBytes() {
        // 0x10000 → [0xFE, 0x00, 0x00, 0x01, 0x00]
        XCTAssertEqual(CompactSize.encode(0x10000), [0xFE, 0x00, 0x00, 0x01, 0x00])
    }

    func testEncodeEightBytes() {
        // 0x1_0000_0000 → [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        XCTAssertEqual(CompactSize.encode(0x1_0000_0000),
                       [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
    }

    // MARK: - Round-trip

    func testRoundTrip() throws {
        let testValues: [UInt64] = [
            0, 1, 0xFC, 0xFD, 0xFE, 0xFF, 0x100, 0xFFFF,
            0x10000, 0xFFFF_FFFF, 0x1_0000_0000, UInt64.max,
        ]

        for value in testValues {
            let encoded = CompactSize.encode(value)
            let (decoded, bytesRead) = try CompactSize.decode(from: encoded)
            XCTAssertEqual(decoded, value, "Round-trip failed for \(value)")
            XCTAssertEqual(bytesRead, encoded.count, "Wrong bytesRead for \(value)")
        }
    }

    // MARK: - Decode errors

    func testDecodeEmptyThrows() {
        XCTAssertThrowsError(try CompactSize.decode(from: [] as [UInt8]))
    }

    func testDecodeNonCanonicalThrows() {
        // 0xFD prefix but value < 0xFD (should have used 1-byte encoding)
        let nonCanonical: [UInt8] = [0xFD, 0x01, 0x00]
        XCTAssertThrowsError(try CompactSize.decode(from: nonCanonical))
    }

    func testDecodeTruncatedThrows() {
        // 0xFD prefix but only 2 bytes total (needs 3)
        let truncated: [UInt8] = [0xFD, 0x01]
        XCTAssertThrowsError(try CompactSize.decode(from: truncated))
    }
}
