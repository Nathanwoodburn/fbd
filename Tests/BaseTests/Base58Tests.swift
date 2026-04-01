import XCTest
@testable import Base

final class Base58Tests: XCTestCase {

    func testEncodeEmpty() {
        XCTAssertEqual(base58Encode([]), "")
    }

    func testDecodeEmpty() {
        let result = base58Decode("")
        XCTAssertNotNil(result)
        XCTAssertEqual(result, [])
    }

    func testRoundTrip() {
        let data: [UInt8] = [0x00, 0x01, 0x02, 0xAB, 0xCD, 0xEF]
        let encoded = base58Encode(data)
        let decoded = base58Decode(encoded)
        XCTAssertEqual(decoded, data)
    }

    func testLeadingZeros() {
        // Leading zero bytes map to '1' characters
        let data: [UInt8] = [0x00, 0x00, 0x00, 0x01]
        let encoded = base58Encode(data)
        XCTAssertTrue(encoded.hasPrefix("111"))
        let decoded = base58Decode(encoded)
        XCTAssertEqual(decoded, data)
    }

    func testKnownVector() {
        // "Hello World" in Base58 (well-known test vector)
        let data = Array("Hello World".utf8)
        let encoded = base58Encode(data)
        XCTAssertEqual(encoded, "JxF12TrwUP45BMd")
        let decoded = base58Decode(encoded)
        XCTAssertEqual(decoded, data)
    }

    func testSingleByte() {
        // 0x00 → "1"
        XCTAssertEqual(base58Encode([0x00]), "1")
        XCTAssertEqual(base58Decode("1"), [0x00])

        // 0x01 → "2"
        XCTAssertEqual(base58Encode([0x01]), "2")
        XCTAssertEqual(base58Decode("2"), [0x01])
    }

    func testInvalidCharacter() {
        // '0' (zero), 'O', 'I', 'l' are not in Base58 alphabet
        XCTAssertNil(base58Decode("0"))
        XCTAssertNil(base58Decode("O"))
        XCTAssertNil(base58Decode("I"))
        XCTAssertNil(base58Decode("l"))
    }

    func testAllZeros() {
        let data = [UInt8](repeating: 0, count: 5)
        let encoded = base58Encode(data)
        XCTAssertEqual(encoded, "11111")
        let decoded = base58Decode(encoded)
        XCTAssertEqual(decoded, data)
    }

    func testLargeRoundTrip() {
        // 32-byte key-like data
        let data: [UInt8] = (0..<32).map { UInt8($0) }
        let encoded = base58Encode(data)
        let decoded = base58Decode(encoded)
        XCTAssertEqual(decoded, data)
    }

    func testNonASCIIFails() {
        // Non-ASCII character
        XCTAssertNil(base58Decode("é"))
    }
}
