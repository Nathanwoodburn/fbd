import XCTest
@testable import RPC

final class Base64Tests: XCTestCase {

    // MARK: - Encode

    func testEncodeEmpty() {
        XCTAssertEqual(Base64.encode([]), "")
    }

    func testEncodeOneByte() {
        // 'A' = 0x41 → "QQ=="
        XCTAssertEqual(Base64.encode([0x41]), "QQ==")
    }

    func testEncodeTwoBytes() {
        // "AB" = [0x41, 0x42] → "QUI="
        XCTAssertEqual(Base64.encode([0x41, 0x42]), "QUI=")
    }

    func testEncodeThreeBytes() {
        // "ABC" = [0x41, 0x42, 0x43] → "QUJD"
        XCTAssertEqual(Base64.encode([0x41, 0x42, 0x43]), "QUJD")
    }

    func testEncodeFourBytes() {
        // "ABCD" → "QUJDRA=="
        XCTAssertEqual(Base64.encode([0x41, 0x42, 0x43, 0x44]), "QUJDRA==")
    }

    func testEncodeHelloWorld() {
        let input = Array("Hello, World!".utf8)
        XCTAssertEqual(Base64.encode(input), "SGVsbG8sIFdvcmxkIQ==")
    }

    func testEncodeAllZeros() {
        XCTAssertEqual(Base64.encode([0, 0, 0]), "AAAA")
    }

    func testEncodeAllOnes() {
        XCTAssertEqual(Base64.encode([0xFF, 0xFF, 0xFF]), "////")
    }

    // MARK: - Decode

    func testDecodeEmpty() {
        XCTAssertEqual(Base64.decode(""), [])
    }

    func testDecodeOneByte() {
        XCTAssertEqual(Base64.decode("QQ=="), [0x41])
    }

    func testDecodeTwoBytes() {
        XCTAssertEqual(Base64.decode("QUI="), [0x41, 0x42])
    }

    func testDecodeThreeBytes() {
        XCTAssertEqual(Base64.decode("QUJD"), [0x41, 0x42, 0x43])
    }

    func testDecodeHelloWorld() {
        let bytes = Base64.decode("SGVsbG8sIFdvcmxkIQ==")
        XCTAssertEqual(bytes.flatMap { String(bytes: $0, encoding: .utf8) }, "Hello, World!")
    }

    func testDecodeInvalidCharacter() {
        XCTAssertNil(Base64.decode("!!!"))
    }

    func testDecodeString() {
        XCTAssertEqual(Base64.decodeString("QUJD"), "ABC")
    }

    // MARK: - Round-trip

    func testRoundTripEmpty() {
        let input: [UInt8] = []
        XCTAssertEqual(Base64.decode(Base64.encode(input)), input)
    }

    func testRoundTripSingleByte() {
        for b: UInt8 in [0, 1, 127, 128, 255] {
            let encoded = Base64.encode([b])
            let decoded = Base64.decode(encoded)
            XCTAssertEqual(decoded, [b], "Round-trip failed for byte \(b)")
        }
    }

    func testRoundTripVariousLengths() {
        for len in 1...32 {
            var input = [UInt8](repeating: 0, count: len)
            for i in 0..<len { input[i] = UInt8(i & 0xFF) }
            let encoded = Base64.encode(input)
            let decoded = Base64.decode(encoded)
            XCTAssertEqual(decoded, input, "Round-trip failed for length \(len)")
        }
    }

    func testRoundTrip65ByteSignature() {
        // Simulate a recoverable signature (65 bytes)
        var sig = [UInt8](repeating: 0, count: 65)
        for i in 0..<65 { sig[i] = UInt8(i & 0xFF) }
        let encoded = Base64.encode(sig)
        let decoded = Base64.decode(encoded)
        XCTAssertEqual(decoded, sig)
    }

    func testPaddingAlignment() {
        // length % 3 == 0: no padding
        XCTAssertFalse(Base64.encode([1, 2, 3]).contains("="))
        // length % 3 == 1: two padding chars
        XCTAssertTrue(Base64.encode([1]).hasSuffix("=="))
        // length % 3 == 2: one padding char
        let enc = Base64.encode([1, 2])
        XCTAssertTrue(enc.hasSuffix("=") && !enc.hasSuffix("=="))
    }
}
