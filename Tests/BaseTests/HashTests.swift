import XCTest
@testable import Base

final class HashTests: XCTestCase {

    // MARK: - Hash256

    func testHash256Zero() {
        let zero = Hash256.zero
        XCTAssertEqual(zero.bytes.count, 32)
        XCTAssertTrue(zero.bytes.allSatisfy { $0 == 0 })
        XCTAssertEqual(zero.hex, String(repeating: "0", count: 64))
    }

    func testHash256FromBytes() throws {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[0] = 0xAB
        bytes[31] = 0xCD
        let hash = try Hash256(bytes)
        XCTAssertEqual(hash.bytes[0], 0xAB)
        XCTAssertEqual(hash.bytes[31], 0xCD)
    }

    func testHash256InvalidLength() {
        XCTAssertThrowsError(try Hash256([UInt8](repeating: 0, count: 31)))
        XCTAssertThrowsError(try Hash256([UInt8](repeating: 0, count: 33)))
        XCTAssertThrowsError(try Hash256([]))
    }

    func testHash256Hex() throws {
        let bytes: [UInt8] = (0..<32).map { UInt8($0) }
        let hash = try Hash256(bytes)
        XCTAssertEqual(hash.hex, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    }

    func testHash256ReversedHex() throws {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[0] = 0x01
        bytes[31] = 0xFF
        let hash = try Hash256(bytes)
        // reversed: last byte first
        XCTAssertTrue(hash.reversedHex.hasPrefix("ff"))
        XCTAssertTrue(hash.reversedHex.hasSuffix("01"))
    }

    func testHash256FromHexRoundTrip() throws {
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        let hash = try Hash256.fromHex(hex)
        XCTAssertEqual(hash.hex, hex)
    }

    func testHash256Equatable() throws {
        let a = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let b = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let c = try Hash256([UInt8](repeating: 0xBB, count: 32))
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    // MARK: - Hash256 WireSerializable

    func testHash256WireRoundTrip() throws {
        let bytes: [UInt8] = (0..<32).map { UInt8($0) }
        let hash = try Hash256(bytes)

        var writer = BufferWriter()
        hash.write(to: &writer)
        XCTAssertEqual(writer.count, 32)

        var reader = BufferReader(writer.data)
        let decoded = try Hash256.read(from: &reader)
        XCTAssertEqual(decoded, hash)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - Hash160

    func testHash160Zero() {
        let zero = Hash160.zero
        XCTAssertEqual(zero.bytes.count, 20)
        XCTAssertTrue(zero.bytes.allSatisfy { $0 == 0 })
    }

    func testHash160FromBytes() throws {
        let bytes = [UInt8](repeating: 0xDE, count: 20)
        let hash = try Hash160(bytes)
        XCTAssertEqual(hash.bytes, bytes)
    }

    func testHash160InvalidLength() {
        XCTAssertThrowsError(try Hash160([UInt8](repeating: 0, count: 19)))
        XCTAssertThrowsError(try Hash160([UInt8](repeating: 0, count: 21)))
    }

    func testHash160WireRoundTrip() throws {
        let bytes: [UInt8] = (0..<20).map { UInt8($0) }
        let hash = try Hash160(bytes)

        var writer = BufferWriter()
        hash.write(to: &writer)
        XCTAssertEqual(writer.count, 20)

        var reader = BufferReader(writer.data)
        let decoded = try Hash160.read(from: &reader)
        XCTAssertEqual(decoded, hash)
    }
}
