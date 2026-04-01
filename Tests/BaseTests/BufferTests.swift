import XCTest
@testable import Base

final class BufferTests: XCTestCase {

    // MARK: - UInt8 round-trip

    func testUInt8RoundTrip() throws {
        var writer = BufferWriter()
        writer.writeUInt8(0)
        writer.writeUInt8(42)
        writer.writeUInt8(255)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readUInt8(), 0)
        XCTAssertEqual(try reader.readUInt8(), 42)
        XCTAssertEqual(try reader.readUInt8(), 255)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - UInt16LE round-trip

    func testUInt16LERoundTrip() throws {
        var writer = BufferWriter()
        writer.writeUInt16LE(0)
        writer.writeUInt16LE(0x0102)
        writer.writeUInt16LE(0xFFFF)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readUInt16LE(), 0)
        XCTAssertEqual(try reader.readUInt16LE(), 0x0102)
        XCTAssertEqual(try reader.readUInt16LE(), 0xFFFF)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - UInt32LE round-trip

    func testUInt32LERoundTrip() throws {
        var writer = BufferWriter()
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0xDEAD_BEEF)
        writer.writeUInt32LE(0xFFFF_FFFF)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readUInt32LE(), 0)
        XCTAssertEqual(try reader.readUInt32LE(), 0xDEAD_BEEF)
        XCTAssertEqual(try reader.readUInt32LE(), 0xFFFF_FFFF)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - UInt64LE round-trip

    func testUInt64LERoundTrip() throws {
        var writer = BufferWriter()
        writer.writeUInt64LE(0)
        writer.writeUInt64LE(0xDEAD_BEEF_CAFE_BABE)
        writer.writeUInt64LE(UInt64.max)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readUInt64LE(), 0)
        XCTAssertEqual(try reader.readUInt64LE(), 0xDEAD_BEEF_CAFE_BABE)
        XCTAssertEqual(try reader.readUInt64LE(), UInt64.max)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - Int32LE round-trip

    func testInt32LERoundTrip() throws {
        var writer = BufferWriter()
        writer.writeInt32LE(0)
        writer.writeInt32LE(-1)
        writer.writeInt32LE(Int32.min)
        writer.writeInt32LE(Int32.max)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readInt32LE(), 0)
        XCTAssertEqual(try reader.readInt32LE(), -1)
        XCTAssertEqual(try reader.readInt32LE(), Int32.min)
        XCTAssertEqual(try reader.readInt32LE(), Int32.max)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - Bytes

    func testReadWriteBytes() throws {
        let data: [UInt8] = [1, 2, 3, 4, 5]
        var writer = BufferWriter()
        writer.writeBytes(data)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readBytes(5), data)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testReadRemainingBytes() throws {
        let data: [UInt8] = [10, 20, 30]
        var reader = BufferReader(data)
        _ = try reader.readUInt8()
        let rest = reader.readRemainingBytes()
        XCTAssertEqual(rest, [20, 30])
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - CompactSize via buffer

    func testCompactSizeViaBuffer() throws {
        var writer = BufferWriter()
        writer.writeCompactSize(0)
        writer.writeCompactSize(0xFC)
        writer.writeCompactSize(0xFD)
        writer.writeCompactSize(0x10000)
        writer.writeCompactSize(0x1_0000_0000)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readCompactSize(), 0)
        XCTAssertEqual(try reader.readCompactSize(), 0xFC)
        XCTAssertEqual(try reader.readCompactSize(), 0xFD)
        XCTAssertEqual(try reader.readCompactSize(), 0x10000)
        XCTAssertEqual(try reader.readCompactSize(), 0x1_0000_0000)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - VarBytes

    func testVarBytesRoundTrip() throws {
        let data: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE]
        var writer = BufferWriter()
        writer.writeVarBytes(data)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readVarBytes(), data)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - Underflow errors

    func testReadUInt8Underflow() {
        var reader = BufferReader([])
        XCTAssertThrowsError(try reader.readUInt8())
    }

    func testReadUInt16Underflow() {
        var reader = BufferReader([0x01])
        XCTAssertThrowsError(try reader.readUInt16LE())
    }

    func testReadUInt32Underflow() {
        var reader = BufferReader([0x01, 0x02, 0x03])
        XCTAssertThrowsError(try reader.readUInt32LE())
    }

    func testReadBytesUnderflow() {
        var reader = BufferReader([0x01, 0x02])
        XCTAssertThrowsError(try reader.readBytes(5))
    }

    // MARK: - Little-endian byte order

    func testLittleEndianByteOrder() throws {
        // UInt32 0x04030201 should serialize as [01, 02, 03, 04]
        var writer = BufferWriter()
        writer.writeUInt32LE(0x0403_0201)
        XCTAssertEqual(writer.data, [0x01, 0x02, 0x03, 0x04])
    }
}
