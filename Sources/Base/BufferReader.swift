/// Zero-copy binary deserialization from a byte buffer.
///
/// `BufferReader` wraps a contiguous byte slice and provides sequential read
/// access for little-endian integers, raw byte spans, and compact-size values.
public struct BufferReader: Sendable {
    @usableFromInline
    let data: [UInt8]

    public var offset: Int

    /// Create a reader over the given bytes.
    @inlinable
    public init(_ data: [UInt8]) {
        self.data = data
        self.offset = 0
    }

    /// The number of bytes remaining to be read.
    @inlinable
    public var remaining: Int {
        data.count - offset
    }

    /// Whether all bytes have been consumed.
    @inlinable
    public var isAtEnd: Bool {
        offset >= data.count
    }

    // MARK: - Integer reads (little-endian)

    /// Read a single byte.
    @inlinable
    public mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else { throw BaseError.bufferUnderflow }
        let value = data[offset]
        offset += 1
        return value
    }

    /// Read a little-endian UInt16.
    @inlinable
    public mutating func readUInt16LE() throws -> UInt16 {
        guard remaining >= 2 else { throw BaseError.bufferUnderflow }
        let value = UInt16(data[offset]) |
                    (UInt16(data[offset + 1]) << 8)
        offset += 2
        return value
    }

    /// Read a little-endian UInt32.
    @inlinable
    public mutating func readUInt32LE() throws -> UInt32 {
        guard remaining >= 4 else { throw BaseError.bufferUnderflow }
        let value = UInt32(data[offset]) |
                    (UInt32(data[offset + 1]) << 8) |
                    (UInt32(data[offset + 2]) << 16) |
                    (UInt32(data[offset + 3]) << 24)
        offset += 4
        return value
    }

    /// Read a little-endian UInt64.
    @inlinable
    public mutating func readUInt64LE() throws -> UInt64 {
        guard remaining >= 8 else { throw BaseError.bufferUnderflow }
        let value = UInt64(data[offset]) |
                    (UInt64(data[offset + 1]) << 8) |
                    (UInt64(data[offset + 2]) << 16) |
                    (UInt64(data[offset + 3]) << 24) |
                    (UInt64(data[offset + 4]) << 32) |
                    (UInt64(data[offset + 5]) << 40) |
                    (UInt64(data[offset + 6]) << 48) |
                    (UInt64(data[offset + 7]) << 56)
        offset += 8
        return value
    }

    /// Read a little-endian Int32.
    @inlinable
    public mutating func readInt32LE() throws -> Int32 {
        Int32(bitPattern: try readUInt32LE())
    }

    /// Read a little-endian Int64.
    @inlinable
    public mutating func readInt64LE() throws -> Int64 {
        Int64(bitPattern: try readUInt64LE())
    }

    // MARK: - Integer reads (big-endian, for DNS wire format)

    /// Read a big-endian UInt16.
    @inlinable
    public mutating func readUInt16BE() throws -> UInt16 {
        guard remaining >= 2 else { throw BaseError.bufferUnderflow }
        let value = (UInt16(data[offset]) << 8) |
                    UInt16(data[offset + 1])
        offset += 2
        return value
    }

    /// Read a big-endian UInt32.
    @inlinable
    public mutating func readUInt32BE() throws -> UInt32 {
        guard remaining >= 4 else { throw BaseError.bufferUnderflow }
        let value = (UInt32(data[offset]) << 24) |
                    (UInt32(data[offset + 1]) << 16) |
                    (UInt32(data[offset + 2]) << 8) |
                    UInt32(data[offset + 3])
        offset += 4
        return value
    }

    // MARK: - Raw bytes

    /// Read exactly `count` bytes.
    @inlinable
    public mutating func readBytes(_ count: Int) throws -> [UInt8] {
        guard remaining >= count else { throw BaseError.bufferUnderflow }
        let slice = Array(data[offset..<(offset + count)])
        offset += count
        return slice
    }

    /// Read all remaining bytes.
    @inlinable
    public mutating func readRemainingBytes() -> [UInt8] {
        let slice = Array(data[offset...])
        offset = data.count
        return slice
    }

    // MARK: - Compact size

    /// Read a compact-size encoded value.
    @inlinable
    public mutating func readCompactSize() throws -> UInt64 {
        let slice = data[offset...]
        let (value, bytesRead) = try CompactSize.decode(from: slice)
        offset += bytesRead
        return value
    }

    /// Read a compact-size-prefixed byte array.
    @inlinable
    public mutating func readVarBytes() throws -> [UInt8] {
        let length = try readCompactSize()
        guard length <= UInt64(remaining) else { throw BaseError.bufferUnderflow }
        return try readBytes(Int(length))
    }
}
