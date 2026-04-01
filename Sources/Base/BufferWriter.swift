/// Binary serialization into a growable byte buffer.
///
/// `BufferWriter` provides sequential write access for little-endian integers,
/// raw byte spans, and compact-size values. Matches `BufferReader` symmetrically.
public struct BufferWriter: Sendable {
    /// The accumulated bytes.
    @usableFromInline
    var bytes: [UInt8]

    /// Create a writer with an optional initial capacity hint.
    @inlinable
    public init(capacity: Int = 64) {
        bytes = []
        bytes.reserveCapacity(capacity)
    }

    /// Get the accumulated bytes.
    @inlinable
    public var data: [UInt8] { bytes }

    /// The current number of bytes written.
    @inlinable
    public var count: Int { bytes.count }

    // MARK: - Integer writes (little-endian)

    /// Write a single byte.
    @inlinable
    public mutating func writeUInt8(_ value: UInt8) {
        bytes.append(value)
    }

    /// Write a little-endian UInt16.
    @inlinable
    public mutating func writeUInt16LE(_ value: UInt16) {
        bytes.append(UInt8(value & 0xFF))
        bytes.append(UInt8(value >> 8))
    }

    /// Write a little-endian UInt32.
    @inlinable
    public mutating func writeUInt32LE(_ value: UInt32) {
        bytes.append(UInt8(value & 0xFF))
        bytes.append(UInt8((value >> 8) & 0xFF))
        bytes.append(UInt8((value >> 16) & 0xFF))
        bytes.append(UInt8(value >> 24))
    }

    /// Write a little-endian UInt64.
    @inlinable
    public mutating func writeUInt64LE(_ value: UInt64) {
        bytes.append(UInt8(value & 0xFF))
        bytes.append(UInt8((value >> 8) & 0xFF))
        bytes.append(UInt8((value >> 16) & 0xFF))
        bytes.append(UInt8((value >> 24) & 0xFF))
        bytes.append(UInt8((value >> 32) & 0xFF))
        bytes.append(UInt8((value >> 40) & 0xFF))
        bytes.append(UInt8((value >> 48) & 0xFF))
        bytes.append(UInt8(value >> 56))
    }

    /// Write a little-endian Int32.
    @inlinable
    public mutating func writeInt32LE(_ value: Int32) {
        writeUInt32LE(UInt32(bitPattern: value))
    }

    /// Write a little-endian Int64.
    @inlinable
    public mutating func writeInt64LE(_ value: Int64) {
        writeUInt64LE(UInt64(bitPattern: value))
    }

    // MARK: - Integer writes (big-endian, for DNS wire format)

    /// Write a big-endian UInt16.
    @inlinable
    public mutating func writeUInt16BE(_ value: UInt16) {
        bytes.append(UInt8(value >> 8))
        bytes.append(UInt8(value & 0xFF))
    }

    /// Write a big-endian UInt32.
    @inlinable
    public mutating func writeUInt32BE(_ value: UInt32) {
        bytes.append(UInt8(value >> 24))
        bytes.append(UInt8((value >> 16) & 0xFF))
        bytes.append(UInt8((value >> 8) & 0xFF))
        bytes.append(UInt8(value & 0xFF))
    }

    // MARK: - Raw bytes

    /// Write raw bytes.
    @inlinable
    public mutating func writeBytes(_ data: some Sequence<UInt8>) {
        bytes.append(contentsOf: data)
    }

    // MARK: - Compact size

    /// Write a compact-size encoded value.
    @inlinable
    public mutating func writeCompactSize(_ value: UInt64) {
        bytes.append(contentsOf: CompactSize.encode(value))
    }

    /// Write a compact-size-prefixed byte array.
    @inlinable
    public mutating func writeVarBytes(_ data: [UInt8]) {
        writeCompactSize(UInt64(data.count))
        writeBytes(data)
    }
}
