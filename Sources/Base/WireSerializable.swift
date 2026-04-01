/// A type that can be serialized to and deserialized from the Fistbump wire format.
///
/// All protocol-level data structures (transactions, blocks, headers, etc.)
/// conform to this protocol to enable network serialization.
public protocol WireSerializable: Sendable {
    /// The serialized size in bytes.
    var serializedSize: Int { get }

    /// Write this value's binary representation into the given writer.
    func write(to writer: inout BufferWriter)

    /// Read a value from the given reader.
    static func read(from reader: inout BufferReader) throws -> Self
}

extension WireSerializable {
    /// Serialize this value to a byte array.
    public func serializedData() -> [UInt8] {
        var writer = BufferWriter(capacity: serializedSize)
        write(to: &writer)
        return writer.data
    }
}
