import Base

/// Witness data for a transaction input (spending proof).
///
/// Wire format:
/// ```
/// [varint]     item count
/// [items...]   each item is varint-length-prefixed bytes
/// ```
public struct Witness: Equatable, Sendable {
    /// The witness stack items (signatures, public keys, scripts, etc.).
    public let items: [[UInt8]]

    public init(items: [[UInt8]] = []) {
        self.items = items
    }

    /// An empty witness (no items).
    public static let empty = Witness()
}

extension Witness: WireSerializable {
    public var serializedSize: Int {
        var size = CompactSize.encodedSize(of: UInt64(items.count))
        for item in items {
            size += CompactSize.encodedSize(of: UInt64(item.count))
            size += item.count
        }
        return size
    }

    public func write(to writer: inout BufferWriter) {
        writer.writeCompactSize(UInt64(items.count))
        for item in items {
            writer.writeVarBytes(item)
        }
    }

    public static func read(from reader: inout BufferReader) throws -> Witness {
        let count = try reader.readCompactSize()
        guard count <= 1000 else {
            throw ProtocolError.tooManyItems(Int(count))
        }
        var items: [[UInt8]] = []
        items.reserveCapacity(Int(count))
        for _ in 0..<count {
            items.append(try reader.readVarBytes())
        }
        return Witness(items: items)
    }
}
