import Base

/// A Fistbump covenant — the name operation attached to a transaction output.
///
/// Wire format:
/// ```
/// [1 byte]    type (CovenantType raw value)
/// [varint]    item count
/// [items...]  each item is varint-length-prefixed bytes
/// ```
public struct Covenant: Equatable, Sendable {
    /// The covenant operation type.
    public let type: CovenantType

    /// The data items (e.g., name hash, height, resource data).
    public let items: [[UInt8]]

    /// Create a covenant with the given type and items.
    public init(type: CovenantType, items: [[UInt8]] = []) {
        self.type = type
        self.items = items
    }

    /// A NONE covenant (no name operation).
    public static let none = Covenant(type: .none)
}

extension Covenant: WireSerializable {
    public var serializedSize: Int {
        var size = 1 // type byte
        size += CompactSize.encodedSize(of: UInt64(items.count))
        for item in items {
            size += CompactSize.encodedSize(of: UInt64(item.count))
            size += item.count
        }
        return size
    }

    public func write(to writer: inout BufferWriter) {
        writer.writeUInt8(type.rawValue)
        writer.writeCompactSize(UInt64(items.count))
        for item in items {
            writer.writeVarBytes(item)
        }
    }

    public static func read(from reader: inout BufferReader) throws -> Covenant {
        let typeByte = try reader.readUInt8()
        guard let type = CovenantType(rawValue: typeByte) else {
            throw ProtocolError.unknownCovenantType(typeByte)
        }
        let count = try reader.readCompactSize()
        guard count <= 1000 else {
            throw ProtocolError.tooManyItems(Int(count))
        }
        var items: [[UInt8]] = []
        items.reserveCapacity(Int(count))
        for _ in 0..<count {
            items.append(try reader.readVarBytes())
        }
        return Covenant(type: type, items: items)
    }
}
