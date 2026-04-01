import Base

/// The type of an inventory item in P2P messages.
public enum InvType: UInt32, Sendable {
    /// A transaction.
    case tx = 1
    /// A block.
    case block = 2
    /// A filtered block (compact).
    case filteredBlock = 3
    /// A compact block.
    case compactBlock = 4
}

/// An inventory item — references a transaction or block by hash.
///
/// Wire format (36 bytes):
/// ```
/// [4 bytes]   type (uint32 LE)
/// [32 bytes]  hash
/// ```
public struct InvItem: Equatable, Sendable {
    /// The item type.
    public let type: InvType

    /// The item hash.
    public let hash: Hash256

    public init(type: InvType, hash: Hash256) {
        self.type = type
        self.hash = hash
    }
}

extension InvItem: WireSerializable {
    public var serializedSize: Int { 36 }

    public func write(to writer: inout BufferWriter) {
        writer.writeUInt32LE(type.rawValue)
        hash.write(to: &writer)
    }

    public static func read(from reader: inout BufferReader) throws -> InvItem {
        let rawType = try reader.readUInt32LE()
        guard let type = InvType(rawValue: rawType) else {
            throw ProtocolError.unknownInvType(rawType)
        }
        let hash = try Hash256.read(from: &reader)
        return InvItem(type: type, hash: hash)
    }
}
