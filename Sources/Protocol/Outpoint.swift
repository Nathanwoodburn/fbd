import Base

/// A reference to a specific output of a previous transaction.
///
/// Wire format (36 bytes):
/// ```
/// [32 bytes]  hash (transaction ID)
/// [4 bytes]   index (uint32 LE)
/// ```
public struct Outpoint: Equatable, Hashable, Sendable {
    /// The transaction ID containing the referenced output.
    public let hash: Hash256

    /// The zero-based index of the output within that transaction.
    public let index: UInt32

    public init(hash: Hash256, index: UInt32) {
        self.hash = hash
        self.index = index
    }

    /// A null outpoint (zero hash, index 0xFFFFFFFF).
    public static let null = Outpoint(hash: .zero, index: 0xFFFF_FFFF)

    /// Whether this is a null/coinbase outpoint.
    public var isNull: Bool {
        hash == .zero && index == 0xFFFF_FFFF
    }
}

extension Outpoint: WireSerializable {
    public var serializedSize: Int { 36 }

    public func write(to writer: inout BufferWriter) {
        hash.write(to: &writer)
        writer.writeUInt32LE(index)
    }

    public static func read(from reader: inout BufferReader) throws -> Outpoint {
        let hash = try Hash256.read(from: &reader)
        let index = try reader.readUInt32LE()
        return Outpoint(hash: hash, index: index)
    }
}
