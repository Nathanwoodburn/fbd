import Base

/// A Fistbump transaction input.
///
/// Unlike Bitcoin, Fistbump inputs contain no scriptSig — all spending
/// proofs are in the witness section. Each input is exactly 40 bytes.
///
/// Wire format (40 bytes):
/// ```
/// [32 bytes]  prevout hash
/// [4 bytes]   prevout index (uint32 LE)
/// [4 bytes]   sequence (uint32 LE)
/// ```
public struct Input: Equatable, Sendable {
    /// The outpoint being spent.
    public let prevout: Outpoint

    /// The sequence number (used for relative timelocks and RBF).
    public let sequence: UInt32

    public init(prevout: Outpoint, sequence: UInt32 = 0xFFFF_FFFF) {
        self.prevout = prevout
        self.sequence = sequence
    }

    /// Whether this input is a coinbase input (null prevout).
    public var isCoinbase: Bool {
        prevout.isNull
    }
}

extension Input: WireSerializable {
    public var serializedSize: Int { 40 }

    public func write(to writer: inout BufferWriter) {
        prevout.write(to: &writer)
        writer.writeUInt32LE(sequence)
    }

    public static func read(from reader: inout BufferReader) throws -> Input {
        let prevout = try Outpoint.read(from: &reader)
        let sequence = try reader.readUInt32LE()
        return Input(prevout: prevout, sequence: sequence)
    }
}
