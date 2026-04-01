import Base
import ExtCrypto

/// A Fistbump block (header + transactions + BalloonHash proof).
///
/// Wire format:
/// ```
/// [236 bytes]    header
/// [varint]       transaction count
/// [txs...]       each transaction (variable size)
/// ```
///
/// The `balloonProof` is transmitted separately in the headers packet,
/// not as part of the base block wire format.
public struct Block: Equatable, Sendable {
    /// The block header.
    public let header: BlockHeader

    /// The transactions in this block.
    public let transactions: [Transaction]

    /// BalloonHash proof for fast PoW verification.
    public let balloonProof: BalloonProof

    public init(header: BlockHeader, transactions: [Transaction], balloonProof: BalloonProof) {
        self.header = header
        self.transactions = transactions
        self.balloonProof = balloonProof
    }
}

extension Block: WireSerializable {
    public var serializedSize: Int {
        var size = header.serializedSize
        size += CompactSize.encodedSize(of: UInt64(transactions.count))
        for tx in transactions {
            size += tx.serializedSize
        }
        size += BalloonProof.serializedSize
        return size
    }

    public func write(to writer: inout BufferWriter) {
        header.write(to: &writer)
        writer.writeCompactSize(UInt64(transactions.count))
        for tx in transactions {
            tx.write(to: &writer)
        }
        writer.writeBytes(balloonProof.serialize())
    }

    public static func read(from reader: inout BufferReader) throws -> Block {
        let header = try BlockHeader.read(from: &reader)
        let txCount = try reader.readCompactSize()
        guard txCount <= 100_000 else {
            throw BaseError.bufferUnderflow
        }
        var transactions: [Transaction] = []
        transactions.reserveCapacity(Int(txCount))
        for _ in 0..<txCount {
            transactions.append(try Transaction.read(from: &reader))
        }
        let proofData = try reader.readBytes(BalloonProof.serializedSize)
        guard let proof = BalloonProof.deserialize(proofData) else {
            throw BaseError.bufferUnderflow
        }
        return Block(header: header, transactions: transactions, balloonProof: proof)
    }
}
