import Base
import ExtCrypto
import Protocol
import Consensus

/// Metadata for a block stored in the chain index.
///
/// Each entry contains the block header fields plus computed data
/// like height and cumulative chainwork. Entries form a tree structure
/// via `prevBlock` pointers, with the "best chain" being the path
/// with the most cumulative proof-of-work.
public struct ChainEntry: Equatable, Sendable {
    /// The block header hash (BLAKE2b+SHA3 PoW hash).
    public let hash: Hash256

    /// The block version (also carries version bits for soft forks).
    public let version: UInt32

    /// The hash of the previous block.
    public let prevBlock: Hash256

    /// The transaction merkle root.
    public let merkleRoot: Hash256

    /// The witness commitment merkle root.
    public let witnessRoot: Hash256

    /// The Urkel tree root (name state).
    public let treeRoot: Hash256

    /// Reserved root (for future use).
    public let reservedRoot: Hash256

    /// The block timestamp (seconds since epoch).
    public let time: UInt64

    /// The compact difficulty target.
    public let bits: UInt32

    /// The miner-iterated nonce.
    public let nonce: UInt32

    /// The extra nonce (24 bytes).
    public let extraNonce: [UInt8]

    /// The PoW mask (32 bytes).
    public let mask: [UInt8]

    /// The block height.
    public let height: Int

    /// The cumulative proof-of-work up to and including this block.
    public let chainwork: Target256

    /// Whether this is the genesis block.
    public var isGenesis: Bool { height == 0 }

    /// Create a chain entry from a block header and previous entry.
    ///
    /// Computes the block hash and cumulative chainwork.
    public static func fromBlock(_ header: BlockHeader, prev: ChainEntry?, slots: Int = BalloonHash.defaultSlots, rounds: Int = BalloonHash.defaultRounds, delta: Int = BalloonHash.defaultDelta) throws -> ChainEntry {
        let hash = try ProofOfWork.powHash(for: header, slots: slots, rounds: rounds, delta: delta)
        return fromBlock(header, hash: hash, prev: prev)
    }

    /// Create a chain entry from a block header with a precomputed PoW hash.
    public static func fromBlock(_ header: BlockHeader, hash: Hash256, prev: ChainEntry?) -> ChainEntry {
        let height: Int
        let chainwork: Target256

        if let prev = prev {
            height = prev.height + 1
            let proof = DifficultyRetarget.targetToWork(header.bits)
            chainwork = prev.chainwork + proof
        } else {
            height = 0
            chainwork = DifficultyRetarget.targetToWork(header.bits)
        }

        return ChainEntry(
            hash: hash,
            version: header.version,
            prevBlock: header.prevBlock,
            merkleRoot: header.merkleRoot,
            witnessRoot: header.witnessRoot,
            treeRoot: header.treeRoot,
            reservedRoot: header.reservedRoot,
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
            extraNonce: header.extraNonce,
            mask: header.mask,
            height: height,
            chainwork: chainwork
        )
    }

    /// Get the proof-of-work (number of hashes) for this block's target.
    public var proof: Target256 {
        DifficultyRetarget.targetToWork(bits)
    }

    /// Check if a version bit is set.
    ///
    /// Fistbump does NOT use the BIP9 0x20000000 version prefix —
    /// simply checks whether the specified bit is set. Matches hsd's `hasBit()`.
    public func hasBit(_ bit: Int) -> Bool {
        (version & (1 << bit)) != 0
    }

    /// Reconstruct a BlockHeader from this entry.
    public func toHeader() -> BlockHeader {
        BlockHeader(
            nonce: nonce,
            time: time,
            prevBlock: prevBlock,
            treeRoot: treeRoot,
            extraNonce: extraNonce,
            reservedRoot: reservedRoot,
            witnessRoot: witnessRoot,
            merkleRoot: merkleRoot,
            version: version,
            bits: bits,
            mask: mask
        )
    }
}

// MARK: - WireSerializable (308-byte fixed record)

extension ChainEntry: WireSerializable {
    /// Fixed serialized size: 32 + 4 + 32*5 + 8 + 4 + 4 + 24 + 32 + 8 + 32 = 308 bytes.
    public static let recordSize = 308

    public var serializedSize: Int { Self.recordSize }

    public func write(to writer: inout BufferWriter) {
        hash.write(to: &writer)            // 32
        writer.writeUInt32LE(version)       // 4
        prevBlock.write(to: &writer)        // 32
        merkleRoot.write(to: &writer)       // 32
        witnessRoot.write(to: &writer)      // 32
        treeRoot.write(to: &writer)         // 32
        reservedRoot.write(to: &writer)     // 32
        writer.writeUInt64LE(time)          // 8
        writer.writeUInt32LE(bits)          // 4
        writer.writeUInt32LE(nonce)         // 4
        writer.writeBytes(extraNonce)       // 24
        writer.writeBytes(mask)             // 32
        writer.writeInt64LE(Int64(height))  // 8
        writer.writeBytes(chainwork.bigEndianBytes()) // 32
    }

    public static func read(from reader: inout BufferReader) throws -> ChainEntry {
        let hash = try Hash256.read(from: &reader)
        let version = try reader.readUInt32LE()
        let prevBlock = try Hash256.read(from: &reader)
        let merkleRoot = try Hash256.read(from: &reader)
        let witnessRoot = try Hash256.read(from: &reader)
        let treeRoot = try Hash256.read(from: &reader)
        let reservedRoot = try Hash256.read(from: &reader)
        let time = try reader.readUInt64LE()
        let bits = try reader.readUInt32LE()
        let nonce = try reader.readUInt32LE()
        let extraNonce = try reader.readBytes(24)
        let mask = try reader.readBytes(32)
        let height = Int(try reader.readInt64LE())
        let chainworkBytes = try reader.readBytes(32)
        let chainwork = Target256(bigEndian: chainworkBytes)

        return ChainEntry(
            hash: hash,
            version: version,
            prevBlock: prevBlock,
            merkleRoot: merkleRoot,
            witnessRoot: witnessRoot,
            treeRoot: treeRoot,
            reservedRoot: reservedRoot,
            time: time,
            bits: bits,
            nonce: nonce,
            extraNonce: extraNonce,
            mask: mask,
            height: height,
            chainwork: chainwork
        )
    }
}
