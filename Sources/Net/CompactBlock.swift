import Base
import Protocol
import ExtCrypto
import Consensus

// MARK: - SipHash-2-4

/// SipHash-2-4 implementation for compact block short transaction IDs.
///
/// Produces a 64-bit hash from arbitrary input using two 64-bit keys.
/// Used in BIP 152 (adapted for FBD) to create 6-byte short tx IDs.
enum SipHash24 {

    static func hash(key0: UInt64, key1: UInt64, data: [UInt8]) -> UInt64 {
        var v0: UInt64 = 0x736f6d6570736575 ^ key0
        var v1: UInt64 = 0x646f72616e646f6d ^ key1
        var v2: UInt64 = 0x6c7967656e657261 ^ key0
        var v3: UInt64 = 0x7465646279746573 ^ key1

        let length = data.count
        let blocks = length / 8

        // Process full 8-byte blocks
        for i in 0..<blocks {
            let offset = i * 8
            var m: UInt64 = 0
            for j in 0..<8 {
                m |= UInt64(data[offset + j]) << (j * 8)
            }
            v3 ^= m
            sipRound(&v0, &v1, &v2, &v3)
            sipRound(&v0, &v1, &v2, &v3)
            v0 ^= m
        }

        // Process remaining bytes + length byte
        var last: UInt64 = UInt64(length & 0xFF) << 56
        let remaining = length % 8
        let tailStart = blocks * 8
        for i in 0..<remaining {
            last |= UInt64(data[tailStart + i]) << (i * 8)
        }

        v3 ^= last
        sipRound(&v0, &v1, &v2, &v3)
        sipRound(&v0, &v1, &v2, &v3)
        v0 ^= last

        // Finalization
        v2 ^= 0xFF
        sipRound(&v0, &v1, &v2, &v3)
        sipRound(&v0, &v1, &v2, &v3)
        sipRound(&v0, &v1, &v2, &v3)
        sipRound(&v0, &v1, &v2, &v3)

        return v0 ^ v1 ^ v2 ^ v3
    }

    private static func sipRound(
        _ v0: inout UInt64, _ v1: inout UInt64,
        _ v2: inout UInt64, _ v3: inout UInt64
    ) {
        v0 = v0 &+ v1
        v1 = rotl(v1, 13)
        v1 ^= v0
        v0 = rotl(v0, 32)
        v2 = v2 &+ v3
        v3 = rotl(v3, 16)
        v3 ^= v2
        v0 = v0 &+ v3
        v3 = rotl(v3, 21)
        v3 ^= v0
        v2 = v2 &+ v1
        v1 = rotl(v1, 17)
        v1 ^= v2
        v2 = rotl(v2, 32)
    }

    private static func rotl(_ x: UInt64, _ b: UInt64) -> UInt64 {
        (x << b) | (x >> (64 - b))
    }
}

// MARK: - Short Transaction ID

/// A 6-byte short transaction ID used in compact blocks.
struct ShortTxId: Equatable, Hashable {
    let bytes: [UInt8] // 6 bytes

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// Compute a short txid from a full transaction hash using SipHash keys.
    static func compute(txHash: Hash256, key0: UInt64, key1: UInt64) -> ShortTxId {
        let hash = SipHash24.hash(key0: key0, key1: key1, data: txHash.bytes)
        // Take the first 6 bytes (little-endian)
        var bytes = [UInt8](repeating: 0, count: 6)
        for i in 0..<6 {
            bytes[i] = UInt8((hash >> (i * 8)) & 0xFF)
        }
        return ShortTxId(bytes)
    }
}

// MARK: - Compact Block Data

/// Parsed compact block structure (BIP 152 for FBD).
struct CompactBlockData: Sendable {
    /// The block header.
    let header: BlockHeader
    /// BalloonHash proof for PoW verification.
    let balloonProof: BalloonProof
    /// Random nonce for SipHash key derivation.
    let nonce: UInt64
    /// Short transaction IDs (6 bytes each).
    let shortIds: [[UInt8]]
    /// Prefilled transactions (index + full tx).
    let prefilledTxs: [(index: UInt32, tx: Transaction)]

    /// Create a compact block from a full block.
    ///
    /// Prefills the coinbase (index 0) and computes 6-byte short IDs
    /// for all remaining transactions.
    static func fromBlock(_ block: Block, slots: Int = BalloonHash.defaultSlots) throws -> CompactBlockData {
        let headerHash = try ProofOfWork.powHash(for: block.header, slots: slots)
        return fromBlock(block, headerHash: headerHash)
    }

    /// Derive the SipHash keys from a header hash + nonce.
    private static func deriveSipHashKeys(headerHash: Hash256, nonce: UInt64) -> (key0: UInt64, key1: UInt64) {
        var material = headerHash.bytes
        var w = BufferWriter(capacity: 8)
        w.writeUInt64LE(nonce)
        material.append(contentsOf: w.data)
        let hash = SHA256Hash.hash(material)
        var r = BufferReader(hash.bytes)
        let k0 = (try? r.readUInt64LE()) ?? 0
        let k1 = (try? r.readUInt64LE()) ?? 0
        return (k0, k1)
    }

    /// Create a compact block from a full block with a precomputed header hash.
    static func fromBlock(_ block: Block, headerHash: Hash256) -> CompactBlockData {
        var nonce: UInt64 = 0
        for i in 0..<8 { nonce |= UInt64(UInt8.random(in: 0...255)) << (i * 8) }

        let (k0, k1) = deriveSipHashKeys(headerHash: headerHash, nonce: nonce)

        // Coinbase is always prefilled at differential index 0
        var prefilledTxs: [(index: UInt32, tx: Transaction)] = []
        if !block.transactions.isEmpty {
            prefilledTxs.append((index: 0, tx: block.transactions[0]))
        }

        // Compute short IDs for remaining transactions
        var shortIds: [[UInt8]] = []
        shortIds.reserveCapacity(max(block.transactions.count - 1, 0))
        for i in 1..<block.transactions.count {
            let txHash = block.transactions[i].txHash()
            let sid = ShortTxId.compute(txHash: txHash, key0: k0, key1: k1)
            shortIds.append(sid.bytes)
        }

        return CompactBlockData(
            header: block.header,
            balloonProof: block.balloonProof,
            nonce: nonce,
            shortIds: shortIds,
            prefilledTxs: prefilledTxs
        )
    }

    /// Derive the SipHash keys from a precomputed header hash + nonce.
    func sipHashKeys(headerHash: Hash256) -> (key0: UInt64, key1: UInt64) {
        Self.deriveSipHashKeys(headerHash: headerHash, nonce: nonce)
    }
}

// MARK: - Compact Block Packets

/// CompactBlock packet (type 23).
public struct CompactBlockPacket: Packet, Sendable {
    public static let type: PacketType = .cmpctblock

    let data: CompactBlockData

    init(data: CompactBlockData) {
        self.data = data
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        data.header.write(to: &w)
        w.writeBytes(data.balloonProof.serialize())
        w.writeUInt64LE(data.nonce)
        w.writeCompactSize(UInt64(data.shortIds.count))
        for sid in data.shortIds {
            w.writeBytes(sid)
        }
        w.writeCompactSize(UInt64(data.prefilledTxs.count))
        for (index, tx) in data.prefilledTxs {
            w.writeCompactSize(UInt64(index))
            tx.write(to: &w)
        }
        return w.data
    }

    public static func decode(from payload: [UInt8]) throws -> CompactBlockPacket {
        var r = BufferReader(payload)
        let header = try BlockHeader.read(from: &r)
        let proofData = try r.readBytes(BalloonProof.serializedSize)
        guard let proof = BalloonProof.deserialize(proofData) else {
            throw NetError.malformedPacket("invalid BalloonProof")
        }
        let nonce = try r.readUInt64LE()
        let sidCount = Int(try r.readCompactSize())
        guard sidCount <= 10_000 else {
            throw NetError.malformedPacket("compact block shortId count too large")
        }
        var shortIds = [[UInt8]]()
        shortIds.reserveCapacity(sidCount)
        for _ in 0..<sidCount {
            shortIds.append(try r.readBytes(6))
        }
        let pfCount = Int(try r.readCompactSize())
        guard pfCount <= 10_000 else {
            throw NetError.malformedPacket("compact block prefilled count too large")
        }
        var prefilledTxs = [(index: UInt32, tx: Transaction)]()
        prefilledTxs.reserveCapacity(pfCount)
        for _ in 0..<pfCount {
            let index = UInt32(try r.readCompactSize())
            let tx = try Transaction.read(from: &r)
            prefilledTxs.append((index: index, tx: tx))
        }
        let data = CompactBlockData(header: header, balloonProof: proof, nonce: nonce,
                                     shortIds: shortIds, prefilledTxs: prefilledTxs)
        return CompactBlockPacket(data: data)
    }
}

/// GetBlockTxn packet (type 24) — request missing transactions.
public struct GetBlockTxnPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .getblocktxn

    /// Block hash.
    public let hash: Hash256
    /// Indices of requested transactions (differentially encoded on wire).
    public let indices: [UInt32]

    public init(hash: Hash256, indices: [UInt32]) {
        self.hash = hash
        self.indices = indices
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        hash.write(to: &w)
        w.writeCompactSize(UInt64(indices.count))
        // Differential encoding: first index is absolute, rest are deltas
        var prev: UInt32 = 0
        for (i, idx) in indices.enumerated() {
            if i == 0 {
                w.writeCompactSize(UInt64(idx))
            } else {
                w.writeCompactSize(UInt64(idx - prev - 1))
            }
            prev = idx
        }
        return w.data
    }

    public static func decode(from payload: [UInt8]) throws -> GetBlockTxnPacket {
        var r = BufferReader(payload)
        let hash = try Hash256.read(from: &r)
        let count = Int(try r.readCompactSize())
        guard count <= 50_000 else {
            throw NetError.malformedPacket("getblocktxn index count too large: \(count)")
        }
        var indices = [UInt32]()
        indices.reserveCapacity(count)
        var prev: UInt32 = 0
        for i in 0..<count {
            let diff = UInt32(try r.readCompactSize())
            let idx: UInt32
            if i == 0 {
                idx = diff
            } else {
                let (sum, ov1) = prev.addingReportingOverflow(diff)
                let (result, ov2) = sum.addingReportingOverflow(1)
                guard !ov1 && !ov2 else {
                    throw NetError.malformedPacket("getblocktxn index overflow")
                }
                idx = result
            }
            indices.append(idx)
            prev = idx
        }
        return GetBlockTxnPacket(hash: hash, indices: indices)
    }
}

/// BlockTxn packet (type 25) — response with missing transactions.
public struct BlockTxnPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .blocktxn

    /// Block hash.
    public let hash: Hash256
    /// The requested transactions.
    public let transactions: [Transaction]

    public init(hash: Hash256, transactions: [Transaction]) {
        self.hash = hash
        self.transactions = transactions
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        hash.write(to: &w)
        w.writeCompactSize(UInt64(transactions.count))
        for tx in transactions {
            tx.write(to: &w)
        }
        return w.data
    }

    public static func decode(from payload: [UInt8]) throws -> BlockTxnPacket {
        var r = BufferReader(payload)
        let hash = try Hash256.read(from: &r)
        let count = Int(try r.readCompactSize())
        guard count <= 50_000 else {
            throw NetError.malformedPacket("blocktxn tx count too large: \(count)")
        }
        var transactions = [Transaction]()
        transactions.reserveCapacity(count)
        for _ in 0..<count {
            transactions.append(try Transaction.read(from: &r))
        }
        return BlockTxnPacket(hash: hash, transactions: transactions)
    }
}

// MARK: - Compact Block Reconstructor

/// Attempts to reconstruct a full block from a compact block and mempool.
enum CompactBlockReconstructor {

    enum Result {
        /// Full block successfully reconstructed.
        case success(Block)
        /// Some transactions are missing — request them.
        case missing(blockHash: Hash256, indices: [UInt32])
    }

    /// Try to reconstruct a block from compact block data and a mempool snapshot.
    ///
    /// - Parameters:
    ///   - data: The compact block data.
    ///   - mempoolTxs: Map of txHash → Transaction from the mempool.
    /// - Returns: Either a fully reconstructed block or list of missing tx indices.
    static func reconstruct(
        data: CompactBlockData,
        mempoolTxs: [Hash256: Transaction],
        blockHash: Hash256
    ) -> Result {
        let (key0, key1) = data.sipHashKeys(headerHash: blockHash)

        // Total tx count = short IDs + prefilled
        let totalTxs = data.shortIds.count + data.prefilledTxs.count

        // Build a map of short ID → mempool tx
        var shortIdMap = [ShortTxId: Transaction]()
        for (hash, tx) in mempoolTxs {
            let sid = ShortTxId.compute(txHash: hash, key0: key0, key1: key1)
            shortIdMap[sid] = tx
        }

        // Reconstruct the transaction list
        var txs = [Transaction?](repeating: nil, count: totalTxs)

        // Place prefilled transactions (using differential indices)
        var pfIndex: UInt32 = 0
        for (i, pf) in data.prefilledTxs.enumerated() {
            let absIndex = i == 0 ? pf.index : pfIndex + pf.index + 1
            pfIndex = absIndex
            guard Int(absIndex) < totalTxs else { continue }
            txs[Int(absIndex)] = pf.tx
        }

        // Fill remaining slots from mempool using short IDs
        var shortIdIdx = 0
        for i in 0..<totalTxs {
            if txs[i] != nil { continue }
            guard shortIdIdx < data.shortIds.count else { break }

            let sid = ShortTxId(data.shortIds[shortIdIdx])
            shortIdIdx += 1

            if let tx = shortIdMap[sid] {
                txs[i] = tx
            }
        }

        // Check for missing transactions
        var missingIndices = [UInt32]()
        for (i, tx) in txs.enumerated() {
            if tx == nil {
                missingIndices.append(UInt32(i))
            }
        }

        if missingIndices.isEmpty {
            let block = Block(header: data.header, transactions: txs.compactMap { $0 }, balloonProof: data.balloonProof)
            return .success(block)
        } else {
            return .missing(blockHash: blockHash, indices: missingIndices)
        }
    }

    /// Fill in missing transactions from a blocktxn response.
    static func fillMissing(
        txs: inout [Transaction?],
        missingIndices: [UInt32],
        responseTxs: [Transaction],
        header: BlockHeader,
        balloonProof: BalloonProof
    ) -> Block? {
        guard responseTxs.count == missingIndices.count else { return nil }
        for (i, idx) in missingIndices.enumerated() {
            guard Int(idx) < txs.count else { return nil }
            txs[Int(idx)] = responseTxs[i]
        }
        // Verify no holes remain
        guard txs.allSatisfy({ $0 != nil }) else { return nil }
        return Block(header: header, transactions: txs.compactMap { $0 }, balloonProof: balloonProof)
    }
}
