import Base
import ExtCrypto
import Protocol
import Consensus
import Chain
import Mempool

/// A block template ready for mining.
///
/// Contains all the information a miner needs to construct a valid block:
/// the header template, selected transactions, and computed merkle roots.
public struct BlockTemplate: Sendable {
    /// The block header template (nonce and time can be varied by miner).
    public let header: BlockHeader

    /// The coinbase transaction (first transaction).
    public let coinbase: Transaction

    /// The selected transactions from the mempool (excluding coinbase).
    public let transactions: [Transaction]

    /// Total fees from included transactions.
    public let fees: Int64

    /// Total weight of all transactions (including coinbase).
    public let weight: Int

    /// Total sigops of all transactions.
    public let sigops: Int

    /// The block height.
    public let height: Int
}

/// Assembles block templates by selecting transactions from the mempool.
///
/// The assembler uses a greedy fee-rate strategy: transactions are sorted
/// by fee rate (bumps per kilobyte) and packed into the block until
/// the weight limit is reached.
public enum BlockAssembler {

    /// The reserved weight for the coinbase transaction.
    /// Ensures there's always room for the coinbase.
    public static let coinbaseReservedWeight = 4000

    /// The reserved sigops for the coinbase transaction.
    public static let coinbaseReservedSigops = 400

    /// Create a block template from the current chain tip and mempool.
    ///
    /// - Parameters:
    ///   - tip: The current chain tip entry.
    ///   - mempool: The transaction mempool.
    ///   - address: The miner's payout address.
    ///   - treeRoot: The current Urkel tree root.
    ///   - reservedRoot: Reserved root hash (usually zero).
    ///   - time: The block timestamp.
    ///   - bits: The difficulty target bits.
    /// - Returns: A block template ready for mining.
    public static func assemble(
        tip: ChainEntry,
        mempool: Mempool,
        address: Address,
        treeRoot: Hash256 = .zero,
        reservedRoot: Hash256 = .zero,
        time: UInt64,
        bits: UInt32
    ) throws -> BlockTemplate {
        let height = tip.height + 1
        let maxWeight = Constants.maxBlockWeight
        let maxSigops = Constants.maxBlockSigops

        var selectedTxs = [Transaction]()
        var totalFees: Int64 = 0
        var totalWeight = coinbaseReservedWeight
        var totalSigops = coinbaseReservedSigops

        // Track which tx hashes are in the mempool and which are selected,
        // so we can skip children whose parents are missing.
        let entries = mempool.getByFeeRate()
        var mempoolHashes = Set<Hash256>()
        for entry in entries {
            mempoolHashes.insert(entry.hash)
        }
        var selectedSet = Set<Hash256>()

        for entry in entries {
            let txWeight = entry.tx.weight
            let txSigops = entry.sigops

            // Check weight limit
            if totalWeight + txWeight > maxWeight {
                continue
            }

            // Check sigops limit
            if totalSigops + txSigops > maxSigops {
                continue
            }

            // Skip transactions whose in-mempool parents were not selected
            var missingParent = false
            for input in entry.tx.inputs {
                if input.isCoinbase { continue }
                if mempoolHashes.contains(input.prevout.hash) && !selectedSet.contains(input.prevout.hash) {
                    missingParent = true
                    break
                }
            }
            if missingParent { continue }

            selectedTxs.append(entry.tx)
            selectedSet.insert(entry.hash)
            let (newFees, overflow) = totalFees.addingReportingOverflow(entry.fee)
            totalFees = overflow ? Int64.max : newFees
            totalWeight += txWeight
            totalSigops += txSigops
        }

        // Topological sort: parents must appear before children.
        // A child is any tx that spends an output created by another tx
        // in the same block. Cycle participants are dropped.
        let presortCount = selectedTxs.count
        selectedTxs = topologicalSort(selectedTxs)

        // If cycle participants were dropped, recalculate totals
        if selectedTxs.count != presortCount {
            let survivingHashes = Set(selectedTxs.map { $0.txHash() })
            totalFees = 0
            totalWeight = coinbaseReservedWeight
            totalSigops = coinbaseReservedSigops
            for entry in entries {
                if survivingHashes.contains(entry.tx.txHash()) {
                    totalFees += entry.fee
                    totalWeight += entry.tx.weight
                    totalSigops += entry.sigops
                }
            }
        }

        // Build coinbase
        let coinbase = CoinbaseBuilder.build(
            address: address,
            height: height,
            fees: totalFees
        )

        // Compute merkle root from all transactions (coinbase first)
        var allTxHashes = [Hash256]()
        allTxHashes.reserveCapacity(1 + selectedTxs.count)
        allTxHashes.append(coinbase.txHash())
        for tx in selectedTxs {
            allTxHashes.append(tx.txHash())
        }
        let merkleRoot = try MerkleTree.computeRoot(allTxHashes)

        // Compute witness root (zero for coinbase, full hash for others)
        let witnessRoot = try computeWitnessRoot(coinbase: coinbase, txs: selectedTxs)

        // Add coinbase weight
        totalWeight = totalWeight - coinbaseReservedWeight + coinbase.weight

        // Build header template
        let header = BlockHeader(
            nonce: 0,
            time: time,
            prevBlock: tip.hash,
            treeRoot: treeRoot,
            reservedRoot: reservedRoot,
            witnessRoot: witnessRoot,
            merkleRoot: merkleRoot,
            version: 0,
            bits: bits
        )

        return BlockTemplate(
            header: header,
            coinbase: coinbase,
            transactions: selectedTxs,
            fees: totalFees,
            weight: totalWeight,
            sigops: totalSigops,
            height: height
        )
    }

    /// Topologically sort transactions so parents come before children.
    ///
    /// If tx B spends an output from tx A, tx A must appear first in the block.
    /// Uses Kahn's algorithm (BFS) for a stable topological order.
    private static func topologicalSort(_ txs: [Transaction]) -> [Transaction] {
        guard txs.count > 1 else { return txs }

        // Build a set of tx hashes in this block
        var txByHash: [Hash256: Int] = [:]  // hash → index
        for (i, tx) in txs.enumerated() {
            txByHash[tx.txHash()] = i
        }

        // Build adjacency: for each tx, which other txs depend on it?
        var dependsOn: [[Int]] = Array(repeating: [], count: txs.count)  // parent indices for each tx
        var inDegree = [Int](repeating: 0, count: txs.count)

        for (i, tx) in txs.enumerated() {
            for input in tx.inputs {
                if let parentIdx = txByHash[input.prevout.hash], parentIdx != i {
                    dependsOn[i].append(parentIdx)
                    inDegree[i] += 1
                }
            }
        }

        // Kahn's algorithm: process nodes with no dependencies first
        var queue = [Int]()
        for i in 0..<txs.count {
            if inDegree[i] == 0 { queue.append(i) }
        }

        var result = [Transaction]()
        result.reserveCapacity(txs.count)

        // Build reverse adjacency (parent → children)
        var children: [[Int]] = Array(repeating: [], count: txs.count)
        for (child, parents) in dependsOn.enumerated() {
            for parent in parents {
                children[parent].append(child)
            }
        }

        var head = 0
        while head < queue.count {
            let idx = queue[head]
            head += 1
            result.append(txs[idx])
            for child in children[idx] {
                inDegree[child] -= 1
                if inDegree[child] == 0 {
                    queue.append(child)
                }
            }
        }

        // If there's a cycle, drop the cycle participants rather than
        // falling back to unsorted order (which could violate parent-before-child).
        return result
    }

    /// Compute the witness root for a set of transactions.
    ///
    /// The witness hash includes the full serialization (with witness data).
    /// For the coinbase, a zero hash is used.
    private static func computeWitnessRoot(
        coinbase: Transaction,
        txs: [Transaction]
    ) throws -> Hash256 {
        var allTxs = [coinbase] + txs
        return try MerkleTree.computeWitnessRoot(allTxs)
    }
}
