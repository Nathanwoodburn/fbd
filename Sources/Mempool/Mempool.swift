import Foundation
import Base
import Protocol
import Script
import Consensus
import Chain
import Covenants

/// A transaction mempool for Handshake.
///
/// Stores unconfirmed transactions waiting to be included in blocks.
/// Tracks spent outpoints, name covenant operations, and orphan
/// transactions. Enforces fee, size, and ancestor limits.
public final class Mempool: @unchecked Sendable {
    /// Protects all mutable state from concurrent access.
    public let lock = NSRecursiveLock()

    /// Transaction hash → mempool entry.
    public var map: [Hash256: MempoolEntry]

    /// Outpoint key → spending transaction hash.
    public var spents: [Outpoint: Hash256]

    /// Name-aware covenant tracking.
    public var contracts: ContractState

    /// Orphan transactions (hash → raw bytes).
    public var orphans: [Hash256: [UInt8]]

    /// Parent tx hash → set of orphan tx hashes waiting for it.
    public var waiting: [Hash256: Set<Hash256>]

    /// Current estimated memory usage in bytes.
    public var size: Int

    /// Called after a transaction is accepted into the mempool.
    public var onTransactionAccepted: (@Sendable (Transaction) -> Void)?

    /// Called after a transaction is removed/evicted from the mempool.
    public var onTransactionRemoved: (@Sendable (Transaction) -> Void)?

    /// Look up a name's auctionSubdomains flag by nameHash. Set by the node.
    public var nameHasAuctionSubdomains: ((_ nameHash: [UInt8]) -> Bool)?

    /// Validate a transaction's covenants against current chain state.
    /// Set by the node. Returns nil if valid, or an Error if invalid.
    public var validateCovenants: ((_ tx: Transaction, _ coinView: CoinView, _ height: Int) -> Error?)?

    public init() {
        self.map = [:]
        self.spents = [:]
        self.contracts = ContractState()
        self.orphans = [:]
        self.waiting = [:]
        self.size = 0
    }

    /// The number of transactions in the mempool.
    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return map.count
    }

    /// Whether the mempool contains a transaction with the given hash.
    public func has(_ hash: Hash256) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return map[hash] != nil
    }

    /// Get a mempool entry by hash.
    public func get(_ hash: Hash256) -> MempoolEntry? {
        lock.lock()
        defer { lock.unlock() }
        return map[hash]
    }

    /// Check if an outpoint is spent by a mempool transaction.
    public func isDoubleSpend(_ tx: Transaction) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        for input in tx.inputs {
            if input.isCoinbase { continue }
            if spents[input.prevout] != nil { return true }
        }
        return false
    }

    // MARK: - Transaction Acceptance

    /// Accept a transaction into the mempool after full validation.
    ///
    /// Validates: sanity, double-spend, UTXO existence, coinbase maturity,
    /// fee policy, witness scripts, name covenant conflicts, ancestor limits.
    ///
    /// Returns the MempoolEntry on success.
    @discardableResult
    public func acceptTransaction(
        _ tx: Transaction,
        coinDB: CoinDatabase,
        chainHeight: Int,
        params: ConsensusParams
    ) throws -> MempoolEntry {
        lock.lock()
        defer { lock.unlock() }
        let txHash = tx.txHash()

        // 1. Reject coinbase
        guard !tx.isCoinbase else {
            throw MempoolError.verificationFailed("coinbase not allowed in mempool")
        }

        // 2. Duplicate check
        guard !has(txHash) else {
            throw MempoolError.alreadyExists
        }

        // 3. Sanity checks
        try BlockValidator.checkTransactionSanity(tx)

        // 3a. Covenant sanity checks
        for output in tx.outputs {
            try CovenantVerifier.checkCovenantSanity(output.covenant)
        }

        // 3b. Policy weight limit
        guard tx.weight <= MempoolPolicy.maxTxWeight else {
            throw MempoolError.nonStandard("transaction weight exceeds policy limit")
        }

        // 4. Double-spend check
        guard !isDoubleSpend(tx) else {
            throw MempoolError.doubleSpend
        }

        // 5. Name conflict check
        guard !contracts.hasNames(tx) else {
            throw MempoolError.nameConflict
        }

        // 5b. Delegation + auctionSubdomains conflict check (UPDATE and REGISTER)
        for output in tx.outputs {
            if (output.covenant.type == .update || output.covenant.type == .register) && output.covenant.items.count > 2 {
                let nameHash = output.covenant.items[0]
                // Check chain state flag
                let chainFlag = nameHasAuctionSubdomains?(nameHash) ?? false
                // Check covenant's own flags byte (bit 0)
                let covFlag = output.covenant.items.count > 3
                    && !output.covenant.items[3].isEmpty
                    && (output.covenant.items[3][0] & 1 != 0)
                if chainFlag || covFlag {
                    let resource = output.covenant.items[2]
                    if !resource.isEmpty && NameRules.containsDelegationRecords(resource) {
                        throw MempoolError.invalidCovenant(
                            "delegation records not allowed with auctionSubdomains"
                        )
                    }
                }
            }
        }

        // 6. Build CoinView
        var view = CoinView()

        for input in tx.inputs {
            if input.isCoinbase { continue }

            // Check if another mempool tx already spends this outpoint
            if spents[input.prevout] != nil {
                throw MempoolError.doubleSpend
            }

            // Check if a mempool tx created this output
            if let parentEntry = map[input.prevout.hash] {
                // Add the parent tx's outputs to the view (as unconfirmed, height -1)
                view.addTX(parentEntry.tx, height: -1)
            } else if let coin = coinDB.getCoin(input.prevout) {
                // Load from confirmed UTXO set
                view.addEntry(input.prevout, coin)
            } else {
                throw MempoolError.orphanTransaction
            }
        }

        // 7. Coinbase maturity
        for input in tx.inputs {
            if input.isCoinbase { continue }
            if let entry = view.getEntry(input.prevout), entry.coinbase {
                try BlockValidator.checkCoinbaseMaturity(
                    coinbaseHeight: entry.height,
                    spendHeight: chainHeight + 1,
                    params: params
                )
            }
        }

        // 8. Fee calculation
        guard let fee = view.getFee(tx), fee >= 0 else {
            throw MempoolError.insufficientFee
        }

        let minFee = MempoolPolicy.getMinFee(size: tx.virtualSize)
        guard fee >= minFee else {
            throw MempoolError.insufficientFee
        }

        // 9. Absurd fee check
        let absurdFee = MempoolPolicy.absurdFeeFactor * minFee
        if fee > absurdFee {
            throw MempoolError.absurdFee
        }

        // 10. Witness verification
        for (i, input) in tx.inputs.enumerated() {
            if input.isCoinbase { continue }
            guard let coin = view.getEntry(input.prevout) else { continue }
            try WitnessVerifier.verify(
                tx: tx,
                index: i,
                address: coin.output.address,
                value: coin.output.value,
                flags: .standard
            )
        }

        // 10b. Covenant semantic validation (payments, state transitions, etc.)
        if let validateCovenants = validateCovenants,
           tx.outputs.contains(where: { $0.covenant.type.isName }) {
            if let error = validateCovenants(tx, view, chainHeight + 1) {
                throw MempoolError.invalidCovenant("\(error)")
            }
        }

        // 11. Ancestor count
        guard countAncestors(tx) <= MempoolPolicy.maxAncestors else {
            throw MempoolError.tooManyAncestors
        }

        // 12. Size limits — evict if needed, then check
        let estimatedSize = 200 + tx.serializedSize
        if size + estimatedSize > MempoolPolicy.maxSize {
            evictByFeeRate()
            if size + estimatedSize > MempoolPolicy.maxSize {
                throw MempoolError.mempoolFull
            }
        }

        // 13. Create MempoolEntry
        let now = UInt64(Date().timeIntervalSince1970)
        let entry = MempoolEntry(tx: tx, view: view, height: chainHeight, time: now)

        // 14. Sigops limit
        guard entry.sigops <= MempoolPolicy.maxTxSigops else {
            throw MempoolError.tooManySigops
        }

        // 15–16. Add to pool (addEntry handles covenant tracking and spents)
        addEntry(entry)

        // Notify listeners (wallet indexing, etc.)
        onTransactionAccepted?(entry.tx)

        return entry
    }

    // MARK: - Block Integration

    /// Remove all transactions confirmed in a block.
    ///
    /// Confirmed txs are removed silently. Any mempool txs that depended
    /// on the confirmed txs (descendants/conflicts) are evicted with
    /// wallet notification so spent coins can be restored.
    public func removeBlock(_ block: Block) {
        lock.lock()
        defer { lock.unlock() }
        // Collect confirmed tx hashes for fast lookup
        var confirmedHashes = Set<Hash256>()
        for tx in block.transactions {
            if tx.isCoinbase { continue }
            confirmedHashes.insert(tx.txHash())
        }

        for hash in confirmedHashes {
            guard let entry = map[hash] else { continue }
            let removed = removeEntry(hash)
            // Notify wallets about any NON-confirmed descendants that got evicted
            for evicted in removed where evicted.hash != entry.hash && !confirmedHashes.contains(evicted.hash) {
                onTransactionRemoved?(evicted.tx)
            }
        }

        // Resolve orphans whose missing parent was just confirmed
        for tx in block.transactions {
            let txHash = tx.txHash()
            let resolved = resolveOrphans(for: txHash)
            for orphanHash in resolved {
                removeOrphan(orphanHash)
            }
        }
    }

    /// Re-add transactions from a disconnected block (reorg).
    public func addBlock(_ block: Block, coinDB: CoinDatabase, chainHeight: Int, params: ConsensusParams) {
        lock.lock()
        defer { lock.unlock() }
        for tx in block.transactions {
            if tx.isCoinbase { continue }
            // Ignore errors — tx may now be invalid after reorg
            _ = try? acceptTransaction(tx, coinDB: coinDB, chainHeight: chainHeight, params: params)
        }
    }

    // MARK: - Adding Entries

    /// Add a validated mempool entry.
    ///
    /// Indexes the entry in all maps and tracks covenant operations.
    public func addEntry(_ entry: MempoolEntry) {
        lock.lock()
        defer { lock.unlock() }
        let hash = entry.hash

        // Index by hash
        map[hash] = entry

        // Track spent outpoints
        for input in entry.tx.inputs {
            if input.isCoinbase { continue }
            spents[input.prevout] = hash
        }

        // Track covenants
        contracts.track(entry.tx, txHash: hash)

        // Update size estimate
        size += estimateMemUsage(entry)
    }

    /// Remove a mempool entry and all its descendants.
    ///
    /// Returns the list of removed entries.
    @discardableResult
    public func removeEntry(_ hash: Hash256) -> [MempoolEntry] {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = map.removeValue(forKey: hash) else { return [] }
        var removed = [entry]

        // Remove spent outpoint tracking
        for input in entry.tx.inputs {
            if input.isCoinbase { continue }
            spents.removeValue(forKey: input.prevout)
        }

        // Untrack covenants
        contracts.untrack(entry.tx, txHash: hash)

        // Update size
        size -= estimateMemUsage(entry)

        // Remove any descendants (transactions spending this tx's outputs)
        let txHash = entry.hash
        for (i, _) in entry.tx.outputs.enumerated() {
            let childOutpoint = Outpoint(hash: txHash, index: UInt32(i))
            if let childHash = spents[childOutpoint] {
                removed.append(contentsOf: removeEntry(childHash))
            }
        }

        return removed
    }

    /// Remove a transaction from the mempool and notify listeners.
    ///
    /// Unlike `removeEntry`, this fires `onTransactionRemoved` for each
    /// evicted transaction so wallets can restore spent coins.
    @discardableResult
    public func evictEntry(_ hash: Hash256) -> [MempoolEntry] {
        lock.lock()
        defer { lock.unlock() }
        let removed = removeEntry(hash)
        for entry in removed {
            onTransactionRemoved?(entry.tx)
        }
        return removed
    }

    // MARK: - Orphans

    /// Add an orphan transaction.
    ///
    /// - Parameters:
    ///   - hash: The transaction hash.
    ///   - raw: The serialized transaction bytes.
    ///   - missingParents: The hashes of missing parent transactions.
    public func addOrphan(_ hash: Hash256, raw: [UInt8], missingParents: [Hash256]) {
        lock.lock()
        defer { lock.unlock() }
        // Limit orphan pool
        if orphans.count >= MempoolPolicy.maxOrphans {
            evictRandomOrphan()
        }

        orphans[hash] = raw
        for parent in missingParents {
            waiting[parent, default: []].insert(hash)
        }
    }

    /// Remove an orphan transaction.
    public func removeOrphan(_ hash: Hash256) {
        lock.lock()
        defer { lock.unlock() }
        orphans.removeValue(forKey: hash)
        // Remove from waiting sets
        for key in waiting.keys {
            waiting[key]?.remove(hash)
            if waiting[key]?.isEmpty == true {
                waiting.removeValue(forKey: key)
            }
        }
    }

    /// Evict a random orphan to make room.
    private func evictRandomOrphan() {
        guard let key = orphans.keys.first else { return }
        removeOrphan(key)
    }

    /// Resolve orphans waiting for a parent transaction.
    ///
    /// - Parameter parentHash: The hash of the newly available parent.
    /// - Returns: Hashes of orphans that may now have all parents available.
    public func resolveOrphans(for parentHash: Hash256) -> [Hash256] {
        lock.lock()
        defer { lock.unlock() }
        guard let waiters = waiting.removeValue(forKey: parentHash) else {
            return []
        }
        return Array(waiters)
    }

    // MARK: - Eviction

    /// Evict expired transactions.
    ///
    /// - Parameter now: The current unix timestamp.
    /// - Returns: The number of transactions evicted.
    @discardableResult
    public func evictExpired(now: UInt64) -> Int {
        lock.lock()
        defer { lock.unlock() }
        var evicted = 0
        for hash in map.keys {
            guard let entry = map[hash] else { continue }
            if now >= entry.time + MempoolPolicy.expiryTime {
                let removed = removeEntry(hash)
                evicted += removed.count
            }
        }
        return evicted
    }

    /// Evict transactions by fee rate until under the threshold.
    ///
    /// Sorts entries by effective fee rate once, then evicts from the
    /// bottom of the sorted list. This avoids the O(n^2) cost of
    /// scanning for the minimum on every eviction.
    ///
    /// - Returns: The number of transactions evicted.
    @discardableResult
    public func evictByFeeRate() -> Int {
        lock.lock()
        defer { lock.unlock() }
        guard size > MempoolPolicy.evictionThreshold && !map.isEmpty else { return 0 }

        // Sort all entries by effective fee rate (lowest first)
        let sorted = map.values.sorted { a, b in
            let rateA: Int64
            if a.descFee * Int64(a.size) > a.deltaFee * Int64(a.descSize) {
                rateA = a.descRate
            } else {
                rateA = a.deltaRate
            }
            let rateB: Int64
            if b.descFee * Int64(b.size) > b.deltaFee * Int64(b.descSize) {
                rateB = b.descRate
            } else {
                rateB = b.deltaRate
            }
            return rateA < rateB
        }

        var evicted = 0
        for entry in sorted {
            guard size > MempoolPolicy.evictionThreshold else { break }
            // Entry may already have been removed as a descendant of a
            // previous eviction, so check it still exists.
            guard map[entry.hash] != nil else { continue }
            let removed = evictEntry(entry.hash)
            evicted += removed.count
        }

        return evicted
    }

    // MARK: - Ancestor Counting

    /// Count the number of in-mempool ancestors for a transaction.
    public func countAncestors(_ tx: Transaction) -> Int {
        lock.lock()
        defer { lock.unlock() }
        var visited = Set<Hash256>()
        var queue = [Hash256]()

        for input in tx.inputs {
            if input.isCoinbase { continue }
            if map[input.prevout.hash] != nil {
                queue.append(input.prevout.hash)
            }
        }

        while let hash = queue.popLast() {
            guard visited.insert(hash).inserted else { continue }
            if let entry = map[hash] {
                for input in entry.tx.inputs {
                    if input.isCoinbase { continue }
                    if map[input.prevout.hash] != nil && !visited.contains(input.prevout.hash) {
                        queue.append(input.prevout.hash)
                    }
                }
            }
        }

        return visited.count
    }

    // MARK: - Query

    /// Get all transactions in the mempool, sorted by fee rate (highest first).
    public func getByFeeRate() -> [MempoolEntry] {
        lock.lock()
        defer { lock.unlock() }
        return map.values.sorted { $0.rate > $1.rate }
    }

    // MARK: - Helpers

    /// Estimate memory usage for an entry (simplified).
    private func estimateMemUsage(_ entry: MempoolEntry) -> Int {
        // Base struct overhead + serialized tx size
        200 + entry.tx.serializedSize
    }
}
