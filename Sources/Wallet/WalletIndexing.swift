import Storage
import Foundation
import Base
import Consensus
import Covenants
import Protocol

// MARK: - Block & Transaction Indexing

extension WalletDB {
    /// Index a block, tracking wallet UTXOs.
    ///
    /// Scans outputs for addresses we own, removes spent coins from inputs.
    @discardableResult
    public func indexBlock(_ block: Block, height: Int) throws -> [(hash: Hash256, sent: UInt64, received: UInt64)] {
        lock.lock()
        defer { lock.unlock() }
        guard initialized else { return [] }

        // Ensure blocks are indexed sequentially — skipping a block would
        // permanently lose its wallet transactions. scanHeight == -1 means
        // no blocks indexed yet, so any starting height is valid.
        guard scanHeight == -1 || height == scanHeight + 1 else {
            throw WalletError.heightMismatch(expected: scanHeight + 1, got: height)
        }

        var ops = [(db: UInt8, op: LevelDBStore.BatchOp)]()
        var gapChanged = false
        var spentCoins = [UInt8]()
        var relevantTxs = [(hash: Hash256, sent: UInt64, received: UInt64)]()

        // Track coins added within this block so same-block spends are detected.
        // The DB isn't committed until the end, so get() won't see intra-block coins.
        var pendingCoins = [[UInt8]: [UInt8]]()  // outpointKey → serialized WalletCoin

        let blockTime = UInt64(block.header.time)

        for (txIndex, tx) in block.transactions.enumerated() {
            let txHash = tx.txHash()
            var txSent: UInt64 = 0
            var txReceived: UInt64 = 0
            var txInputTotal: UInt64 = 0
            var allInputsOurs = true
            var touchesWallet = false

            // Scan outputs for our addresses
            for (outputIndex, output) in tx.outputs.enumerated() {
                let addrKey = AddressKey(output.address)
                guard addressSet.contains(addrKey) else { continue }

                touchesWallet = true
                // Don't count covenant-locked outputs as received (they're not spendable)
                if !output.covenant.type.isName {
                    txReceived += output.value
                }

                let outpoint = Outpoint(hash: txHash, index: UInt32(outputIndex))
                let coin = WalletCoin(
                    value: output.value,
                    height: height,
                    coinbase: txIndex == 0,
                    address: output.address,
                    covenant: output.covenant,
                    outpoint: outpoint
                )

                let coinKey = outpointKey(outpoint)
                let serialized = coin.serialize()
                ops.append((coinsDB, .put(key: coinKey, value: serialized)))
                pendingCoins[coinKey] = serialized

                // For BID covenants, create a partial BidRecord if none exists.
                // This handles wallet reimport where the nonce is lost — the
                // record is flagged with zeroed nonce/value so the UI can prompt
                // the user to repair it.
                if output.covenant.type == .bid && output.covenant.items.count >= 4 {
                    let bidNameHash = NameHash(unchecked: output.covenant.items[0])
                    // Create a placeholder only if no record exists at this key.
                    var kw = BufferWriter(capacity: 68)
                    kw.writeBytes(bidNameHash.bytes)
                    kw.writeBytes(outpoint.hash.bytes)
                    kw.writeUInt32LE(outpoint.index)
                    if (try? get(db: bidsDB, key: kw.data)) == nil {
                        try? saveBid(BidRecord(
                            nameHash: bidNameHash, outpoint: outpoint,
                            nonce: .zero, value: 0, lockup: output.value, height: height
                        ))
                    }
                }

                // Add to address→outpoint index
                let idxKey = addressKeyBytes(output.address) + coinKey
                ops.append((indexDB, .put(key: idxKey, value: [])))

                // Advance gap tracking
                if let pathData = try get(db: addressesDB, key: addressKeyBytes(output.address)) {
                    if let path = String(bytes: pathData, encoding: .utf8) {
                        updateGapTracking(path: path)
                        gapChanged = true
                    }
                }
            }

            // Scan inputs for spent coins
            if !tx.isCoinbase {
                for input in tx.inputs {
                    let coinKey = outpointKey(input.prevout)
                    // Check committed DB first, then pending intra-block coins
                    let existing = try get(db: coinsDB, key: coinKey) ?? pendingCoins[coinKey]
                    if let existing {
                        if let coin = WalletCoin.deserialize(existing, outpoint: input.prevout) {
                            touchesWallet = true
                            txSent += coin.value
                            txInputTotal += coin.value
                            let idxKey = addressKeyBytes(coin.address) + coinKey
                            ops.append((indexDB, .delete(key: idxKey)))
                        }
                        ops.append((coinsDB, .delete(key: coinKey)))
                        pendingCoins.removeValue(forKey: coinKey)
                        // Save to undo data for disconnect support
                        spentCoins.append(contentsOf: serializeUndoEntry(coinKey, existing))
                    } else {
                        allInputsOurs = false
                    }
                }
            } else {
                allInputsOurs = false
            }

            // Record history entry if this tx touches the wallet
            if touchesWallet {
                let fee: UInt64
                if allInputsOurs && txSent > 0 {
                    let totalOut = tx.outputs.reduce(UInt64(0)) { $0 + $1.value }
                    fee = txInputTotal > totalOut ? txInputTotal - totalOut : 0
                } else {
                    fee = 0
                }
                // Collect covenant types from wallet-relevant outputs
                var covTypes: UInt16 = 0
                for output in tx.outputs {
                    if addressSet.contains(AddressKey(output.address)) {
                        covTypes |= (1 << output.covenant.type.rawValue)
                    }
                }
                let record = TransactionRecord(
                    txHash: txHash, sent: txSent, received: txReceived,
                    fee: fee, height: Int32(height), timestamp: blockTime,
                    covenantTypes: covTypes
                )
                let histKey = historyKey(height: height, txIndex: txIndex, txHash: txHash)
                ops.append((historyDB, .put(key: histKey, value: record.serialize())))

                // Remove the mempool history entry (if any) now that the tx is confirmed
                let mempoolHistKey = historyKey(height: Int(Int32.max), txIndex: 0, txHash: txHash)
                ops.append((historyDB, .delete(key: mempoolHistKey)))

                relevantTxs.append((hash: txHash, sent: txSent, received: txReceived))
            }
        }

        // Store undo data for disconnect support (only if we spent wallet coins)
        if !spentCoins.isEmpty {
            ops.append((undoDB, .put(key: intToBytes(height), value: spentCoins)))
        }

        // Update scan height
        ops.append((metaDB, .put(key: Array("height".utf8), value: intToBytes(height))))

        // Persist used indices if changed
        if gapChanged {
            ops.append((metaDB, .put(key: Array("usedReceive".utf8),
                                     value: intToBytes(receiveIndex))))
            ops.append((metaDB, .put(key: Array("usedChange".utf8),
                                     value: intToBytes(changeIndex))))
        }

        if !ops.isEmpty {
            try writeBatch(ops)
        }

        scanHeight = height

        // Extend gap if needed
        if gapChanged {
            try ensureGap()
        }

        return relevantTxs
    }

    /// Index a single transaction from the mempool.
    ///
    /// Adds unconfirmed outputs (height = -1) for addresses we own, and
    /// marks confirmed coins spent by this transaction as "spent-by-unconfirmed"
    /// (height = -(originalHeight + 2)) so they can be restored on startup.
    @discardableResult
    public func indexTransaction(_ tx: Transaction, timestamp: UInt64? = nil) throws -> Bool {
        guard initialized else { return false }

        let txHash = tx.txHash()
        var ops = [(db: UInt8, op: LevelDBStore.BatchOp)]()
        var txSent: UInt64 = 0
        var txReceived: UInt64 = 0
        var txInputTotal: UInt64 = 0
        var allInputsOurs = true
        var touchesWallet = false

        // Mark spent wallet coins (soft-delete: preserve for recovery on restart)
        if !tx.isCoinbase {
            for input in tx.inputs {
                let coinKey = outpointKey(input.prevout)
                if let existing = try get(db: coinsDB, key: coinKey) {
                    if let coin = WalletCoin.deserialize(existing, outpoint: input.prevout) {
                        touchesWallet = true
                        txSent += coin.value
                        txInputTotal += coin.value
                        // Mark as spent-by-unconfirmed: encode original height as -(height + 2)
                        // height -1 = unconfirmed coin, height <= -2 = spent-by-unconfirmed
                        // Special case: unconfirmed coins (h=-1) would get -((-1)+2)=-1,
                        // staying at -1 and causing double-counting. Use Int32.min as sentinel.
                        let spentHeight = coin.height == -1 ? Int(Int32.min) : -(coin.height + 2)
                        let markedCoin = WalletCoin(
                            value: coin.value, height: spentHeight,
                            coinbase: coin.coinbase, address: coin.address,
                            covenant: coin.covenant, outpoint: coin.outpoint
                        )
                        ops.append((coinsDB, .put(key: coinKey, value: markedCoin.serialize())))
                    }
                } else {
                    allInputsOurs = false
                }
            }
        } else {
            allInputsOurs = false
        }

        // Add unconfirmed outputs
        for (outputIndex, output) in tx.outputs.enumerated() {
            let addrKey = AddressKey(output.address)
            guard addressSet.contains(addrKey) else { continue }

            touchesWallet = true
            // Don't count covenant-locked outputs as received (they're not spendable)
            if !output.covenant.type.isName {
                txReceived += output.value
            }

            let outpoint = Outpoint(hash: txHash, index: UInt32(outputIndex))
            let coinKey = outpointKey(outpoint)

            // Skip if this output already exists (e.g. confirmed coin)
            if let _ = try get(db: coinsDB, key: coinKey) { continue }

            let coin = WalletCoin(
                value: output.value,
                height: -1,
                coinbase: false,
                address: output.address,
                covenant: output.covenant,
                outpoint: outpoint
            )

            ops.append((coinsDB, .put(key: coinKey, value: coin.serialize())))

            let idxKey = addressKeyBytes(output.address) + coinKey
            ops.append((indexDB, .put(key: idxKey, value: [])))
        }

        // Record history entry for mempool tx
        if touchesWallet {
            let fee: UInt64
            if allInputsOurs && txSent > 0 {
                let totalOut = tx.outputs.reduce(UInt64(0)) { $0 + $1.value }
                fee = txInputTotal > totalOut ? txInputTotal - totalOut : 0
            } else {
                fee = 0
            }
            var covTypes: UInt16 = 0
            for output in tx.outputs {
                if addressSet.contains(AddressKey(output.address)) {
                    covTypes |= (1 << output.covenant.type.rawValue)
                }
            }
            let ts = timestamp ?? UInt64(Date().timeIntervalSince1970)
            let record = TransactionRecord(
                txHash: txHash, sent: txSent, received: txReceived,
                fee: fee, height: -1, timestamp: ts,
                covenantTypes: covTypes
            )
            // Mempool: height=max, txIndex=0 so it sorts after all confirmed
            let histKey = historyKey(height: Int(Int32.max), txIndex: 0, txHash: txHash)
            ops.append((historyDB, .put(key: histKey, value: record.serialize())))
        }

        if !ops.isEmpty {
            try writeBatch(ops)
        }

        return touchesWallet
    }

    /// Reverse a mempool transaction's wallet changes.
    ///
    /// Restores spent-by-unconfirmed coins to their original confirmed height,
    /// removes unconfirmed output coins, and deletes mempool history entries.
    /// Called when a mempool transaction is evicted or replaced.
    @discardableResult
    public func unindexTransaction(_ tx: Transaction) throws -> Bool {
        guard initialized else { return false }

        let txHash = tx.txHash()
        var ops = [(db: UInt8, op: LevelDBStore.BatchOp)]()
        var touchesWallet = false

        // Restore inputs: undo spent-by-unconfirmed marks
        if !tx.isCoinbase {
            for input in tx.inputs {
                let coinKey = outpointKey(input.prevout)
                if let existing = try get(db: coinsDB, key: coinKey) {
                    if let coin = WalletCoin.deserialize(existing, outpoint: input.prevout),
                       coin.height <= -2 {
                        // Restore to original height
                        // Int32.min sentinel = was unconfirmed (h=-1), otherwise -(h+2)
                        let originalHeight = coin.height == Int(Int32.min) ? -1 : -(coin.height + 2)
                        let restored = WalletCoin(
                            value: coin.value, height: originalHeight,
                            coinbase: coin.coinbase, address: coin.address,
                            covenant: coin.covenant, outpoint: coin.outpoint
                        )
                        ops.append((coinsDB, .put(key: coinKey, value: restored.serialize())))
                        touchesWallet = true
                    }
                }
            }
        }

        // Remove unconfirmed outputs created by this tx
        for (outputIndex, output) in tx.outputs.enumerated() {
            let outpoint = Outpoint(hash: txHash, index: UInt32(outputIndex))
            let coinKey = outpointKey(outpoint)
            if let existing = try get(db: coinsDB, key: coinKey) {
                if let coin = WalletCoin.deserialize(existing, outpoint: outpoint),
                   coin.height == -1 {
                    ops.append((coinsDB, .delete(key: coinKey)))
                    let idxKey = addressKeyBytes(output.address) + coinKey
                    ops.append((indexDB, .delete(key: idxKey)))
                    touchesWallet = true
                }
            }
        }

        // Remove mempool history entry
        let histKey = historyKey(height: Int(Int32.max), txIndex: 0, txHash: txHash)
        if let _ = try get(db: historyDB, key: histKey) {
            ops.append((historyDB, .delete(key: histKey)))
        }

        if !ops.isEmpty {
            try writeBatch(ops)
        }

        return touchesWallet
    }

    /// Reverse a block's wallet changes during a chain reorganization.
    ///
    /// Removes outputs that were added by this block and restores any
    /// wallet coins that were spent by this block (from undo data).
    public func unindexBlock(_ block: Block, height: Int) throws {
        guard initialized else { return }
        guard height == scanHeight else { return }

        var ops = [(db: UInt8, op: LevelDBStore.BatchOp)]()

        for (txIndex, tx) in block.transactions.enumerated() {
            let txHash = tx.txHash()

            // Remove outputs that were added to the wallet by this block
            for (outputIndex, output) in tx.outputs.enumerated() {
                let addrKey = AddressKey(output.address)
                guard addressSet.contains(addrKey) else { continue }

                let outpoint = Outpoint(hash: txHash, index: UInt32(outputIndex))
                let coinKey = outpointKey(outpoint)
                ops.append((coinsDB, .delete(key: coinKey)))

                // Remove from address index
                let idxKey = addressKeyBytes(output.address) + coinKey
                ops.append((indexDB, .delete(key: idxKey)))
            }

            // Delete history entry for this tx
            let histKey = historyKey(height: height, txIndex: txIndex, txHash: txHash)
            ops.append((historyDB, .delete(key: histKey)))
        }

        // Restore spent coins from undo data
        if let undoData = try get(db: undoDB, key: intToBytes(height)) {
            let entries = deserializeUndoEntries(undoData)
            for (coinKey, coinData) in entries {
                ops.append((coinsDB, .put(key: coinKey, value: coinData)))

                // Restore address index entry
                if let coin = WalletCoin.deserialize(coinData,
                    outpoint: outpointFromKey(coinKey)) {
                    let idxKey = addressKeyBytes(coin.address) + coinKey
                    ops.append((indexDB, .put(key: idxKey, value: [])))
                }
            }
            // Delete undo data for this height
            ops.append((undoDB, .delete(key: intToBytes(height))))
        }

        // Update scan height to previous block
        let newHeight = height - 1
        ops.append((metaDB, .put(key: Array("height".utf8), value: intToBytes(newHeight))))

        if !ops.isEmpty {
            try writeBatch(ops)
        }

        scanHeight = newHeight
    }

    /// Set the scan height without indexing any blocks.
    public func setScanHeight(_ height: Int) throws {
        scanHeight = height
        try put(db: metaDB, key: Array("height".utf8), value: intToBytes(height))
    }

    /// Clear coins, index, and undo databases and reset scan height to -1.
    ///
    /// Call this before re-scanning all blocks to rebuild wallet state
    /// from scratch.
    public func resetForRescan() throws {
        guard initialized else { return }
        try clearDB(coinsDB)
        try clearDB(indexDB)
        try clearDB(undoDB)
        try clearDB(historyDB)
        scanHeight = -1
        try put(db: metaDB, key: Array("height".utf8), value: intToBytes(-1))
    }

    /// Purge all unconfirmed wallet state from the database.
    ///
    /// Called on startup to clean up stale mempool state:
    /// - Deletes unconfirmed coins (height = -1) created by mempool txs
    /// - Restores confirmed coins that were marked as spent-by-unconfirmed
    ///   (height <= -2) back to their original confirmed height
    /// - Removes unconfirmed history entries
    ///
    /// - Returns: Number of coins affected (for logging).
    @discardableResult
    public func purgeUnconfirmedState() throws -> Int {
        guard initialized else { return 0 }

        var ops = [(db: UInt8, op: LevelDBStore.BatchOp)]()
        var affected = 0

        try forEachEntry(db: coinsDB) { key, value in
            guard key.count == 36 else { return }
            let txHash = Hash256(unchecked: Array(key[0..<32]))
            let idx = UInt32(key[32]) | UInt32(key[33]) << 8
                | UInt32(key[34]) << 16 | UInt32(key[35]) << 24
            let outpoint = Outpoint(hash: txHash, index: idx)
            guard let coin = WalletCoin.deserialize(value, outpoint: outpoint) else { return }

            if coin.height == -1 {
                // Unconfirmed coin from mempool tx — delete it
                ops.append((coinsDB, .delete(key: key)))
                let idxKey = addressKeyBytes(coin.address) + key
                ops.append((indexDB, .delete(key: idxKey)))
                affected += 1
            } else if coin.height == Int(Int32.min) {
                // Unconfirmed coin spent by another mempool tx — delete it entirely
                ops.append((coinsDB, .delete(key: key)))
                let idxKey = addressKeyBytes(coin.address) + key
                ops.append((indexDB, .delete(key: idxKey)))
                affected += 1
            } else if coin.height <= -2 {
                // Confirmed coin marked as spent-by-unconfirmed — restore original height
                let originalHeight = -(coin.height + 2)
                let restored = WalletCoin(
                    value: coin.value, height: originalHeight,
                    coinbase: coin.coinbase, address: coin.address,
                    covenant: coin.covenant, outpoint: coin.outpoint
                )
                ops.append((coinsDB, .put(key: key, value: restored.serialize())))
                affected += 1
            }
        }

        // Remove unconfirmed history entries (stored with height=Int32.max)
        try forEachEntry(db: historyDB) { key, value in
            guard key.count == 38 else { return }
            // Height is first 4 bytes, big-endian
            let h = Int(key[0]) << 24 | Int(key[1]) << 16 | Int(key[2]) << 8 | Int(key[3])
            if h == Int(Int32.max) {
                ops.append((historyDB, .delete(key: key)))
            }
        }

        if !ops.isEmpty {
            try writeBatch(ops)
        }

        return affected
    }

    /// List recent transaction history (newest first).
    ///
    /// - Parameters:
    ///   - count: Maximum records to return (default 10).
    ///   - offset: Number of records to skip (default 0).
    /// - Returns: Array of transaction records, newest first.
    public func listTransactions(count: Int = 10, offset: Int = 0) throws -> [TransactionRecord] {
        var results = [TransactionRecord]()
        var skipped = 0

        try reverseForEachEntry(db: historyDB) { key, value in
            // Key: [height:4 BE][txIndex:2 BE][txHash:32]
            guard key.count == 38 else { return true }
            let txIndex = UInt16(key[4]) << 8 | UInt16(key[5])
            let txHash = Hash256(unchecked: Array(key[6..<38]))

            if skipped < offset {
                skipped += 1
                return true
            }

            if var record = TransactionRecord.deserialize(value, txHash: txHash) {
                record.coinbase = txIndex == 0 && record.height >= 0
                results.append(record)
            }

            return results.count < count
        }

        return results
    }
}
