import Foundation
import Base
import Protocol
import Consensus
import Storage

// MARK: - Transaction & Address Indexing

extension Chain {

    /// Whether the transaction index is enabled.
    public var hasTxIndex: Bool {
        lock.lock()
        defer { lock.unlock() }
        return txIndexStore != nil
    }

    /// Whether the address index is enabled.
    public var hasAddrIndex: Bool {
        lock.lock()
        defer { lock.unlock() }
        return addrIndexStore != nil
    }

    /// Index a transaction's location (called during connectBlock when tx index is enabled).
    /// Called from within already-locked context (_connectBlock); do not acquire lock.
    func putTxIndex(txHash: Hash256, height: Int, txIndex: Int) {
        guard let store = txIndexStore else { return }
        var value = [UInt8]()
        value.append(contentsOf: withUnsafeBytes(of: UInt32(height).littleEndian) { Array($0) })
        value.append(contentsOf: withUnsafeBytes(of: UInt16(txIndex).littleEndian) { Array($0) })
        try? store.put(db: txIndexDB, key: txHash.bytes, value: value)
    }

    /// Look up a transaction's block location from the index.
    public func getTxLocation(txHash: Hash256) -> (height: Int, txIndex: Int)? {
        lock.lock()
        defer { lock.unlock() }
        guard let store = txIndexStore else { return nil }
        guard let data = try? store.get(db: txIndexDB, key: txHash.bytes), data.count >= 6 else {
            return nil
        }
        let height = Int(UInt32(data[0]) | UInt32(data[1]) << 8 | UInt32(data[2]) << 16 | UInt32(data[3]) << 24)
        let txIdx = Int(UInt16(data[4]) | UInt16(data[5]) << 8)
        return (height: height, txIndex: txIdx)
    }

    /// Remove a transaction from the index (called during disconnectBlock).
    /// Called from within already-locked context (_disconnectTo); do not acquire lock.
    func removeTxIndex(txHash: Hash256) {
        guard let store = txIndexStore else { return }
        try? store.delete(db: txIndexDB, key: txHash.bytes)
    }

    // MARK: - Address Index

    /// Index a block's address->tx and address->coin mappings.
    ///
    /// For each output: records address->txHash and address->outpoint (unspent coin).
    /// For each input (non-coinbase): records address->txHash and removes the spent coin.
    /// The `undoCoins` parameter supplies the coins being spent (needed for input addresses).
    /// Called from within already-locked context (_connectBlock); do not acquire lock.
    func indexAddresses(block: Block, height: Int, undoCoins: [CoinEntry]) {
        guard let store = addrIndexStore else { return }
        var batch: [(db: UInt8, op: LevelDBStore.BatchOp)] = []
        var undoIdx = 0

        for (i, tx) in block.transactions.enumerated() {
            let txHash = tx.txHash()

            // Index outputs: address->tx mapping + new unspent coin
            for (j, output) in tx.outputs.enumerated() {
                let addr = output.address.hash
                guard addr != Address.null.hash else { continue }

                // addr + txHash -> tx mapping (key-existence)
                batch.append((addrTxDB, .put(key: addr + txHash.bytes, value: [])))

                // addr + txHash + index -> unspent coin
                let idx = UInt32(j)
                let coinKey = addr + txHash.bytes + [
                    UInt8(idx & 0xFF), UInt8((idx >> 8) & 0xFF),
                    UInt8((idx >> 16) & 0xFF), UInt8((idx >> 24) & 0xFF),
                ]
                batch.append((addrCoinDB, .put(key: coinKey, value: [])))
            }

            // Index inputs: address->tx mapping + remove spent coin
            if i > 0 {
                for input in tx.inputs {
                    if input.isCoinbase { continue }
                    guard undoIdx < undoCoins.count else { break }
                    let coin = undoCoins[undoIdx]
                    undoIdx += 1

                    let addr = coin.output.address.hash
                    guard addr != Address.null.hash else { continue }

                    // This tx touches this address
                    batch.append((addrTxDB, .put(key: addr + txHash.bytes, value: [])))

                    // Remove the spent coin
                    let prevIdx = input.prevout.index
                    let coinKey = addr + input.prevout.hash.bytes + [
                        UInt8(prevIdx & 0xFF), UInt8((prevIdx >> 8) & 0xFF),
                        UInt8((prevIdx >> 16) & 0xFF), UInt8((prevIdx >> 24) & 0xFF),
                    ]
                    batch.append((addrCoinDB, .delete(key: coinKey)))
                }
            }
        }

        try? store.writeBatch(batch)
    }

    /// Remove address index entries for a block being disconnected.
    ///
    /// Reverses the operations from `indexAddresses`: removes address->tx mappings,
    /// removes output coins, and restores spent input coins.
    /// Called from within already-locked context (_disconnectTo); do not acquire lock.
    func unindexAddresses(block: Block, height: Int, undoCoins: [CoinEntry]) {
        guard let store = addrIndexStore else { return }
        var batch: [(db: UInt8, op: LevelDBStore.BatchOp)] = []
        var undoIdx = undoCoins.count - 1

        // Process transactions in reverse (matching CoinDatabase.disconnectBlock order)
        for i in stride(from: block.transactions.count - 1, through: 0, by: -1) {
            let tx = block.transactions[i]
            let txHash = tx.txHash()

            // Remove output coins
            for (j, output) in tx.outputs.enumerated() {
                let addr = output.address.hash
                guard addr != Address.null.hash else { continue }

                batch.append((addrTxDB, .delete(key: addr + txHash.bytes)))

                let idx = UInt32(j)
                let coinKey = addr + txHash.bytes + [
                    UInt8(idx & 0xFF), UInt8((idx >> 8) & 0xFF),
                    UInt8((idx >> 16) & 0xFF), UInt8((idx >> 24) & 0xFF),
                ]
                batch.append((addrCoinDB, .delete(key: coinKey)))
            }

            // Restore spent input coins (reverse order to match undo stack)
            if i > 0 {
                for inputIdx in stride(from: tx.inputs.count - 1, through: 0, by: -1) {
                    let input = tx.inputs[inputIdx]
                    if input.isCoinbase { continue }
                    guard undoIdx >= 0 else { break }
                    let coin = undoCoins[undoIdx]
                    undoIdx -= 1

                    let addr = coin.output.address.hash
                    guard addr != Address.null.hash else { continue }

                    // Restore the unspent coin
                    let prevIdx = input.prevout.index
                    let coinKey = addr + input.prevout.hash.bytes + [
                        UInt8(prevIdx & 0xFF), UInt8((prevIdx >> 8) & 0xFF),
                        UInt8((prevIdx >> 16) & 0xFF), UInt8((prevIdx >> 24) & 0xFF),
                    ]
                    batch.append((addrCoinDB, .put(key: coinKey, value: [])))
                }
            }
        }

        try? store.writeBatch(batch)
    }

    /// Get all transaction hashes that involve the given address.
    ///
    /// Requires `--index-address`. Returns an empty array if the index is disabled.
    public func getTxHashesByAddress(_ address: Address) -> [Hash256] {
        lock.lock()
        defer { lock.unlock() }
        guard let store = addrIndexStore else { return [] }
        var results: [Hash256] = []
        try? store.forEachEntry(db: addrTxDB, keyPrefix: address.hash) { key, _ in
            if key.count >= 32 {
                results.append(Hash256(unchecked: Array(key[0..<32])))
            }
            return true
        }
        return results
    }

    /// Get all unspent coin outpoints for the given address.
    ///
    /// Requires `--index-address`. Returns an empty array if the index is disabled.
    public func getCoinsByAddress(_ address: Address) -> [(hash: Hash256, index: UInt32)] {
        lock.lock()
        defer { lock.unlock() }
        guard let store = addrIndexStore else { return [] }
        var results: [(hash: Hash256, index: UInt32)] = []
        try? store.forEachEntry(db: addrCoinDB, keyPrefix: address.hash) { key, _ in
            if key.count >= 36 {
                let hash = Hash256(unchecked: Array(key[0..<32]))
                let index = UInt32(key[32])
                    | UInt32(key[33]) << 8
                    | UInt32(key[34]) << 16
                    | UInt32(key[35]) << 24
                results.append((hash: hash, index: index))
            }
            return true
        }
        return results
    }
}
