import Base
import Foundation
import Protocol
import Consensus
import Storage

/// UTXO database backed by LevelDB.
///
/// Manages three logical databases (via key prefixes) within a single LevelDB:
/// - `coins`: active UTXO set (outpoint → CoinEntry)
/// - `undo`: block disconnect data (height → serialized undo coins)
/// - `meta`: chain aggregate state (`"state"` → ChainState)
public final class CoinDatabase: @unchecked Sendable {
    private let lock = NSLock()
    private let store: LevelDBStore
    private let coinsDB: UInt8
    private let undoDB: UInt8
    private let metaDB: UInt8

    /// Current chain state (cached in memory, persisted to meta DB).
    private var state: ChainState

    /// Last committed block height (-1 if no blocks have been processed).
    private var _committedHeight: Int = -1
    public var committedHeight: Int {
        lock.lock()
        defer { lock.unlock() }
        return _committedHeight
    }

    /// The meta-key used to store ChainState.
    private static let stateKey: [UInt8] = Array("state".utf8)

    /// The meta-key used to store committed height.
    private static let heightKey: [UInt8] = Array("height".utf8)

    /// Sentinel key: records the height of a block write in progress.
    /// Set before the flat-file write, cleared atomically with saveView.
    /// If present on startup, a block was written but UTXO was not committed.
    private static let pendingHeightKey: [UInt8] = Array("pending".utf8)

    /// Height of an in-flight block write, if any (nil = no pending write).
    private var _pendingHeight: Int?
    public var pendingHeight: Int? {
        lock.lock()
        defer { lock.unlock() }
        return _pendingHeight
    }

    /// Open or create a coin database at the given path.
    ///
    /// - Parameters:
    ///   - path: Directory path for the LevelDB database.
    ///   - network: The network type (for genesis state).
    public init(path: String, network: NetworkType) throws {
        self.store = try LevelDBStore(path: path)
        self.coinsDB = store.openDatabase(name: "coins")
        self.undoDB = store.openDatabase(name: "undo")
        self.metaDB = store.openDatabase(name: "meta")

        // Load persisted state or start fresh
        if let data = try store.get(db: metaDB, key: Self.stateKey),
           let loaded = try? ChainState.deserialize(from: data) {
            self.state = loaded
        } else {
            self.state = ChainState()
        }

        // Load committed height
        if let data = try store.get(db: metaDB, key: Self.heightKey), data.count >= 4 {
            _committedHeight = Int(UInt32(data[0])
                | UInt32(data[1]) << 8
                | UInt32(data[2]) << 16
                | UInt32(data[3]) << 24)
        }

        // Load pending height sentinel
        if let data = try store.get(db: metaDB, key: Self.pendingHeightKey), data.count >= 4 {
            _pendingHeight = Int(UInt32(data[0])
                | UInt32(data[1]) << 8
                | UInt32(data[2]) << 16
                | UInt32(data[3]) << 24)
        }
    }

    /// Reset the entire coin database (coins, undo data, and state).
    /// After this, committedHeight is -1 and the UTXO set is empty.
    public func reset() throws {
        lock.lock()
        defer { lock.unlock() }
        try store.clearDatabase(db: coinsDB)
        try store.clearDatabase(db: undoDB)
        state = ChainState()
        let batch: [(db: UInt8, op: LevelDBStore.BatchOp)] = [
            (metaDB, .put(key: Self.stateKey, value: state.serialize())),
            (metaDB, .delete(key: Self.heightKey)),
            (metaDB, .delete(key: Self.pendingHeightKey)),
        ]
        try store.writeBatch(batch)
        _committedHeight = -1
        _pendingHeight = nil
    }

    /// Record that a block at `height` is about to be written to the block store.
    /// Must be called before the flat-file write. Cleared atomically by `saveView`.
    public func markPendingHeight(_ height: Int) throws {
        lock.lock()
        defer { lock.unlock() }
        let h = UInt32(height)
        let val: [UInt8] = [
            UInt8(h & 0xFF), UInt8((h >> 8) & 0xFF),
            UInt8((h >> 16) & 0xFF), UInt8((h >> 24) & 0xFF),
        ]
        try store.writeBatch([(metaDB, .put(key: Self.pendingHeightKey, value: val))])
        _pendingHeight = height
    }

    // MARK: - Coin Operations

    /// Look up a coin by outpoint.
    public func getCoin(_ outpoint: Outpoint) -> CoinEntry? {
        lock.lock()
        defer { lock.unlock() }
        let key = outpointKey(outpoint)
        guard let data = try? store.get(db: coinsDB, key: key) else { return nil }
        return try? CoinEntry.deserialize(from: data)
    }

    /// Save a CoinView's changes to the database in a single atomic write.
    ///
    /// This processes the view's map to determine which coins to add/remove,
    /// serializes the undo stack, updates chain state, and commits everything
    /// in one LevelDB write batch.
    ///
    /// - Parameters:
    ///   - view: The coin view with pending changes.
    ///   - height: The block height being connected.
    ///   - hash: The block hash being connected.
    public func saveView(_ view: CoinView, height: Int, hash: Hash256) throws {
        lock.lock()
        defer { lock.unlock() }
        var batch: [(db: UInt8, op: LevelDBStore.BatchOp)] = []

        // Snapshot state for rollback on write failure
        let savedState = state

        // Build set of outpoints that were both created and spent in this block
        var spentInBlock = Set<Outpoint>()
        for (txHash, outputs) in view.map {
            for (index, entry) in outputs {
                if entry.spent && entry.fresh {
                    spentInBlock.insert(Outpoint(hash: txHash, index: index))
                }
            }
        }

        // Process coin map: add new coins, remove spent coins
        for (txHash, outputs) in view.map {
            for (index, entry) in outputs {
                let outpoint = Outpoint(hash: txHash, index: index)
                let key = outpointKey(outpoint)
                if entry.spent {
                    // Skip intra-block spends (created and consumed in same block).
                    // These were never in the DB so nothing to delete, and we
                    // must not decrement state.coin for them.
                    if !entry.fresh {
                        batch.append((coinsDB, .delete(key: key)))
                        state.spend(value: entry.output.value)
                    }
                } else {
                    batch.append((coinsDB, .put(key: key, value: entry.serialize())))
                    state.add(value: entry.output.value)
                }
            }
        }

        // Serialize and store undo data (always write, even if empty,
        // so disconnectBlock can find it for coinbase-only blocks)
        let undoKey = heightKey(height)
        let undoValue = serializeUndo(view.undo)
        batch.append((undoDB, .put(key: undoKey, value: undoValue)))

        // Update chain state
        let txCount = view.map.values.reduce(0) { count, outputs in
            count + (outputs.isEmpty ? 0 : 1)
        }
        state.connect(txCount: txCount)
        state.commit(hash)
        batch.append((metaDB, .put(key: Self.stateKey, value: state.serialize())))

        // Persist committed height
        let h = UInt32(height)
        let heightVal: [UInt8] = [
            UInt8(h & 0xFF), UInt8((h >> 8) & 0xFF),
            UInt8((h >> 16) & 0xFF), UInt8((h >> 24) & 0xFF),
        ]
        batch.append((metaDB, .put(key: Self.heightKey, value: heightVal)))

        // Clear the pending-height sentinel atomically with the UTXO commit.
        batch.append((metaDB, .delete(key: Self.pendingHeightKey)))

        // Atomic write (rollback state on failure)
        do {
            try store.writeBatch(batch)
        } catch {
            state = savedState
            throw error
        }
        _committedHeight = height
        _pendingHeight = nil
    }

    /// Retrieve undo data for a given block height.
    public func getUndo(height: Int) throws -> [CoinEntry]? {
        lock.lock()
        defer { lock.unlock() }
        return try _getUndo(height: height)
    }

    /// Internal unlocked undo retrieval (caller must hold lock).
    private func _getUndo(height: Int) throws -> [CoinEntry]? {
        let key = heightKey(height)
        guard let data = try store.get(db: undoDB, key: key) else { return nil }
        return try deserializeUndo(data)
    }

    /// Reverse a block's UTXO changes using the stored undo data.
    ///
    /// For each transaction (in reverse order):
    /// - Removes outputs created by this block
    /// - Restores inputs that were spent by this block (from undo data)
    ///
    /// The undo stack was built during connect by iterating txs and inputs
    /// in forward order. To reverse it, we iterate txs in reverse and pop
    /// undo entries from the end, processing each tx's inputs in reverse.
    ///
    /// Deletes the undo data for this height, updates chain state and
    /// committed height, all in a single atomic write batch.
    ///
    /// - Parameters:
    ///   - block: The block to disconnect.
    ///   - height: The block height.
    ///   - prevHash: The previous block's hash (new chain tip after disconnect).
    public func disconnectBlock(_ block: Block, height: Int, prevHash: Hash256) throws {
        lock.lock()
        defer { lock.unlock() }
        // Load undo coins for this block
        guard let undoCoins = try _getUndo(height: height) else {
            throw ChainError.validationFailed("missing undo data for height \(height)")
        }

        // Snapshot state for rollback on write failure
        let savedState = state

        // Build set of outpoints that were created and spent within this block.
        // These were never persisted (fresh+spent skip in saveView), so we must
        // not call state.spend for them or issue a DB delete.
        var spentInBlock = Set<Outpoint>()
        let blockTxHashes = Set(block.transactions.map { $0.txHash() })
        for tx in block.transactions {
            for input in tx.inputs {
                if input.isCoinbase { continue }
                if blockTxHashes.contains(input.prevout.hash) {
                    spentInBlock.insert(input.prevout)
                }
            }
        }

        var batch: [(db: UInt8, op: LevelDBStore.BatchOp)] = []
        var undoIdx = undoCoins.count - 1

        // Process transactions in reverse order
        for i in stride(from: block.transactions.count - 1, through: 0, by: -1) {
            let tx = block.transactions[i]
            let txHash = tx.txHash()

            // Remove outputs created by this block's transaction
            for j in 0..<tx.outputs.count {
                let outpoint = Outpoint(hash: txHash, index: UInt32(j))
                // Skip intra-block spends — they were never in the DB
                if spentInBlock.contains(outpoint) { continue }
                let key = outpointKey(outpoint)
                batch.append((coinsDB, .delete(key: key)))
                state.spend(value: tx.outputs[j].value)
            }

            // Restore inputs from undo data (skip coinbase tx — it has no spent inputs)
            if i > 0 {
                // Iterate inputs in reverse to match the undo stack order
                for inputIdx in stride(from: tx.inputs.count - 1, through: 0, by: -1) {
                    let input = tx.inputs[inputIdx]
                    if input.isCoinbase { continue }
                    guard undoIdx >= 0 else {
                        throw ChainError.validationFailed("undo stack underflow at height \(height)")
                    }
                    let coin = undoCoins[undoIdx]
                    undoIdx -= 1
                    // Skip intra-block spends: these coins were created and consumed
                    // within this block (fresh+spent) and were never written to the
                    // persistent DB. We must still consume the undo entry for alignment.
                    if spentInBlock.contains(input.prevout) { continue }
                    let key = outpointKey(input.prevout)
                    batch.append((coinsDB, .put(key: key, value: coin.serialize())))
                    state.add(value: coin.output.value)
                }
            }
        }

        // Delete undo data for this height
        batch.append((undoDB, .delete(key: heightKey(height))))

        // Update chain state
        state.disconnect(txCount: block.transactions.count)
        state.commit(prevHash)
        batch.append((metaDB, .put(key: Self.stateKey, value: state.serialize())))

        // Update committed height to height - 1
        let newHeight = UInt32(max(0, height - 1))
        let heightVal: [UInt8] = [
            UInt8(newHeight & 0xFF), UInt8((newHeight >> 8) & 0xFF),
            UInt8((newHeight >> 16) & 0xFF), UInt8((newHeight >> 24) & 0xFF),
        ]
        batch.append((metaDB, .put(key: Self.heightKey, value: heightVal)))

        do {
            try store.writeBatch(batch)
        } catch {
            state = savedState
            throw error
        }
        _committedHeight = Int(newHeight)
    }

    /// Get the current chain state.
    public func getState() -> ChainState {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    /// The current UTXO count from chain state.
    public var coinCount: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return state.coin
    }

    /// Close the LevelDB database.
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        store.close()
    }

    // MARK: - Key Encoding

    /// Encode an outpoint as a 36-byte key: [txHash: 32] [index: 4 LE].
    private func outpointKey(_ outpoint: Outpoint) -> [UInt8] {
        var key = [UInt8]()
        key.reserveCapacity(36)
        key.append(contentsOf: outpoint.hash.bytes)
        key.append(UInt8(outpoint.index & 0xFF))
        key.append(UInt8((outpoint.index >> 8) & 0xFF))
        key.append(UInt8((outpoint.index >> 16) & 0xFF))
        key.append(UInt8((outpoint.index >> 24) & 0xFF))
        return key
    }

    /// Encode a height as a 4-byte little-endian key.
    private func heightKey(_ height: Int) -> [UInt8] {
        let h = UInt32(height)
        return [
            UInt8(h & 0xFF),
            UInt8((h >> 8) & 0xFF),
            UInt8((h >> 16) & 0xFF),
            UInt8((h >> 24) & 0xFF),
        ]
    }

    // MARK: - Undo Serialization

    /// Serialize an array of undo CoinEntries.
    ///
    /// Format: [count: 4 LE] [entry0] [entry1] ...
    private func serializeUndo(_ entries: [CoinEntry]) -> [UInt8] {
        var out = [UInt8]()
        let count = UInt32(entries.count)
        out.append(UInt8(count & 0xFF))
        out.append(UInt8((count >> 8) & 0xFF))
        out.append(UInt8((count >> 16) & 0xFF))
        out.append(UInt8((count >> 24) & 0xFF))
        for entry in entries {
            let data = entry.serialize()
            // Length-prefix each entry for safe deserialization
            let len = UInt32(data.count)
            out.append(UInt8(len & 0xFF))
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8((len >> 16) & 0xFF))
            out.append(UInt8((len >> 24) & 0xFF))
            out.append(contentsOf: data)
        }
        return out
    }

    /// Deserialize an array of undo CoinEntries.
    private func deserializeUndo(_ data: [UInt8]) throws -> [CoinEntry] {
        guard data.count >= 4 else {
            throw ChainError.validationFailed("undo data too short")
        }

        let count = Int(
            UInt32(data[0])
            | UInt32(data[1]) << 8
            | UInt32(data[2]) << 16
            | UInt32(data[3]) << 24
        )

        var entries: [CoinEntry] = []
        entries.reserveCapacity(count)
        var pos = 4

        for _ in 0..<count {
            guard pos + 4 <= data.count else {
                throw ChainError.validationFailed("undo entry length truncated")
            }
            let len = Int(
                UInt32(data[pos])
                | UInt32(data[pos + 1]) << 8
                | UInt32(data[pos + 2]) << 16
                | UInt32(data[pos + 3]) << 24
            )
            pos += 4

            guard pos + len <= data.count else {
                throw ChainError.validationFailed("undo entry data truncated")
            }
            let entryData = Array(data[pos..<(pos + len)])
            let entry = try CoinEntry.deserialize(from: entryData)
            entries.append(entry)
            pos += len
        }

        return entries
    }
}
