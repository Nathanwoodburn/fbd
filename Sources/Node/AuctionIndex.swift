import Foundation
import Base
import Chain
import Covenants
import Protocol
import Storage

// MARK: - Data Structures

/// Auction lifecycle state.
public enum AuctionState: String, Sendable {
    case opening
    case bidding
    case reveal
    case closed

    /// Single-byte encoding for LevelDB storage.
    var tag: UInt8 {
        switch self {
        case .opening: return 0
        case .bidding: return 1
        case .reveal:  return 2
        case .closed:  return 3
        }
    }

    static func fromTag(_ tag: UInt8) -> AuctionState? {
        switch tag {
        case 0: return .opening
        case 1: return .bidding
        case 2: return .reveal
        case 3: return .closed
        default: return nil
        }
    }
}

/// A tracked name auction.
public struct AuctionEntry: Sendable {
    public let name: String
    public let nameHash: String
    public let openHeight: Int
    public var openEnd: Int
    public var biddingEnd: Int
    public var revealEnd: Int
    public var bidCount: Int
    public var highestRevealed: UInt64
    public var highestLockup: UInt64
    public var state: AuctionState

    func serialize() -> [UInt8] {
        var w = BufferWriter(capacity: 128)
        let nameBytes = Array(name.utf8)
        w.writeCompactSize(UInt64(nameBytes.count))
        w.writeBytes(nameBytes)
        let nhBytes = Array(nameHash.utf8)
        w.writeCompactSize(UInt64(nhBytes.count))
        w.writeBytes(nhBytes)
        w.writeUInt32LE(UInt32(openHeight))
        w.writeUInt32LE(UInt32(openEnd))
        w.writeUInt32LE(UInt32(biddingEnd))
        w.writeUInt32LE(UInt32(revealEnd))
        w.writeUInt32LE(UInt32(bidCount))
        w.writeUInt64LE(highestRevealed)
        w.writeUInt64LE(highestLockup)
        w.writeUInt8(state.tag)
        return w.data
    }

    static func deserialize(from data: [UInt8]) throws -> AuctionEntry {
        var r = BufferReader(data)
        let nameLen = try r.readCompactSize()
        let nameBytes = try r.readBytes(Int(nameLen))
        let name = String(bytes: nameBytes, encoding: .utf8) ?? ""
        let nhLen = try r.readCompactSize()
        let nhBytes = try r.readBytes(Int(nhLen))
        let nameHash = String(bytes: nhBytes, encoding: .utf8) ?? ""
        let openHeight = Int(try r.readUInt32LE())
        let openEnd = Int(try r.readUInt32LE())
        let biddingEnd = Int(try r.readUInt32LE())
        let revealEnd = Int(try r.readUInt32LE())
        let bidCount = Int(try r.readUInt32LE())
        let highestRevealed = try r.readUInt64LE()
        let highestLockup = (try? r.readUInt64LE()) ?? 0
        let stateTag = try r.readUInt8()
        guard let state = AuctionState.fromTag(stateTag) else {
            throw BaseError.bufferUnderflow
        }
        return AuctionEntry(
            name: name, nameHash: nameHash, openHeight: openHeight,
            openEnd: openEnd, biddingEnd: biddingEnd, revealEnd: revealEnd,
            bidCount: bidCount, highestRevealed: highestRevealed,
            highestLockup: highestLockup, state: state
        )
    }
}

/// A bid observed on the network.
public struct AuctionBid: Sendable {
    public let nameHash: String
    public let txHash: String
    public let outputIndex: Int
    public let height: Int
    public let lockup: UInt64
    public let blindHash: String
    public let address: String
    // Set when the corresponding REVEAL is seen.
    public var revealedValue: UInt64?
    public var revealTxHash: String?
    public var revealHeight: Int?

    /// LevelDB key: nameHash (64 UTF-8) + txHash (64 UTF-8) + outputIndex (4 LE).
    var storageKey: [UInt8] {
        var key = Array(nameHash.utf8)
        key.append(contentsOf: txHash.utf8)
        key.append(UInt8(outputIndex & 0xFF))
        key.append(UInt8((outputIndex >> 8) & 0xFF))
        key.append(UInt8((outputIndex >> 16) & 0xFF))
        key.append(UInt8((outputIndex >> 24) & 0xFF))
        return key
    }

    func serialize() -> [UInt8] {
        var w = BufferWriter(capacity: 256)
        let nhBytes = Array(nameHash.utf8)
        w.writeCompactSize(UInt64(nhBytes.count))
        w.writeBytes(nhBytes)
        let txBytes = Array(txHash.utf8)
        w.writeCompactSize(UInt64(txBytes.count))
        w.writeBytes(txBytes)
        w.writeUInt32LE(UInt32(outputIndex))
        w.writeUInt32LE(UInt32(height))
        w.writeUInt64LE(lockup)
        let blindBytes = Array(blindHash.utf8)
        w.writeCompactSize(UInt64(blindBytes.count))
        w.writeBytes(blindBytes)
        let addrBytes = Array(address.utf8)
        w.writeCompactSize(UInt64(addrBytes.count))
        w.writeBytes(addrBytes)
        // Optional reveal fields: 1-byte flags + data.
        var flags: UInt8 = 0
        if revealedValue != nil { flags |= 1 }
        if revealTxHash != nil { flags |= 2 }
        if revealHeight != nil { flags |= 4 }
        w.writeUInt8(flags)
        if let v = revealedValue { w.writeUInt64LE(v) }
        if let h = revealTxHash {
            let hb = Array(h.utf8)
            w.writeCompactSize(UInt64(hb.count))
            w.writeBytes(hb)
        }
        if let rh = revealHeight { w.writeUInt32LE(UInt32(rh)) }
        return w.data
    }

    static func deserialize(from data: [UInt8]) throws -> AuctionBid {
        var r = BufferReader(data)
        let nhLen = try r.readCompactSize()
        let nhBytes = try r.readBytes(Int(nhLen))
        let nameHash = String(bytes: nhBytes, encoding: .utf8) ?? ""
        let txLen = try r.readCompactSize()
        let txBytes = try r.readBytes(Int(txLen))
        let txHash = String(bytes: txBytes, encoding: .utf8) ?? ""
        let outputIndex = Int(try r.readUInt32LE())
        let height = Int(try r.readUInt32LE())
        let lockup = try r.readUInt64LE()
        let blindLen = try r.readCompactSize()
        let blindBytes = try r.readBytes(Int(blindLen))
        let blindHash = String(bytes: blindBytes, encoding: .utf8) ?? ""
        let addrLen = try r.readCompactSize()
        let addrBytes = try r.readBytes(Int(addrLen))
        let address = String(bytes: addrBytes, encoding: .utf8) ?? ""
        let flags = try r.readUInt8()
        let revealedValue: UInt64? = (flags & 1 != 0) ? try r.readUInt64LE() : nil
        var revealTxHash: String?
        if flags & 2 != 0 {
            let rtLen = try r.readCompactSize()
            let rtBytes = try r.readBytes(Int(rtLen))
            revealTxHash = String(bytes: rtBytes, encoding: .utf8)
        }
        let revealHeight: Int? = (flags & 4 != 0) ? Int(try r.readUInt32LE()) : nil
        return AuctionBid(
            nameHash: nameHash, txHash: txHash, outputIndex: outputIndex,
            height: height, lockup: lockup, blindHash: blindHash, address: address,
            revealedValue: revealedValue, revealTxHash: revealTxHash, revealHeight: revealHeight
        )
    }
}

// MARK: - AuctionIndex

/// Index of name auctions and their bids.
///
/// **Default mode** (no flag): in-memory only, scans last 5000 blocks on startup,
/// prunes closed auctions periodically.
///
/// **`--index-auctions` mode**: backed by a LevelDB database for persistence.
/// All auctions and bids are stored on disk and loaded into memory at startup.
/// No pruning — full history is kept.
///
/// Thread-safe via NSLock.
public final class AuctionIndex: @unchecked Sendable {

    private let lock = NSLock()

    /// Auctions keyed by nameHash hex.
    private var auctions: [String: AuctionEntry] = [:]

    /// Bids keyed by nameHash hex.
    private var bids: [String: [AuctionBid]] = [:]

    /// Secondary index: state → set of nameHash hex strings.
    private var byState: [AuctionState: Set<String>] = [
        .opening: [],
        .bidding: [],
        .reveal: [],
        .closed: [],
    ]

    /// Tracks which nameHashes were affected at each block height (for reorg undo).
    private var blockIndex: [Int: Set<String>] = [:]

    /// Network name parameters (auction timing).
    private let nameParams: NameParams

    /// Network type (for address encoding).
    private let network: NetworkType

    // MARK: - Storage (nil = in-memory only)

    private let store: LevelDBStore?
    private let auctionsDB: UInt8
    private let bidsDB: UInt8
    private let metaDB: UInt8

    private static let tipKey: [UInt8] = Array("tip".utf8)

    /// Last height at which closed-auction pruning ran (in-memory mode only).
    private var lastPruneHeight: Int = 0

    /// Whether this index is backed by persistent storage.
    public var isPersistent: Bool { store != nil }

    /// Create an auction index.
    ///
    /// - Parameters:
    ///   - network: The network type (for address encoding and auction timing).
    ///   - storePath: If non-nil, open a LevelDB at this path for persistence.
    public init(network: NetworkType, storePath: String? = nil) throws {
        self.nameParams = NameParams.params(for: network)
        self.network = network

        if let path = storePath {
            let s = try LevelDBStore(path: path, cacheSize: 8 * 1024 * 1024)
            self.store = s
            self.auctionsDB = s.openDatabase(name: "auctions")
            self.bidsDB = s.openDatabase(name: "bids")
            self.metaDB = s.openDatabase(name: "meta")
        } else {
            self.store = nil
            self.auctionsDB = 0
            self.bidsDB = 0
            self.metaDB = 0
        }
    }

    /// Close the underlying LevelDB store (if any).
    public func close() {
        store?.close()
    }

    // MARK: - Block Processing

    /// Index a connected block — scan transactions for OPEN/BID/REVEAL covenants.
    public func indexBlock(_ block: Block, height: Int) {
        lock.lock()
        defer { lock.unlock() }

        var affected = Set<String>()
        var batch: [(db: UInt8, op: LevelDBStore.BatchOp)] = []

        for tx in block.transactions {
            let txHash = tx.txHash().hex

            for (outputIdx, output) in tx.outputs.enumerated() {
                let cov = output.covenant
                switch cov.type {

                case .open:
                    guard let entry = makeAuctionEntry(cov: cov, height: height) else { continue }
                    let nh = entry.nameHash
                    if let existing = auctions[nh] {
                        // Name re-opened (expired and auctioned again) — replace the old entry
                        removeFromState(nh, state: existing.state)
                        auctions[nh] = entry
                        addToState(nh, state: entry.state)
                        // Clear old bids from previous auction
                        bids.removeValue(forKey: nh)
                        affected.insert(nh)
                    } else {
                        auctions[nh] = entry
                        addToState(nh, state: entry.state)
                        affected.insert(nh)
                    }

                case .bid:
                    guard let bid = makeBid(cov: cov, output: output, txHash: txHash, outputIndex: outputIdx, height: height) else { continue }
                    let nh = bid.nameHash
                    if store != nil {
                        batch.append((bidsDB, .put(key: bid.storageKey, value: bid.serialize())))
                    }
                    bids[nh, default: []].append(bid)
                    // If we see a BID for a name we haven't tracked (OPEN was before our scan window),
                    // create the auction entry from the BID's covenant data.
                    if auctions[nh] == nil {
                        if let entry = makeAuctionEntryFromBid(cov: cov, height: height) {
                            auctions[nh] = entry
                            addToState(nh, state: entry.state)
                        }
                    }
                    if var a = auctions[nh] {
                        a.bidCount += 1
                        if bid.lockup > a.highestLockup {
                            a.highestLockup = bid.lockup
                        }
                        auctions[nh] = a
                    }
                    affected.insert(nh)

                case .reveal:
                    guard let nh = nameHashHex(from: cov) else { continue }
                    // Match REVEAL to original BID via input prevout.
                    // The input at the same index as this output spent the BID output.
                    if outputIdx < tx.inputs.count {
                        let prevout = tx.inputs[outputIdx].prevout
                        let prevTxHash = prevout.hash.hex
                        let prevIndex = Int(prevout.index)
                        if var bidList = bids[nh] {
                            for i in bidList.indices {
                                if bidList[i].txHash == prevTxHash && bidList[i].outputIndex == prevIndex {
                                    bidList[i].revealedValue = output.value
                                    bidList[i].revealTxHash = txHash
                                    bidList[i].revealHeight = height
                                    if store != nil {
                                        batch.append((bidsDB, .put(key: bidList[i].storageKey, value: bidList[i].serialize())))
                                    }
                                    break
                                }
                            }
                            bids[nh] = bidList
                        }
                        // Update highest revealed value on the auction.
                        if var a = auctions[nh] {
                            if output.value > a.highestRevealed {
                                a.highestRevealed = output.value
                                auctions[nh] = a
                            }
                        }
                    }
                    affected.insert(nh)

                default:
                    break
                }
            }
        }

        if !affected.isEmpty {
            blockIndex[height] = (blockIndex[height] ?? []).union(affected)
        }

        // Transition auction states based on the new height.
        transitionStates(currentHeight: height)

        // Persist affected auctions to LevelDB.
        if let store = store {
            for nh in affected {
                if let entry = auctions[nh] {
                    let key = Array(nh.utf8)
                    batch.append((auctionsDB, .put(key: key, value: entry.serialize())))
                }
            }
            // Store tip height.
            var tipVal = [UInt8](repeating: 0, count: 4)
            tipVal[0] = UInt8(height & 0xFF)
            tipVal[1] = UInt8((height >> 8) & 0xFF)
            tipVal[2] = UInt8((height >> 16) & 0xFF)
            tipVal[3] = UInt8((height >> 24) & 0xFF)
            batch.append((metaDB, .put(key: Self.tipKey, value: tipVal)))
            try? store.writeBatch(batch)
        }

        // Prune closed auctions every 720 blocks (in-memory mode only).
        if store == nil && height - lastPruneHeight >= 720 {
            pruneClosedAuctions(currentHeight: height)
            lastPruneHeight = height
        }
    }

    /// Reverse a disconnected block — remove entries/bids added at that height.
    ///
    /// Scans the block for OPEN/BID/REVEAL covenants to determine which names
    /// were affected, rather than relying on the in-memory `blockIndex` (which
    /// isn't populated for blocks loaded from LevelDB on startup).
    public func unindexBlock(_ block: Block, height: Int) {
        lock.lock()
        defer { lock.unlock() }

        // Determine affected names by scanning the block itself.
        var affected = Set<String>()
        for tx in block.transactions {
            for output in tx.outputs {
                switch output.covenant.type {
                case .open, .bid, .reveal:
                    if let nh = nameHashHex(from: output.covenant) {
                        affected.insert(nh)
                    }
                default:
                    break
                }
            }
        }

        // Also include anything tracked in blockIndex for this height.
        if let indexed = blockIndex.removeValue(forKey: height) {
            affected.formUnion(indexed)
        }

        guard !affected.isEmpty else { return }

        var batch: [(db: UInt8, op: LevelDBStore.BatchOp)] = []

        for nh in affected {
            // Remove bids added at this height.
            if var bidList = bids[nh] {
                let removed = bidList.filter { $0.height == height }
                bidList.removeAll { $0.height == height }
                if store != nil {
                    for bid in removed {
                        batch.append((bidsDB, .delete(key: bid.storageKey)))
                    }
                }
                // Also undo reveals that happened at this height.
                for i in bidList.indices {
                    if bidList[i].revealHeight == height {
                        bidList[i].revealedValue = nil
                        bidList[i].revealTxHash = nil
                        bidList[i].revealHeight = nil
                        if store != nil {
                            batch.append((bidsDB, .put(key: bidList[i].storageKey, value: bidList[i].serialize())))
                        }
                    }
                }
                if bidList.isEmpty {
                    bids.removeValue(forKey: nh)
                } else {
                    bids[nh] = bidList
                }
            }

            // If the auction was opened at this height, remove it entirely.
            if let a = auctions[nh], a.openHeight == height {
                removeFromState(nh, state: a.state)
                auctions.removeValue(forKey: nh)
                if store != nil {
                    batch.append((auctionsDB, .delete(key: Array(nh.utf8))))
                }
            } else if var a = auctions[nh] {
                // Recompute bidCount, highestRevealed, and highestLockup from remaining bids.
                let remaining = bids[nh] ?? []
                a.bidCount = remaining.count
                a.highestRevealed = remaining.compactMap(\.revealedValue).max() ?? 0
                a.highestLockup = remaining.map(\.lockup).max() ?? 0
                auctions[nh] = a
                if store != nil {
                    batch.append((auctionsDB, .put(key: Array(nh.utf8), value: a.serialize())))
                }
            }
        }

        // Re-transition states at the new tip height (height - 1).
        transitionStates(currentHeight: height - 1)

        // Persist changes.
        if let store = store {
            let newTip = height - 1
            var tipVal = [UInt8](repeating: 0, count: 4)
            tipVal[0] = UInt8(newTip & 0xFF)
            tipVal[1] = UInt8((newTip >> 8) & 0xFF)
            tipVal[2] = UInt8((newTip >> 16) & 0xFF)
            tipVal[3] = UInt8((newTip >> 24) & 0xFF)
            batch.append((metaDB, .put(key: Self.tipKey, value: tipVal)))
            try? store.writeBatch(batch)
        }
    }

    // MARK: - Startup

    /// Populate the index on startup.
    ///
    /// **Persistent mode**: loads all data from LevelDB, then catches up from
    /// the stored tip to the current chain height.
    ///
    /// **In-memory mode**: scans the last 5000 blocks.
    public func populate(chain: Chain) throws {
        let currentHeight = chain.storedHeight
        guard currentHeight >= 0 else { return }

        if let store = store {
            // Load existing data from LevelDB.
            let loaded = try loadFromStore(store: store, currentHeight: currentHeight)

            // Catch up from stored tip to chain tip.
            if loaded < currentHeight {
                let startHeight = loaded + 1
                for h in startHeight...currentHeight {
                    guard let block = try chain.getBlock(height: h) else { continue }
                    indexBlock(block, height: h)
                }
            }
        } else {
            // In-memory: scan last 5000 blocks.
            let startHeight = max(0, currentHeight - 5000)
            for h in startHeight...currentHeight {
                guard let block = try chain.getBlock(height: h) else { continue }
                indexBlock(block, height: h)
            }
        }
    }

    /// Load all auctions and bids from LevelDB into the in-memory maps.
    /// Returns the stored tip height (-1 if no data).
    private func loadFromStore(store: LevelDBStore, currentHeight: Int) throws -> Int {
        lock.lock()
        defer { lock.unlock() }

        // Load auctions.
        try store.forEachEntry(db: auctionsDB) { _, value in
            if let entry = try? AuctionEntry.deserialize(from: value) {
                auctions[entry.nameHash] = entry
                let state = computeState(entry: entry, currentHeight: currentHeight)
                addToState(entry.nameHash, state: state)
                if state != entry.state {
                    var e = entry
                    e.state = state
                    auctions[e.nameHash] = e
                }
            }
        }

        // Load bids.
        try store.forEachEntry(db: bidsDB) { _, value in
            if let bid = try? AuctionBid.deserialize(from: value) {
                bids[bid.nameHash, default: []].append(bid)
            }
        }

        // Read stored tip height.
        if let tipData = try store.get(db: metaDB, key: Self.tipKey), tipData.count >= 4 {
            let h = Int(tipData[0])
                | (Int(tipData[1]) << 8)
                | (Int(tipData[2]) << 16)
                | (Int(tipData[3]) << 24)
            return h
        }
        return -1
    }

    // MARK: - Queries

    /// List auctions with optional state filter and pagination.
    public func getAuctions(state: AuctionState? = nil, count: Int = 100, offset: Int = 0) -> [AuctionEntry] {
        lock.lock()
        defer { lock.unlock() }

        let entries: [AuctionEntry]
        if let state = state {
            let hashes = byState[state] ?? []
            entries = hashes.compactMap { auctions[$0] }
        } else {
            entries = Array(auctions.values)
        }

        let sorted = entries.sorted { $0.openHeight > $1.openHeight }
        let start = min(offset, sorted.count)
        let end = min(start + count, sorted.count)
        return Array(sorted[start..<end])
    }

    /// List all bids for a given name (by nameHash hex).
    public func getBids(nameHash: String) -> [AuctionBid] {
        lock.lock()
        defer { lock.unlock() }
        return bids[nameHash] ?? []
    }

    /// Total number of tracked auctions.
    public var auctionCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return auctions.count
    }

    /// Look up a single auction by nameHash hex.
    public func getAuction(nameHash: String) -> AuctionEntry? {
        lock.lock()
        defer { lock.unlock() }
        return auctions[nameHash]
    }

    // MARK: - Internal Helpers

    /// Transition auction states based on the current block height.
    private func transitionStates(currentHeight: Int) {
        for (nh, var entry) in auctions {
            let newState = computeState(entry: entry, currentHeight: currentHeight)
            if newState != entry.state {
                removeFromState(nh, state: entry.state)
                entry.state = newState
                auctions[nh] = entry
                addToState(nh, state: newState)
            }
        }
    }

    /// Compute the correct state for an auction at the given height.
    private func computeState(entry: AuctionEntry, currentHeight: Int) -> AuctionState {
        if currentHeight < entry.openEnd {
            return .opening
        } else if currentHeight < entry.biddingEnd {
            return .bidding
        } else if currentHeight < entry.revealEnd {
            return .reveal
        } else {
            return .closed
        }
    }

    /// Remove closed auctions past their revealEnd (in-memory mode only).
    private func pruneClosedAuctions(currentHeight: Int) {
        let closed = byState[.closed] ?? []
        for nh in closed {
            auctions.removeValue(forKey: nh)
            bids.removeValue(forKey: nh)
            byState[.closed]?.remove(nh)
        }
        // Also clean up old blockIndex entries.
        let cutoff = currentHeight - 5000
        blockIndex = blockIndex.filter { $0.key > cutoff }
    }

    private func addToState(_ nameHash: String, state: AuctionState) {
        byState[state, default: []].insert(nameHash)
    }

    private func removeFromState(_ nameHash: String, state: AuctionState) {
        byState[state]?.remove(nameHash)
    }

    /// Extract nameHash hex from a covenant, returning nil on malformed data.
    private func nameHashHex(from cov: Covenant) -> String? {
        guard let nh = try? CovenantData.nameHash(from: cov) else { return nil }
        return nh.hex
    }

    /// Build an AuctionEntry from an OPEN covenant.
    private func makeAuctionEntry(cov: Covenant, height: Int) -> AuctionEntry? {
        guard let nhObj = try? CovenantData.nameHash(from: cov) else { return nil }
        let nh = nhObj.hex
        let nameBytes = (try? CovenantData.rawName(from: cov)) ?? []
        let name = String(bytes: nameBytes, encoding: .utf8) ?? ""

        let openEnd = height + nameParams.openPeriod
        let biddingEnd = openEnd + nameParams.biddingPeriod
        let revealEnd = biddingEnd + nameParams.revealPeriod

        return AuctionEntry(
            name: name,
            nameHash: nh,
            openHeight: height,
            openEnd: openEnd,
            biddingEnd: biddingEnd,
            revealEnd: revealEnd,
            bidCount: 0,
            highestRevealed: 0,
            highestLockup: 0,
            state: .opening
        )
    }

    /// Build an AuctionEntry from a BID covenant (for late-discovered auctions).
    private func makeAuctionEntryFromBid(cov: Covenant, height: Int) -> AuctionEntry? {
        guard let nhObj = try? CovenantData.nameHash(from: cov) else { return nil }
        let nh = nhObj.hex
        let nameBytes = (try? CovenantData.rawName(from: cov)) ?? []
        let name = String(bytes: nameBytes, encoding: .utf8) ?? ""

        // BID covenant item[1] contains the auction start height.
        guard let startHeight = try? CovenantData.height(from: cov) else { return nil }

        let openEnd = startHeight + nameParams.openPeriod
        let biddingEnd = openEnd + nameParams.biddingPeriod
        let revealEnd = biddingEnd + nameParams.revealPeriod

        let state = computeState(
            entry: AuctionEntry(name: name, nameHash: nh, openHeight: startHeight,
                                openEnd: openEnd, biddingEnd: biddingEnd, revealEnd: revealEnd,
                                bidCount: 0, highestRevealed: 0, highestLockup: 0, state: .opening),
            currentHeight: height
        )

        return AuctionEntry(
            name: name,
            nameHash: nh,
            openHeight: startHeight,
            openEnd: openEnd,
            biddingEnd: biddingEnd,
            revealEnd: revealEnd,
            bidCount: 0,
            highestRevealed: 0,
            highestLockup: 0,
            state: state
        )
    }

    /// Build an AuctionBid from a BID covenant output.
    private func makeBid(cov: Covenant, output: Output, txHash: String, outputIndex: Int, height: Int) -> AuctionBid? {
        guard let nhObj = try? CovenantData.nameHash(from: cov) else { return nil }
        let nh = nhObj.hex
        let blindBytes = (try? CovenantData.blindHash(from: cov)) ?? []
        let blind = HexEncoding.encode(blindBytes)
        let addr = output.address.toBech32(network: network)

        return AuctionBid(
            nameHash: nh,
            txHash: txHash,
            outputIndex: outputIndex,
            height: height,
            lockup: output.value,
            blindHash: blind,
            address: addr
        )
    }
}
