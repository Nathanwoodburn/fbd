import Base
import Urkel
import Covenants
import Foundation
import Storage

/// Wraps an in-memory Urkel tree with a pending name state map.
///
/// Name states are keyed by their 32-byte SHA3-256 name hash. Changes
/// accumulate in the pending map and are flushed to the tree every
/// `treeInterval` blocks.
///
/// When initialized with a path, persists committed state to LevelDB using
/// node-level persistence: only dirty tree nodes are written on each commit,
/// then collapsed to lightweight hash references. This makes commits O(dirty)
/// instead of O(total tree size).
///
/// An application-level node cache (analogous to Bitcoin Core's CCoinsViewCache)
/// sits in front of LevelDB to avoid repeated reads for hot internal tree nodes.
public final class NameDB {
    private var tree: UrkelTree
    private var pending: [Hash256: NameState]

    /// Cached tree root hash — invalidated when the tree is modified (commit/insert).
    private var cachedRootHash: [UInt8]?

    /// Optional LevelDB backing store for persistence.
    private var store: LevelDBStore?
    private var metaDB: UInt8 = 0
    private var nodesDB: UInt8 = 0
    private var snapshotsDB: UInt8 = 0

    /// Application-level write-through node cache (nodeId → serialized node data).
    ///
    /// Like Bitcoin Core's CCoinsViewCache, this absorbs resolver reads so most
    /// lookups never hit LevelDB. After commitDirtyNodes(), newly written nodes
    /// are added to this cache. Resolved nodes during tree traversal are also
    /// cached. This is critical because after each commit, the modified tree path
    /// (root → leaf) is collapsed to hash references, and the next commit must
    /// re-resolve them. LevelDB doesn't mmap, so we need an explicit
    /// application-level cache.
    private var nodeCache: [UInt64: [UInt8]] = [:]

    /// Maximum node cache entries before trimming. Each entry is ~100-200 bytes
    /// of serialized data + 8 bytes key, so 500k entries ≈ 50-100MB.
    private static let maxNodeCacheEntries = 500_000

    /// Active snapshot for batching resolver reads during commit.
    private var activeSnapshot: LevelDBStore.Snapshot?

    /// Last persisted commit height (-1 if no persistence or empty).
    public private(set) var committedHeight: Int = -1

    /// Next node ID to assign (0 reserved for null sentinel).
    private var nextNodeId: UInt64 = 1

    /// Persistence ID of the current tree root node (0 = empty tree).
    private var rootNodeId: UInt64 = 0

    /// In-memory only init (no persistence).
    public init() {
        self.tree = UrkelTree()
        self.pending = [:]
    }

    /// Persistent init — opens LevelDB at `path` and loads existing state.
    public init(path: String) throws {
        self.tree = UrkelTree()
        self.pending = [:]

        // Tree nodes are read-heavy (resolver traversals) — use a large block cache.
        let store = try LevelDBStore(path: path, cacheSize: 256 * 1024 * 1024) // 256 MB
        self.store = store
        self.metaDB = store.openDatabase(name: "meta")
        self.nodesDB = store.openDatabase(name: "nodes")
        self.snapshotsDB = store.openDatabase(name: "snapshots")

        // Load committed height from meta
        let heightKey: [UInt8] = Array("height".utf8)
        if let heightData = try store.get(db: metaDB, key: heightKey), heightData.count >= 4 {
            committedHeight = Int(UInt32(heightData[0])
                | UInt32(heightData[1]) << 8
                | UInt32(heightData[2]) << 16
                | UInt32(heightData[3]) << 24)
        }

        // Load node-level persistence state
        let rootIdKey: [UInt8] = Array("rootNodeId".utf8)
        let nextIdKey: [UInt8] = Array("nextNodeId".utf8)

        if let rootIdData = try store.get(db: metaDB, key: rootIdKey),
           rootIdData.count >= 8,
           let nextIdData = try store.get(db: metaDB, key: nextIdKey),
           nextIdData.count >= 8 {
            var rootReader = BufferReader(rootIdData)
            rootNodeId = try rootReader.readUInt64LE()
            var nextReader = BufferReader(nextIdData)
            nextNodeId = try nextReader.readUInt64LE()

            if rootNodeId != 0 {
                // Load root node data to get its hash, then create a hash ref
                let rootKey = nodeIdKey(rootNodeId)
                guard let rootData = try store.get(db: nodesDB, key: rootKey) else {
                    throw UrkelError.corruptedData
                }
                nodeCache[rootNodeId] = rootData
                let rootRef = try UrkelTree.deserializeNode(rootData, nodeId: rootNodeId)
                let rootHash = try rootRef.hash()
                tree.setRoot(UrkelNodeRef(hashRef: rootHash, nodeId: rootNodeId))
                cachedRootHash = rootHash
            }
        }

        // Install resolver for lazy node loading
        installResolver(store: store)
    }

    /// Install the resolver closure on the tree for lazy node loading.
    private func installResolver(store: LevelDBStore) {
        tree.resolver = { [weak self] nodeId in
            guard let self = self, let store = self.store else {
                throw UrkelError.unresolvedNode
            }

            // Check application-level cache first (like Bitcoin Core's CCoinsViewCache)
            if let cached = self.nodeCache[nodeId] {
                return try UrkelTree.deserializeNode(cached, nodeId: nodeId)
            }

            // Cache miss — read from LevelDB
            let key = self.nodeIdKey(nodeId)
            let data: [UInt8]?
            if let snapshot = self.activeSnapshot {
                data = try store.get(snapshot: snapshot, db: self.nodesDB, key: key)
            } else {
                data = try store.get(db: self.nodesDB, key: key)
            }
            guard let data = data else {
                throw UrkelError.corruptedData
            }

            // Cache for future reads
            self.nodeCache[nodeId] = data

            return try UrkelTree.deserializeNode(data, nodeId: nodeId)
        }
    }

    /// Current tree root hash (reflects only committed state).
    ///
    /// Cached between tree modifications — the tree only changes during `commit()`.
    public func treeRoot() throws -> [UInt8] {
        if let cached = cachedRootHash { return cached }
        let root = try tree.rootHash()
        cachedRootHash = root
        return root
    }

    /// Get a name state by its 32-byte name hash.
    ///
    /// Checks the pending map first (for intra-block and uncommitted changes),
    /// then falls back to the tree.
    public func getNameState(_ nameHash: NameHash) throws -> NameState? {
        let key = Hash256(unchecked: nameHash.bytes)
        if let ns = pending[key] {
            return ns
        }
        guard let data = try tree.get(nameHash.bytes) else {
            return nil
        }
        return try NameState.deserialize(from: data)
    }

    /// Store a name state in the pending map.
    public func putNameState(_ nameHash: NameHash, _ ns: NameState) {
        let key = Hash256(unchecked: nameHash.bytes)
        pending[key] = ns
    }

    /// The number of entries in the pending map.
    public var pendingCount: Int { pending.count }

    /// Opaque snapshot of the pending map for rollback on failure.
    public typealias PendingSnapshot = [Hash256: NameState]

    /// Take a snapshot of the pending map (COW — cheap until modified).
    public func snapshotPending() -> PendingSnapshot { pending }

    /// Restore the pending map from a previous snapshot,
    /// discarding any changes made since the snapshot was taken.
    public func restorePending(_ snapshot: PendingSnapshot) { pending = snapshot }

    /// Clear the pending map (for testing restart simulation).
    public func clearPendingForTest() { pending.removeAll() }

    /// Flush pending name states into the Urkel tree and persist to LevelDB.
    ///
    /// Called every `treeInterval` blocks. Only dirty tree nodes are written,
    /// making this O(dirty) instead of O(total tree size).
    public func commit(height: Int) throws {
        // Insert pending into tree (invalidates root hash cache).
        // Use a snapshot for all resolver lookups to get a consistent view
        // without per-read overhead.
        cachedRootHash = nil
        if let store = store {
            activeSnapshot = store.beginReadTransaction()
        }
        do {
            for (key, ns) in pending {
                let serialized = ns.serialize()
                try tree.insert(key.bytes, serialized)
            }
        } catch {
            if let snapshot = activeSnapshot { store?.endReadTransaction(snapshot) }
            activeSnapshot = nil
            throw error
        }
        if let snapshot = activeSnapshot { store?.endReadTransaction(snapshot) }
        activeSnapshot = nil
        let pendingCount = pending.count

        // Persist to LevelDB if configured
        if let store = store {
            // Commit dirty nodes — only writes nodes that changed
            // Estimate ~10 dirty nodes per insertion (tree depth + siblings)
            let result = try tree.commitDirtyNodes(nextNodeId: nextNodeId, estimatedDirtyCount: pendingCount * 10)

            var ops: [(db: UInt8, op: LevelDBStore.BatchOp)] = []
            ops.reserveCapacity(result.dirtyNodes.count + 3)

            // IMPORTANT: we do NOT delete "stale" nodes during commit. A
            // superseded node (old version of an internal node or old root)
            // may still be referenced by an older snapshot that's retained
            // for rollback support. Deleting it would corrupt those snapshots
            // and cause rollbackToHeight to fail with corruptedData — which
            // is exactly how reorgs across tree-commit boundaries break.
            //
            // Trade-off: the nodes database grows unbounded until a future
            // compaction pass can safely GC nodes not reachable from any
            // retained snapshot. For a blockchain with infrequent deep reorgs,
            // this growth is bounded by (blocks_with_covenants * tree_interval).
            // See the staleNodeIds field in UrkelTree.CommitResult.

            // Write dirty nodes and populate application cache.
            // These nodes will be re-read on the next commit (after collapse
            // to hash refs), so caching them avoids LevelDB round-trips.
            for (nodeId, data) in result.dirtyNodes {
                ops.append((db: nodesDB, op: .put(key: nodeIdKey(nodeId), value: data)))
                nodeCache[nodeId] = data
            }

            // Trim cache if it grows too large
            if nodeCache.count > Self.maxNodeCacheEntries {
                // Simple strategy: clear and re-seed with this commit's nodes.
                // The hot nodes will be re-cached on the next resolver calls.
                nodeCache.removeAll(keepingCapacity: true)
                for (nodeId, data) in result.dirtyNodes {
                    nodeCache[nodeId] = data
                }
            }

            // Update meta
            let heightKey: [UInt8] = Array("height".utf8)
            let h = UInt32(height)
            let heightVal: [UInt8] = [
                UInt8(h & 0xFF),
                UInt8((h >> 8) & 0xFF),
                UInt8((h >> 16) & 0xFF),
                UInt8((h >> 24) & 0xFF),
            ]
            ops.append((db: metaDB, op: .put(key: heightKey, value: heightVal)))

            let rootIdKey: [UInt8] = Array("rootNodeId".utf8)
            let nextIdKey: [UInt8] = Array("nextNodeId".utf8)
            ops.append((db: metaDB, op: .put(key: rootIdKey, value: uint64LEBytes(result.rootNodeId))))
            ops.append((db: metaDB, op: .put(key: nextIdKey, value: uint64LEBytes(result.nextNodeId))))

            // Save snapshot for rollback support: height → (rootNodeId, nextNodeId)
            let snapKey = snapshotKey(height)
            var snapData = uint64LEBytes(result.rootNodeId)
            snapData.append(contentsOf: uint64LEBytes(result.nextNodeId))
            ops.append((db: snapshotsDB, op: .put(key: snapKey, value: snapData)))

            try store.writeBatch(ops)

            // Clear pending only after successful persist
            pending.removeAll()

            rootNodeId = result.rootNodeId
            nextNodeId = result.nextNodeId
            committedHeight = height
        } else {
            // Non-persistent: clear pending after tree insert
            pending.removeAll()
        }

        cachedRootHash = try tree.rootHash()
    }

    /// Backward-compatible commit without height tracking.
    public func commit() throws {
        try commit(height: -1)
    }

    /// Roll back the tree to the state at the latest treeInterval commit
    /// at or below `height`.
    ///
    /// Restores the root from the saved snapshot and clears pending changes.
    /// Only works with persistent (LevelDB-backed) instances.
    ///
    /// - Parameters:
    ///   - height: The target height to roll back to.
    ///   - treeInterval: The tree commit interval (e.g. 36).
    public func rollbackToHeight(_ height: Int, treeInterval: Int) throws {
        guard let store = store else {
            throw UrkelError.corruptedData
        }

        // Find latest treeInterval commit at or below height
        let targetCommit = (height / treeInterval) * treeInterval

        // Load snapshot for targetCommit
        let snapKey = snapshotKey(targetCommit)
        guard let snapData = try store.get(db: snapshotsDB, key: snapKey),
              snapData.count >= 16 else {
            throw UrkelError.corruptedData
        }

        var snapReader = BufferReader(snapData)
        let savedRootId = try snapReader.readUInt64LE()
        let savedNextId = try snapReader.readUInt64LE()

        // Restore tree root
        if savedRootId == 0 {
            tree.setRoot(.null())
            cachedRootHash = nil
        } else {
            let rootKey = nodeIdKey(savedRootId)
            guard let rootData = try store.get(db: nodesDB, key: rootKey) else {
                throw UrkelError.corruptedData
            }
            nodeCache[savedRootId] = rootData
            let rootRef = try UrkelTree.deserializeNode(rootData, nodeId: savedRootId)
            let rootHash = try rootRef.hash()
            tree.setRoot(UrkelNodeRef(hashRef: rootHash, nodeId: savedRootId))
            cachedRootHash = rootHash
        }

        rootNodeId = savedRootId
        nextNodeId = savedNextId
        pending.removeAll()
        nodeCache.removeAll(keepingCapacity: true)
        committedHeight = targetCommit

        // Update meta in LevelDB
        let heightKey: [UInt8] = Array("height".utf8)
        let h = UInt32(targetCommit)
        let heightVal: [UInt8] = [
            UInt8(h & 0xFF), UInt8((h >> 8) & 0xFF),
            UInt8((h >> 16) & 0xFF), UInt8((h >> 24) & 0xFF),
        ]
        let rootIdKey: [UInt8] = Array("rootNodeId".utf8)
        let nextIdKey: [UInt8] = Array("nextNodeId".utf8)
        var batch: [(db: UInt8, op: LevelDBStore.BatchOp)] = [
            (db: metaDB, op: .put(key: heightKey, value: heightVal)),
            (db: metaDB, op: .put(key: rootIdKey, value: uint64LEBytes(savedRootId))),
            (db: metaDB, op: .put(key: nextIdKey, value: uint64LEBytes(savedNextId))),
        ]

        // Delete stale snapshots above the rollback target
        var staleHeight = targetCommit + treeInterval
        while true {
            let staleKey = snapshotKey(staleHeight)
            guard let _ = try? store.get(db: snapshotsDB, key: staleKey) else { break }
            batch.append((db: snapshotsDB, op: .delete(key: staleKey)))
            staleHeight += treeInterval
        }

        try store.writeBatch(batch)
    }

    /// Close the underlying LevelDB store.
    public func close() {
        store?.close()
        store = nil
    }

    /// Dump all pending entries as (keyHex, serializedValueHex) pairs for debugging.
    public func dumpPending() -> [(key: String, nameHex: String, height: Int, renewal: Int, owner: Bool, value: Int64, highest: Int64, registered: Bool, expired: Bool, transfer: Int, revoked: Int, renewals: Int, dataLen: Int)] {
        pending.map { (key, ns) in
            let name = String(bytes: ns.name, encoding: .ascii) ?? HexEncoding.encode(ns.name)
            return (
                key: HexEncoding.encode(Array(key.bytes.prefix(8))),
                nameHex: name,
                height: ns.height,
                renewal: ns.renewal,
                owner: ns.owner != nil,
                value: ns.value,
                highest: ns.highest,
                registered: ns.registered,
                expired: ns.expired,
                transfer: ns.transfer,
                revoked: ns.revoked,
                renewals: ns.renewals,
                dataLen: ns.data.count
            )
        }.sorted { $0.nameHex < $1.nameHex }
    }

    // MARK: - Private helpers

    /// Convert a height to a 4-byte snapshot key (little-endian).
    private func snapshotKey(_ height: Int) -> [UInt8] {
        let h = UInt32(height)
        return [
            UInt8(h & 0xFF), UInt8((h >> 8) & 0xFF),
            UInt8((h >> 16) & 0xFF), UInt8((h >> 24) & 0xFF),
        ]
    }

    /// Convert a node ID to an 8-byte key (big-endian for lexicographic order).
    private func nodeIdKey(_ id: UInt64) -> [UInt8] {
        uint64BEBytes(id)
    }

    /// Encode a UInt64 as 8 big-endian bytes (preserves lexicographic = numeric order).
    private func uint64BEBytes(_ value: UInt64) -> [UInt8] {
        [
            UInt8((value >> 56) & 0xFF),
            UInt8((value >> 48) & 0xFF),
            UInt8((value >> 40) & 0xFF),
            UInt8((value >> 32) & 0xFF),
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ]
    }

    /// Encode a UInt64 as 8 little-endian bytes (for meta values only).
    private func uint64LEBytes(_ value: UInt64) -> [UInt8] {
        var w = BufferWriter(capacity: 8)
        w.writeUInt64LE(value)
        return w.data
    }
}
