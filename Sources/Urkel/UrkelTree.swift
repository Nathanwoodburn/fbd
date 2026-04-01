import Base
import ExtCrypto

/// An in-memory Urkel trie (base-2 merkleized radix trie).
///
/// Provides authenticated key-value storage with compact proofs
/// for inclusion and exclusion. Keys are 32 bytes (256 bits) and
/// values are limited to `urkelMaxValueSize` bytes.
public struct UrkelTree: @unchecked Sendable {
    /// The root node reference.
    private var root: UrkelNodeRef

    /// Optional resolver for lazily loading persisted `.hash` nodes from disk.
    public var resolver: ((UInt64) throws -> UrkelNodeRef)?

    /// Create an empty Urkel tree.
    public init() {
        self.root = .null()
    }

    /// The hash of the root node (32 bytes).
    ///
    /// For an empty tree, this is the zero hash.
    public func rootHash() throws -> [UInt8] {
        try root.hash()
    }

    /// Direct access to the root node reference (for persistence layer).
    public var rootRef: UrkelNodeRef { root }

    /// Set the root node reference (for persistence layer startup).
    public mutating func setRoot(_ ref: UrkelNodeRef) {
        root = ref
    }

    // MARK: - Get

    /// Look up a value by key.
    ///
    /// - Parameter key: A 32-byte key.
    /// - Returns: The value if found, or `nil`.
    public func get(_ key: [UInt8]) throws -> [UInt8]? {
        guard key.count == urkelKeySize else {
            throw UrkelError.invalidKeySize(key.count)
        }
        return try Self.get(node: root, key: key, depth: 0, resolver: resolver)
    }

    private static func get(node: UrkelNodeRef, key: [UInt8], depth: Int, resolver: ((UInt64) throws -> UrkelNodeRef)?) throws -> [UInt8]? {
        try node.resolveIfNeeded(resolver)

        switch node.node {
        case .null:
            return nil

        case .internal(let n):
            // Check if the key matches this node's prefix
            let matched = n.prefix.count(key, depth)
            if matched != n.prefix.size {
                return nil // Key diverges from prefix
            }

            let newDepth = depth + n.prefix.size
            let bit = Bits.getBit(key, newDepth)
            let child = bit == 0 ? n.left : n.right
            return try get(node: child, key: key, depth: newDepth + 1, resolver: resolver)

        case .leaf(let leaf):
            if leaf.key == key {
                return leaf.value
            }
            return nil

        case .hash:
            throw UrkelError.unresolvedNode
        }
    }

    // MARK: - Insert

    /// Insert or update a key-value pair.
    ///
    /// - Parameters:
    ///   - key: A 32-byte key.
    ///   - value: The value to store (at most `urkelMaxValueSize` bytes).
    public mutating func insert(_ key: [UInt8], _ value: [UInt8]) throws {
        guard key.count == urkelKeySize else {
            throw UrkelError.invalidKeySize(key.count)
        }
        guard value.count <= urkelMaxValueSize else {
            throw UrkelError.valueTooLarge(value.count)
        }
        root = try Self.insert(node: root, key: key, value: value, depth: 0, resolver: resolver)
    }

    private static func insert(node: UrkelNodeRef, key: [UInt8], value: [UInt8], depth: Int, resolver: ((UInt64) throws -> UrkelNodeRef)?) throws -> UrkelNodeRef {
        try node.resolveIfNeeded(resolver)

        switch node.node {
        case .null:
            return UrkelNodeRef(.leaf(UrkelLeaf(key: key, value: value)))

        case .internal(let n):
            let matched = n.prefix.count(key, depth)
            let newDepth = depth + matched

            if matched != n.prefix.size {
                // Key diverges within this node's prefix
                let leafRef = UrkelNodeRef(.leaf(UrkelLeaf(key: key, value: value)))
                let (front, back) = n.prefix.split(matched)
                let childRef = UrkelNodeRef(.internal(UrkelInternal(prefix: back, left: n.left, right: n.right)))
                let bit = Bits.getBit(key, newDepth)
                let newNode = UrkelInternal.from(prefix: front, leafRef, childRef, bit: bit)
                return UrkelNodeRef(.internal(newNode))
            }

            // Full prefix match — recurse into correct child, mutate in place
            let bit = Bits.getBit(key, newDepth)
            let x = bit == 0 ? n.left : n.right
            let z = try insert(node: x, key: key, value: value, depth: newDepth + 1, resolver: resolver)
            if bit == 0 {
                node.node = .internal(UrkelInternal(prefix: n.prefix, left: z, right: n.right))
            } else {
                node.node = .internal(UrkelInternal(prefix: n.prefix, left: n.left, right: z))
            }
            node.markDirty()
            return node

        case .leaf(let leaf):
            if leaf.key == key {
                // Replace existing value — mutate in place
                node.node = .leaf(UrkelLeaf(key: key, value: value))
                node.markDirty()
                return node
            }

            // Collision: create new internal node(s)
            let prefix = Bits.collide(key, leaf.key, depth: depth, maxBits: urkelBits - depth)
            let newDepth = depth + prefix.size
            let leafRef = UrkelNodeRef(.leaf(UrkelLeaf(key: key, value: value)))
            let bit = Bits.getBit(key, newDepth)
            let newNode = UrkelInternal.from(prefix: prefix, leafRef, node, bit: bit)
            return UrkelNodeRef(.internal(newNode))

        case .hash:
            throw UrkelError.unresolvedNode
        }
    }

    // MARK: - Remove

    /// Remove a key from the trie.
    ///
    /// - Parameter key: A 32-byte key.
    /// - Returns: `true` if the key was found and removed.
    @discardableResult
    public mutating func remove(_ key: [UInt8]) throws -> Bool {
        guard key.count == urkelKeySize else {
            throw UrkelError.invalidKeySize(key.count)
        }
        guard let newRoot = try Self.remove(node: root, key: key, depth: 0, resolver: resolver) else {
            return false // Key not found
        }
        root = newRoot
        return true
    }

    /// Result sentinel for "node was removed" (empty subtree).
    private static let removedSentinel = UrkelNodeRef(.null)

    private static func remove(node: UrkelNodeRef, key: [UInt8], depth: Int, resolver: ((UInt64) throws -> UrkelNodeRef)?) throws -> UrkelNodeRef? {
        try node.resolveIfNeeded(resolver)

        switch node.node {
        case .null:
            return nil // Key not found

        case .internal(let n):
            if !n.prefix.has(key, depth) {
                return nil // Key not in this subtree
            }

            let newDepth = depth + n.prefix.size
            let bit = Bits.getBit(key, newDepth)
            let x = bit == 0 ? n.left : n.right
            let y = bit == 0 ? n.right : n.left

            guard let z = try remove(node: x, key: key, depth: newDepth + 1, resolver: resolver) else {
                return nil // Key not found
            }

            if z.node.isNull {
                // Child was removed; collapse with sibling
                try y.resolveIfNeeded(resolver)
                switch y.node {
                case .internal(let sibling):
                    let newPrefix = n.prefix.join(sibling.prefix, bit ^ 1)
                    return UrkelNodeRef(.internal(UrkelInternal(
                        prefix: newPrefix, left: sibling.left, right: sibling.right
                    )))
                default:
                    // Leaf or null — just promote the sibling
                    return y
                }
            }

            let newNode = UrkelInternal.from(prefix: n.prefix, z, y, bit: bit)
            return UrkelNodeRef(.internal(newNode))

        case .leaf(let leaf):
            if leaf.key != key {
                return nil // Key not found
            }
            return removedSentinel

        case .hash:
            throw UrkelError.unresolvedNode
        }
    }

    // MARK: - Serialization (legacy full-tree blob)

    /// Serialize the entire tree structure to bytes (preorder traversal).
    ///
    /// Format per node:
    /// - Null: `0x00`
    /// - Leaf: `0x02` + key(32) + valueLen(2 LE) + value + hash(32) or 0x00 if no cached hash
    /// - Internal: `0x01` + prefixBits(serialized) + hash(32) or 0x00 if none + left + right
    public func serialize() throws -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(1024 * 1024)
        try Self.serializeNode(root, to: &out)
        return out
    }

    private static func serializeNode(_ ref: UrkelNodeRef, to out: inout [UInt8]) throws {
        switch ref.node {
        case .null:
            out.append(0x00)

        case .leaf(let leaf):
            out.append(0x02)
            out.append(contentsOf: leaf.key)
            let len = leaf.value.count
            out.append(UInt8(len & 0xFF))
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(contentsOf: leaf.value)
            // Write cached hash if available
            if let h = ref.cachedHashBytes {
                out.append(0x01)
                out.append(contentsOf: h)
            } else {
                out.append(0x00)
            }

        case .internal(let n):
            out.append(0x01)
            let prefixData = n.prefix.serialize()
            out.append(contentsOf: prefixData)
            // Write cached hash if available
            if let h = ref.cachedHashBytes {
                out.append(0x01)
                out.append(contentsOf: h)
            } else {
                out.append(0x00)
            }
            try serializeNode(n.left, to: &out)
            try serializeNode(n.right, to: &out)

        case .hash:
            throw UrkelError.unresolvedNode
        }
    }

    /// Deserialize a tree from bytes produced by `serialize()`.
    public static func deserialize(_ data: [UInt8]) throws -> UrkelTree {
        var offset = 0
        let root = try deserializeNode(data, offset: &offset)
        var tree = UrkelTree()
        tree.root = root
        return tree
    }

    private static func deserializeNode(_ data: [UInt8], offset: inout Int) throws -> UrkelNodeRef {
        guard offset < data.count else { throw UrkelError.corruptedData }
        let tag = data[offset]
        offset += 1

        switch tag {
        case 0x00:
            return .null()

        case 0x02:
            // Leaf: key(32) + valueLen(2 LE) + value + hashFlag + hash?
            guard offset + 34 <= data.count else { throw UrkelError.corruptedData }
            let key = Array(data[offset..<offset + 32])
            offset += 32
            let valueLen = Int(data[offset]) | (Int(data[offset + 1]) << 8)
            offset += 2
            guard offset + valueLen + 1 <= data.count else { throw UrkelError.corruptedData }
            let value = Array(data[offset..<offset + valueLen])
            offset += valueLen
            let ref = UrkelNodeRef(.leaf(UrkelLeaf(key: key, value: value)))
            let hashFlag = data[offset]
            offset += 1
            if hashFlag == 0x01 {
                guard offset + 32 <= data.count else { throw UrkelError.corruptedData }
                ref.setCachedHash(Array(data[offset..<offset + 32]))
                offset += 32
            }
            return ref

        case 0x01:
            // Internal: prefix + hashFlag + hash? + left + right
            guard let (prefix, consumed) = Bits.deserialize(from: data, at: offset) else {
                throw UrkelError.corruptedData
            }
            offset += consumed
            guard offset < data.count else { throw UrkelError.corruptedData }
            let hashFlag = data[offset]
            offset += 1
            var cachedHash: [UInt8]? = nil
            if hashFlag == 0x01 {
                guard offset + 32 <= data.count else { throw UrkelError.corruptedData }
                cachedHash = Array(data[offset..<offset + 32])
                offset += 32
            }
            let left = try deserializeNode(data, offset: &offset)
            let right = try deserializeNode(data, offset: &offset)
            let ref = UrkelNodeRef(.internal(UrkelInternal(prefix: prefix, left: left, right: right)))
            if let h = cachedHash {
                ref.setCachedHash(h)
            }
            return ref

        default:
            throw UrkelError.corruptedData
        }
    }

    // MARK: - Node-level serialization (for persistence)

    /// Result of committing dirty nodes to persistent storage.
    public struct CommitResult {
        /// Dirty nodes that need to be written to disk: (nodeId, serialized data).
        public let dirtyNodes: [(nodeId: UInt64, data: [UInt8])]
        /// Node IDs that were superseded by this commit and can be deleted from storage.
        public let staleNodeIds: [UInt64]
        /// The root node's persistence ID after commit.
        public let rootNodeId: UInt64
        /// The next available node ID.
        public let nextNodeId: UInt64
    }

    /// Walk the tree and collect all dirty nodes, collapsing them to `.hash` refs.
    ///
    /// Nodes with `nodeId != nil` are already persisted and skipped (along with
    /// their entire subtree). Dirty nodes (nodeId == nil) are serialized, assigned
    /// an ID, and collapsed to lightweight `.hash` references.
    ///
    /// - Parameter nextNodeId: The next available node ID to assign.
    /// - Returns: A `CommitResult` with all dirty nodes and the new root ID.
    public mutating func commitDirtyNodes(nextNodeId: UInt64, estimatedDirtyCount: Int = 0) throws -> CommitResult {
        var dirtyNodes: [(nodeId: UInt64, data: [UInt8])] = []
        var staleNodeIds: [UInt64] = []
        if estimatedDirtyCount > 0 {
            dirtyNodes.reserveCapacity(estimatedDirtyCount)
            staleNodeIds.reserveCapacity(estimatedDirtyCount)
        }
        var currentId = nextNodeId
        let rootId = try Self.commitNode(root, nextNodeId: &currentId, dirtyNodes: &dirtyNodes, staleNodeIds: &staleNodeIds)
        return CommitResult(dirtyNodes: dirtyNodes, staleNodeIds: staleNodeIds, rootNodeId: rootId, nextNodeId: currentId)
    }

    /// Recursively commit a node and its children, returning its persistence ID.
    private static func commitNode(
        _ ref: UrkelNodeRef,
        nextNodeId: inout UInt64,
        dirtyNodes: inout [(nodeId: UInt64, data: [UInt8])],
        staleNodeIds: inout [UInt64]
    ) throws -> UInt64 {
        // Already persisted — skip entire subtree
        if let existingId = ref.nodeId {
            return existingId
        }

        // Collect stale ID (old version of this node that is being replaced)
        if let staleId = ref.staleNodeId {
            staleNodeIds.append(staleId)
            ref.staleNodeId = nil
        }

        switch ref.node {
        case .null:
            return 0 // Sentinel for null

        case .hash:
            // Already persisted but somehow lost nodeId — shouldn't happen
            throw UrkelError.internalError(".hash node without nodeId")

        case .leaf(let leaf):
            // Compute leaf hash directly (avoids indirection through ref.hash() → node.hash())
            let valueHash = try Blake2bHash.hash(leaf.value, size: 32)
            let nodeHash = try UrkelLeaf.computeHash(key: leaf.key, valueHash: valueHash)
            let id = nextNodeId
            nextNodeId += 1
            let data = serializeLeafNode(leaf, hash: nodeHash)
            dirtyNodes.append((nodeId: id, data: data))

            // Mark as persisted but keep expanded in memory (avoids resolver calls on next access)
            ref.nodeId = id
            ref.setCachedHash(nodeHash)
            return id

        case .internal(let n):
            // Recurse children first (sets their cachedHash)
            let leftId = try commitNode(n.left, nextNodeId: &nextNodeId, dirtyNodes: &dirtyNodes, staleNodeIds: &staleNodeIds)
            let rightId = try commitNode(n.right, nextNodeId: &nextNodeId, dirtyNodes: &dirtyNodes, staleNodeIds: &staleNodeIds)
            // Children already have cached hashes from their own commit
            let leftHash = try n.left.hash()
            let rightHash = try n.right.hash()
            // Compute this node's hash directly (avoids re-fetching child hashes through UrkelInternal.hash())
            let nodeHash = try UrkelInternal.computeHash(prefix: n.prefix, left: leftHash, right: rightHash)

            let id = nextNodeId
            nextNodeId += 1
            let data = serializeInternalNode(n, hash: nodeHash, leftId: leftId, leftHash: leftHash, rightId: rightId, rightHash: rightHash)
            dirtyNodes.append((nodeId: id, data: data))

            // Mark as persisted but keep expanded in memory (avoids resolver calls on next access)
            ref.nodeId = id
            ref.setCachedHash(nodeHash)
            return id
        }
    }

    // MARK: - Node serialization formats

    /// Serialize a leaf node for individual storage.
    ///
    /// Format: `0x02 | key(32) | valueLen(2 LE) | value(N) | hash(32)`
    static func serializeLeafNode(_ leaf: UrkelLeaf, hash: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(1 + 32 + 2 + leaf.value.count + 32)
        out.append(0x02)
        out.append(contentsOf: leaf.key)
        let len = leaf.value.count
        out.append(UInt8(len & 0xFF))
        out.append(UInt8((len >> 8) & 0xFF))
        out.append(contentsOf: leaf.value)
        out.append(contentsOf: hash)
        return out
    }

    /// Serialize an internal node for individual storage.
    ///
    /// Format: `0x01 | prefix(serialized) | leftId(8 LE) | leftHash(32) | rightId(8 LE) | rightHash(32) | hash(32)`
    static func serializeInternalNode(_ node: UrkelInternal, hash: [UInt8], leftId: UInt64, leftHash: [UInt8], rightId: UInt64, rightHash: [UInt8]) -> [UInt8] {
        let prefixData = node.prefix.serialize()
        var w = BufferWriter(capacity: 1 + prefixData.count + 8 + 32 + 8 + 32 + 32)
        w.writeUInt8(0x01)
        w.writeBytes(prefixData)
        w.writeUInt64LE(leftId)
        w.writeBytes(leftHash)
        w.writeUInt64LE(rightId)
        w.writeBytes(rightHash)
        w.writeBytes(hash)
        return w.data
    }

    /// Deserialize a node from individual storage format.
    ///
    /// Returns a resolved node with `.hash` children (for internal nodes).
    public static func deserializeNode(_ data: [UInt8], nodeId: UInt64) throws -> UrkelNodeRef {
        guard !data.isEmpty else { throw UrkelError.corruptedData }
        let tag = data[0]

        switch tag {
        case 0x02:
            // Leaf: key(32) + valueLen(2 LE) + value(N) + hash(32)
            guard data.count >= 1 + 32 + 2 else { throw UrkelError.corruptedData }
            let key = Array(data[1..<33])
            let valueLen = Int(data[33]) | (Int(data[34]) << 8)
            guard data.count == 1 + 32 + 2 + valueLen + 32 else { throw UrkelError.corruptedData }
            let value = Array(data[35..<35 + valueLen])
            let hash = Array(data[35 + valueLen..<35 + valueLen + 32])
            let ref = UrkelNodeRef(.leaf(UrkelLeaf(key: key, value: value)))
            ref.nodeId = nodeId
            ref.setCachedHash(hash)
            return ref

        case 0x01:
            // Internal: prefix(serialized) | leftId(8) | leftHash(32) | rightId(8) | rightHash(32) | hash(32)
            guard let (prefix, consumed) = Bits.deserialize(from: data, at: 1) else {
                throw UrkelError.corruptedData
            }
            let startOffset = 1 + consumed
            guard data.count >= startOffset + 8 + 32 + 8 + 32 + 32 else { throw UrkelError.corruptedData }

            var reader = BufferReader(Array(data[startOffset...]))
            let leftId = try reader.readUInt64LE()
            let leftHash = try reader.readBytes(32)
            let rightId = try reader.readUInt64LE()
            let rightHash = try reader.readBytes(32)
            let hash = try reader.readBytes(32)

            // Create children as hash refs (null sentinel uses nodeId 0)
            let left: UrkelNodeRef
            if leftId == 0 {
                left = .null()
            } else {
                left = UrkelNodeRef(hashRef: leftHash, nodeId: leftId)
            }

            let right: UrkelNodeRef
            if rightId == 0 {
                right = .null()
            } else {
                right = UrkelNodeRef(hashRef: rightHash, nodeId: rightId)
            }

            let ref = UrkelNodeRef(.internal(UrkelInternal(prefix: prefix, left: left, right: right)))
            ref.nodeId = nodeId
            ref.setCachedHash(hash)
            return ref

        default:
            throw UrkelError.corruptedData
        }
    }

    // MARK: - Prove

    /// Generate a proof of inclusion or exclusion for a key.
    ///
    /// - Parameter key: A 32-byte key.
    /// - Returns: A proof that can be verified against the tree root hash.
    public func prove(_ key: [UInt8]) throws -> UrkelProof {
        guard key.count == urkelKeySize else {
            throw UrkelError.invalidKeySize(key.count)
        }

        var proof = UrkelProof()
        try Self.prove(node: root, key: key, depth: 0, proof: &proof, resolver: resolver)
        return proof
    }

    private static func prove(node: UrkelNodeRef, key: [UInt8], depth: Int, proof: inout UrkelProof, resolver: ((UInt64) throws -> UrkelNodeRef)?) throws {
        try node.resolveIfNeeded(resolver)

        switch node.node {
        case .null:
            proof.type = .deadend
            proof.depth = depth

        case .internal(let n):
            if !n.prefix.has(key, depth) {
                // Key diverges at this node's prefix
                proof.type = .short
                proof.depth = depth
                proof.prefix = n.prefix
                proof.left = try n.left.hash()
                proof.right = try n.right.hash()
                return
            }

            let newDepth = depth + n.prefix.size
            let bit = Bits.getBit(key, newDepth)
            let sibling = bit == 0 ? n.right : n.left
            let child = bit == 0 ? n.left : n.right

            proof.push(prefix: n.prefix, hash: try sibling.hash())

            try prove(node: child, key: key, depth: newDepth + 1, proof: &proof, resolver: resolver)

        case .leaf(let leaf):
            if leaf.key == key {
                proof.type = .exists
                proof.depth = depth
                proof.value = leaf.value
            } else {
                proof.type = .collision
                proof.depth = depth
                proof.collisionKey = leaf.key
                proof.collisionHash = try Blake2bHash.hash(leaf.value, size: 32)
            }

        case .hash:
            throw UrkelError.unresolvedNode
        }
    }
}

