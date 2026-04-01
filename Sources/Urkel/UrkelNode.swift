import ExtCrypto

/// Key size in bytes (256 bits).
public let urkelKeySize = 32

/// Key size in bits.
public let urkelBits = 256

/// Hash output size in bytes (BLAKE2b-256).
public let urkelHashSize = 32

/// The 32-byte zero hash (empty/null node hash).
public let urkelZeroHash = [UInt8](repeating: 0, count: 32)

/// Domain-separation prefixes for node hashing.
private let leafPrefix: [UInt8] = [0x00]
private let internalPrefix: [UInt8] = [0x01]
private let skipPrefix: [UInt8] = [0x02]

/// Maximum allowed value size in the trie.
public let urkelMaxValueSize = 1023

/// A node in the Urkel trie.
public enum UrkelNode: Equatable, Sendable {
    /// An empty (null) node. Hash is the zero hash.
    case null

    /// An internal (branch) node with optional prefix compression.
    case `internal`(UrkelInternal)

    /// A leaf node holding a key-value pair.
    case leaf(UrkelLeaf)

    /// A persisted-but-not-loaded node (hash reference only).
    ///
    /// This case represents a node that has been written to disk and collapsed
    /// to just its hash. The actual node data is lazily loaded via a resolver.
    /// Note: `UrkelNodeRef.hash()` returns cachedHash before calling `node.hash()`,
    /// so this throwing implementation is a safety net for direct access.
    case hash

    /// Compute the hash of this node.
    public func hash() throws -> [UInt8] {
        switch self {
        case .null:
            return urkelZeroHash
        case .internal(let node):
            return try node.hash()
        case .leaf(let node):
            return try node.hash()
        case .hash:
            throw UrkelError.unresolvedNode
        }
    }

    /// Whether this node is null.
    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }
}

/// An internal (branch) node with an optional prefix for path compression.
public struct UrkelInternal: Equatable, Sendable {
    /// The compressed prefix bits (may be empty).
    public let prefix: Bits

    /// The left child (bit=0 direction).
    public var left: UrkelNodeRef

    /// The right child (bit=1 direction).
    public var right: UrkelNodeRef

    public init(prefix: Bits, left: UrkelNodeRef, right: UrkelNodeRef) {
        self.prefix = prefix
        self.left = left
        self.right = right
    }

    /// Get the child in the given direction (0=left, 1=right).
    public func child(_ bit: Int) -> UrkelNodeRef {
        bit == 0 ? left : right
    }

    /// Create an internal node with children placed by bit direction.
    ///
    /// `x` goes on the `bit` side, `y` goes on the opposite side.
    public static func from(prefix: Bits, _ x: UrkelNodeRef, _ y: UrkelNodeRef, bit: Int) -> UrkelInternal {
        if bit == 0 {
            return UrkelInternal(prefix: prefix, left: x, right: y)
        } else {
            return UrkelInternal(prefix: prefix, left: y, right: x)
        }
    }

    /// Compute the hash of this internal node.
    public func hash() throws -> [UInt8] {
        let leftHash = try left.hash()
        let rightHash = try right.hash()
        return try UrkelInternal.computeHash(prefix: prefix, left: leftHash, right: rightHash)
    }

    /// Compute the hash for an internal node given its components.
    public static func computeHash(prefix: Bits, left: [UInt8], right: [UInt8]) throws -> [UInt8] {
        if prefix.isEmpty {
            // BLAKE2b-256( 0x01 || leftHash || rightHash )
            var input = internalPrefix
            input.append(contentsOf: left)
            input.append(contentsOf: right)
            return try Blake2bHash.hash(input, size: 32)
        } else {
            // BLAKE2b-256( 0x02 || LE16(prefixBitCount) || prefixBytes || leftHash || rightHash )
            var input = skipPrefix
            input.append(UInt8(prefix.size & 0xFF))
            input.append(UInt8(prefix.size >> 8))
            let byteCount = (prefix.size + 7) / 8
            input.append(contentsOf: prefix.data.prefix(byteCount))
            input.append(contentsOf: left)
            input.append(contentsOf: right)
            return try Blake2bHash.hash(input, size: 32)
        }
    }
}

/// A leaf node that holds a 32-byte key and its value.
public struct UrkelLeaf: Equatable, Sendable {
    /// The full 32-byte trie key (e.g., SHA3-256 of the name).
    public let key: [UInt8]

    /// The value stored at this key.
    public let value: [UInt8]

    public init(key: [UInt8], value: [UInt8]) {
        self.key = key
        self.value = value
    }

    /// Compute the leaf hash.
    ///
    /// `BLAKE2b-256( 0x00 || key || BLAKE2b-256(value) )`
    public func hash() throws -> [UInt8] {
        let valueHash = try Blake2bHash.hash(value, size: 32)
        return try UrkelLeaf.computeHash(key: key, valueHash: valueHash)
    }

    /// Compute the leaf hash from a key and pre-hashed value.
    public static func computeHash(key: [UInt8], valueHash: [UInt8]) throws -> [UInt8] {
        var input = leafPrefix
        input.append(contentsOf: key)
        input.append(contentsOf: valueHash)
        return try Blake2bHash.hash(input, size: 32)
    }

    /// Compute the full leaf hash given a key and raw value.
    public static func hashValue(key: [UInt8], value: [UInt8]) throws -> [UInt8] {
        let valueHash = try Blake2bHash.hash(value, size: 32)
        return try computeHash(key: key, valueHash: valueHash)
    }
}

/// An indirect reference to an Urkel node.
///
/// Uses a class wrapper for indirection since Swift enums cannot be
/// directly recursive. Caches the computed hash — since `insert()` creates
/// new `UrkelNodeRef` instances along modified paths, unchanged subtrees
/// retain their cached hashes automatically.
public final class UrkelNodeRef: @unchecked Sendable, Equatable {
    public var node: UrkelNode
    private var cachedHash: [UInt8]?

    /// Persistence ID — nil means dirty (needs writing), non-nil means persisted at this ID.
    public var nodeId: UInt64?

    /// Previous persistence ID that was superseded when this node was marked dirty.
    /// Collected during commit so the caller can delete the old entry from storage.
    public var staleNodeId: UInt64?

    public init(_ node: UrkelNode) {
        self.node = node
    }

    /// Create a hash-only reference for a persisted node.
    ///
    /// The node's data is not loaded; it will be lazily resolved via a resolver
    /// when the tree needs to inspect it.
    public init(hashRef hash: [UInt8], nodeId: UInt64) {
        self.node = .hash
        self.cachedHash = hash
        self.nodeId = nodeId
    }

    public static func null() -> UrkelNodeRef {
        UrkelNodeRef(.null)
    }

    /// Whether this node needs resolution (is a `.hash` placeholder).
    public var needsResolve: Bool {
        if case .hash = node { return true }
        return false
    }

    /// Resolve this node in-place if it's a `.hash` placeholder.
    ///
    /// Calls the resolver to load the full node data from disk, then copies
    /// the loaded node's `.node` field onto self (preserving nodeId and cachedHash).
    public func resolveIfNeeded(_ resolver: ((UInt64) throws -> UrkelNodeRef)?) throws {
        guard case .hash = node else { return }
        guard let resolver = resolver, let id = nodeId else {
            throw UrkelError.unresolvedNode
        }
        let loaded = try resolver(id)
        self.node = loaded.node
        // Keep our existing nodeId and cachedHash
    }

    /// Compute the hash of the referenced node, using cached value if available.
    public func hash() throws -> [UInt8] {
        if let cached = cachedHash { return cached }
        let h = try node.hash()
        cachedHash = h
        return h
    }

    /// The cached hash bytes, if available (for serialization).
    public var cachedHashBytes: [UInt8]? { cachedHash }

    /// Set the cached hash (for deserialization).
    public func setCachedHash(_ hash: [UInt8]) {
        cachedHash = hash
    }

    /// Mark this node as dirty (modified in place).
    ///
    /// Clears the cached hash and persistence ID so the node will be
    /// re-hashed and re-persisted on the next commit. If the node was
    /// previously persisted, its old ID is saved so the caller can
    /// delete the stale entry from storage.
    public func markDirty() {
        cachedHash = nil
        if let id = nodeId {
            staleNodeId = id
        }
        nodeId = nil
    }

    public static func == (lhs: UrkelNodeRef, rhs: UrkelNodeRef) -> Bool {
        // Fast path: compare by persistence ID if both are persisted
        if let lId = lhs.nodeId, let rId = rhs.nodeId {
            return lId == rId
        }
        return lhs.node == rhs.node
    }
}
