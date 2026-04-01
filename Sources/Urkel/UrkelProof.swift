import ExtCrypto

/// The type of an Urkel trie proof.
public enum UrkelProofType: UInt8, Sendable {
    /// Key path leads to a null node (non-existence).
    case deadend = 0
    /// Key path diverges at an internal node's prefix (non-existence).
    case short = 1
    /// Key path leads to a leaf with a different key (non-existence).
    case collision = 2
    /// Key exists and value is provided (existence).
    case exists = 3
}

/// A single node in the authentication path of a proof.
public struct UrkelProofNode: Equatable, Sendable {
    /// The prefix at this internal node (may be empty).
    public let prefix: Bits
    /// The sibling hash (the hash of the child we did NOT traverse).
    public let node: [UInt8]

    public init(prefix: Bits, node: [UInt8]) {
        self.prefix = prefix
        self.node = node
    }
}

/// A proof of inclusion or exclusion for a key in the Urkel trie.
public struct UrkelProof: Equatable, Sendable {
    /// The proof type.
    public var type: UrkelProofType

    /// The depth at which the proof terminates.
    public var depth: Int

    /// The authentication path from root to the proof point.
    public var nodes: [UrkelProofNode]

    // Type-specific fields:

    /// For `short` proofs: the diverging prefix.
    public var prefix: Bits?

    /// For `short` proofs: left child hash at divergence.
    public var left: [UInt8]?

    /// For `short` proofs: right child hash at divergence.
    public var right: [UInt8]?

    /// For `collision` proofs: the key at the leaf.
    public var collisionKey: [UInt8]?

    /// For `collision` proofs: the hash of the value at the leaf.
    public var collisionHash: [UInt8]?

    /// For `exists` proofs: the value.
    public var value: [UInt8]?

    public init(type: UrkelProofType = .deadend, depth: Int = 0, nodes: [UrkelProofNode] = []) {
        self.type = type
        self.depth = depth
        self.nodes = nodes
    }

    /// Add a node to the authentication path.
    public mutating func push(prefix: Bits, hash: [UInt8]) {
        nodes.append(UrkelProofNode(prefix: prefix, node: hash))
    }

    // MARK: - Verification

    /// Verify this proof against an expected root hash and key.
    ///
    /// - Parameters:
    ///   - root: The expected trie root hash (32 bytes).
    ///   - key: The 32-byte key being proven.
    /// - Returns: The value if the proof is an existence proof, or `nil` for
    ///   non-existence proofs.
    /// - Throws: An `UrkelError` if the proof is invalid.
    public func verify(root: [UInt8], key: [UInt8]) throws -> [UInt8]? {
        guard key.count == urkelKeySize else {
            throw UrkelError.invalidKeySize(key.count)
        }

        guard depth <= urkelBits else {
            throw UrkelError.malformedProof("depth exceeds key bits")
        }

        // Step 1: Compute the leaf hash based on proof type.
        var leaf: [UInt8]

        switch type {
        case .deadend:
            leaf = urkelZeroHash

        case .short:
            guard let pfx = prefix, let l = left, let r = right else {
                throw UrkelError.malformedProof("short proof missing fields")
            }
            // The prefix must NOT match the key at this depth.
            if pfx.has(key, depth) {
                throw UrkelError.proofSamePath
            }
            leaf = try UrkelInternal.computeHash(prefix: pfx, left: l, right: r)

        case .collision:
            guard let ck = collisionKey, let ch = collisionHash else {
                throw UrkelError.malformedProof("collision proof missing fields")
            }
            // The collision key must differ from our key.
            if ck == key {
                throw UrkelError.proofSameKey
            }
            leaf = try UrkelLeaf.computeHash(key: ck, valueHash: ch)

        case .exists:
            guard let val = value else {
                throw UrkelError.malformedProof("exists proof missing value")
            }
            leaf = try UrkelLeaf.hashValue(key: key, value: val)
        }

        // Step 2: Walk the authentication path from leaf to root.
        var next = leaf
        var currentDepth = depth

        for i in stride(from: nodes.count - 1, through: 0, by: -1) {
            let proofNode = nodes[i]

            guard currentDepth >= proofNode.prefix.size + 1 else {
                throw UrkelError.proofNegativeDepth
            }

            currentDepth -= 1

            // Determine which side we're on.
            if Bits.getBit(key, currentDepth) == 1 {
                // We're on the right; sibling is on the left.
                next = try UrkelInternal.computeHash(
                    prefix: proofNode.prefix,
                    left: proofNode.node,
                    right: next
                )
            } else {
                // We're on the left; sibling is on the right.
                next = try UrkelInternal.computeHash(
                    prefix: proofNode.prefix,
                    left: next,
                    right: proofNode.node
                )
            }

            currentDepth -= proofNode.prefix.size

            // Verify the prefix matches the key at this depth.
            if !proofNode.prefix.has(key, currentDepth) {
                throw UrkelError.proofPathMismatch
            }
        }

        // Step 3: Final checks.
        guard currentDepth == 0 else {
            throw UrkelError.proofTooDeep
        }

        guard next == root else {
            throw UrkelError.proofHashMismatch
        }

        return type == .exists ? value : nil
    }

    // MARK: - Serialization

    /// Serialize this proof to bytes.
    public func serialize() -> [UInt8] {
        var out = [UInt8]()

        // Field: (type << 14) | depth as u16 LE
        let field = UInt16(type.rawValue) << 14 | UInt16(depth)
        out.append(UInt8(field & 0xFF))
        out.append(UInt8(field >> 8))

        // Count as u16 LE
        let count = UInt16(nodes.count)
        out.append(UInt8(count & 0xFF))
        out.append(UInt8(count >> 8))

        // Bitmap: one bit per node indicating if it has a non-empty prefix
        let bitmapSize = (nodes.count + 7) / 8
        var bitmap = [UInt8](repeating: 0, count: bitmapSize)
        for i in 0..<nodes.count {
            if !nodes[i].prefix.isEmpty {
                let oct = i >> 3
                let bit = i & 7
                bitmap[oct] |= UInt8(1 << (7 - bit))
            }
        }
        out.append(contentsOf: bitmap)

        // Nodes
        for i in 0..<nodes.count {
            if !nodes[i].prefix.isEmpty {
                out.append(contentsOf: nodes[i].prefix.serialize())
            }
            out.append(contentsOf: nodes[i].node)
        }

        // Type-specific data
        switch type {
        case .deadend:
            break

        case .short:
            if let pfx = prefix {
                out.append(contentsOf: pfx.serialize())
            }
            if let l = left { out.append(contentsOf: l) }
            if let r = right { out.append(contentsOf: r) }

        case .collision:
            if let ck = collisionKey { out.append(contentsOf: ck) }
            if let ch = collisionHash { out.append(contentsOf: ch) }

        case .exists:
            if let val = value {
                out.append(UInt8(val.count & 0xFF))
                out.append(UInt8(val.count >> 8))
                out.append(contentsOf: val)
            }
        }

        return out
    }

    /// Deserialize a proof from bytes.
    public static func deserialize(from bytes: [UInt8]) throws -> UrkelProof {
        guard bytes.count >= 4 else {
            throw UrkelError.malformedProof("too short")
        }

        var pos = 0

        // Field
        let field = UInt16(bytes[pos]) | UInt16(bytes[pos + 1]) << 8
        pos += 2
        let typeRaw = UInt8(field >> 14)
        let depth = Int(field & 0x3FFF)

        guard let proofType = UrkelProofType(rawValue: typeRaw) else {
            throw UrkelError.malformedProof("unknown proof type \(typeRaw)")
        }

        // Count (bounded by trie depth — a valid proof has at most 256 path nodes)
        let count = Int(UInt16(bytes[pos]) | UInt16(bytes[pos + 1]) << 8)
        pos += 2
        guard count <= 256 else {
            throw UrkelError.malformedProof("node count \(count) exceeds max trie depth")
        }

        // Bitmap
        let bitmapSize = (count + 7) / 8
        guard pos + bitmapSize <= bytes.count else {
            throw UrkelError.malformedProof("truncated bitmap")
        }
        let bitmap = Array(bytes[pos..<pos + bitmapSize])
        pos += bitmapSize

        // Nodes
        var nodes = [UrkelProofNode]()
        nodes.reserveCapacity(count)
        for i in 0..<count {
            let hasPrefix: Bool
            if !bitmap.isEmpty {
                let oct = i >> 3
                let bit = i & 7
                hasPrefix = (bitmap[oct] >> (7 - bit)) & 1 == 1
            } else {
                hasPrefix = false
            }

            var pfx = Bits()
            if hasPrefix {
                guard let (bits, consumed) = Bits.deserialize(from: bytes, at: pos) else {
                    throw UrkelError.malformedProof("invalid prefix at node \(i)")
                }
                pfx = bits
                pos += consumed
            }

            guard pos + 32 <= bytes.count else {
                throw UrkelError.malformedProof("truncated sibling hash at node \(i)")
            }
            let hash = Array(bytes[pos..<pos + 32])
            pos += 32

            nodes.append(UrkelProofNode(prefix: pfx, node: hash))
        }

        var proof = UrkelProof(type: proofType, depth: depth, nodes: nodes)

        // Type-specific data
        switch proofType {
        case .deadend:
            break

        case .short:
            guard let (bits, consumed) = Bits.deserialize(from: bytes, at: pos) else {
                throw UrkelError.malformedProof("invalid short prefix")
            }
            proof.prefix = bits
            pos += consumed

            guard pos + 64 <= bytes.count else {
                throw UrkelError.malformedProof("truncated short hashes")
            }
            proof.left = Array(bytes[pos..<pos + 32])
            pos += 32
            proof.right = Array(bytes[pos..<pos + 32])
            pos += 32

        case .collision:
            guard pos + 64 <= bytes.count else {
                throw UrkelError.malformedProof("truncated collision data")
            }
            proof.collisionKey = Array(bytes[pos..<pos + 32])
            pos += 32
            proof.collisionHash = Array(bytes[pos..<pos + 32])
            pos += 32

        case .exists:
            guard pos + 2 <= bytes.count else {
                throw UrkelError.malformedProof("truncated value length")
            }
            let valLen = Int(UInt16(bytes[pos]) | UInt16(bytes[pos + 1]) << 8)
            pos += 2
            guard pos + valLen <= bytes.count else {
                throw UrkelError.malformedProof("truncated value")
            }
            proof.value = Array(bytes[pos..<pos + valLen])
            pos += valLen
        }

        return proof
    }
}
