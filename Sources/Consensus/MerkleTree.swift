import Base
import ExtCrypto
import Protocol

/// Domain-separated merkle tree for block transaction and witness roots.
///
/// Fistbump uses a domain-separated merkle tree (RFC 6962) with BLAKE2b-256:
/// - Leaf nodes: `blake2b(0x00 || data)`
/// - Internal nodes: `blake2b(0x01 || left || right)`
/// - Odd nodes use a sentinel (`blake2b(empty)`) instead of duplicating
///
/// This prevents second-preimage attacks that affect Bitcoin's merkle tree.
/// Implementation matches `bcrypto/lib/mrkl.js` used by hsd.
public enum MerkleTree {

    /// Leaf prefix byte (domain separation).
    private static let leafPrefix: UInt8 = 0x00

    /// Internal node prefix byte (domain separation).
    private static let internalPrefix: UInt8 = 0x01

    /// Sentinel hash for odd-length levels: `blake2b(empty)`.
    private static let sentinel: Hash256 = {
        // blake2b-256 of empty input
        let bytes = try! Blake2bHash.hash([], size: 32)
        return Hash256(unchecked: bytes)
    }()

    /// Hash a leaf node: `blake2b(0x00 || data)`.
    private static func hashLeaf(_ data: Hash256) throws -> Hash256 {
        var buf = [UInt8]()
        buf.reserveCapacity(33)
        buf.append(leafPrefix)
        buf.append(contentsOf: data.bytes)
        return try Blake2bHash.hash256(buf)
    }

    /// Hash an internal node: `blake2b(0x01 || left || right)`.
    private static func hashInternal(_ left: Hash256, _ right: Hash256) throws -> Hash256 {
        var buf = [UInt8]()
        buf.reserveCapacity(65)
        buf.append(internalPrefix)
        buf.append(contentsOf: left.bytes)
        buf.append(contentsOf: right.bytes)
        return try Blake2bHash.hash256(buf)
    }

    /// Compute the merkle root of a list of hashes.
    ///
    /// Uses the domain-separated algorithm from RFC 6962:
    /// 1. Each leaf is hashed as `blake2b(0x00 || hash)`
    /// 2. Internal nodes are `blake2b(0x01 || left || right)`
    /// 3. Odd nodes pair with a sentinel (`blake2b(empty)`)
    ///
    /// - Parameter hashes: The leaf-level hashes (e.g., transaction IDs).
    /// - Returns: The 32-byte merkle root. Returns sentinel for empty input.
    public static func computeRoot(_ hashes: [Hash256]) throws -> Hash256 {
        guard !hashes.isEmpty else { return sentinel }

        // Hash all leaves with the 0x00 prefix
        var nodes = try hashes.map { try hashLeaf($0) }

        var size = nodes.count
        var i = 0

        while size > 1 {
            var j = 0
            while j < size {
                let left = nodes[i + j]
                let right: Hash256
                if j + 1 < size {
                    right = nodes[i + j + 1]
                } else {
                    right = sentinel
                }
                nodes.append(try hashInternal(left, right))
                j += 2
            }

            i += size
            size = (size + 1) >> 1
        }

        return nodes.last!
    }

    /// Compute the witness root for a list of transactions.
    ///
    /// Uses the full transaction hash (including witness data) as leaves.
    /// All transactions including coinbase use their actual witness hash.
    public static func computeWitnessRoot(_ txs: [WitnessHashable]) throws -> Hash256 {
        let hashes = txs.map { $0.witnessHash() }
        return try computeRoot(hashes)
    }

    /// Compute the witness root using pre-computed txHashes to avoid double serialization.
    public static func computeWitnessRoot(_ txs: [Transaction], txHashes: [Hash256]) throws -> Hash256 {
        let hashes = zip(txs, txHashes).map { $0.witnessHash(txHash: $1) }
        return try computeRoot(hashes)
    }
}
