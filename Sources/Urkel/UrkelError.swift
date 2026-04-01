/// Errors that can occur during Urkel trie operations.
public enum UrkelError: Error, Equatable, Sendable {
    /// The key size is not 32 bytes.
    case invalidKeySize(Int)

    /// The value exceeds the maximum allowed size.
    case valueTooLarge(Int)

    /// The proof is structurally invalid.
    case malformedProof(String)

    /// The proof verification failed (hash mismatch at root).
    case proofHashMismatch

    /// The proof claims the same key exists (collision proof invalid).
    case proofSameKey

    /// The proof claims the same path (short proof invalid).
    case proofSamePath

    /// Negative depth encountered during proof verification.
    case proofNegativeDepth

    /// The proof path does not match the key at the expected depth.
    case proofPathMismatch

    /// The proof did not fully consume all depth levels.
    case proofTooDeep

    /// An unexpected node type was encountered.
    case unexpectedNodeType

    /// Serialized tree data is corrupted or truncated.
    case corruptedData

    /// A `.hash` node was accessed without a resolver to load the full node.
    case unresolvedNode

    /// An internal consistency violation that should never occur.
    case internalError(String)
}
