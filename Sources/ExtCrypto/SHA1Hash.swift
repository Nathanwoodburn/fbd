import Crypto

/// SHA-1 hash (needed for OP_SHA1, not used for security purposes).
public enum SHA1Hash {
    /// Compute the SHA-1 hash (20 bytes) of the input data.
    public static func hash(_ data: [UInt8]) -> [UInt8] {
        Array(Insecure.SHA1.hash(data: data))
    }
}
