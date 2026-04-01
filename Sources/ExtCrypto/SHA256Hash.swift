import Crypto
import Base

/// SHA-256 hashing utilities.
public enum SHA256Hash {
    /// Compute SHA-256 of the given data.
    public static func hash(_ data: [UInt8]) -> Hash256 {
        let digest = Crypto.SHA256.hash(data: data)
        return Hash256(unchecked: Array(digest))
    }

    /// Compute double SHA-256: SHA256(SHA256(data)).
    ///
    /// Used in Bitcoin-derived protocols for transaction IDs and merkle trees.
    public static func doubleHash(_ data: [UInt8]) -> Hash256 {
        let first = Crypto.SHA256.hash(data: data)
        let second = Crypto.SHA256.hash(data: Array(first))
        return Hash256(unchecked: Array(second))
    }

    /// Compute HMAC-SHA256.
    public static func hmac(key: [UInt8], data: [UInt8]) -> Hash256 {
        let symmetricKey = SymmetricKey(data: key)
        let mac = Crypto.HMAC<Crypto.SHA256>.authenticationCode(for: data, using: symmetricKey)
        return Hash256(unchecked: Array(mac))
    }
}
