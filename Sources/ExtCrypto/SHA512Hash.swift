import Crypto

/// SHA-512 hashing utilities.
public enum SHA512Hash {
    /// Compute HMAC-SHA512, returning 64 bytes.
    public static func hmac(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: key)
        let mac = Crypto.HMAC<Crypto.SHA512>.authenticationCode(for: data, using: symmetricKey)
        return Array(mac)
    }
}
