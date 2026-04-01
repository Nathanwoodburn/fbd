/// PBKDF2 key derivation using HMAC-SHA512.
///
/// Self-contained implementation that avoids _CryptoExtras import issues
/// with minimum round requirements.
public enum PBKDF2 {
    /// Derive a key using PBKDF2 with HMAC-SHA512.
    ///
    /// - Parameters:
    ///   - password: The password bytes.
    ///   - salt: The salt bytes.
    ///   - rounds: Number of iterations (BIP39 uses 2048).
    ///   - keyLength: Desired output length in bytes (BIP39 uses 64).
    /// - Returns: The derived key bytes.
    public static func sha512(password: [UInt8], salt: [UInt8], rounds: Int, keyLength: Int) -> [UInt8] {
        let hLen = 64 // HMAC-SHA512 output length
        let blockCount = (keyLength + hLen - 1) / hLen
        var result = [UInt8]()
        result.reserveCapacity(keyLength)

        for blockIndex in 1...blockCount {
            // U1 = PRF(password, salt || INT(blockIndex))
            let blockBytes: [UInt8] = [
                UInt8((blockIndex >> 24) & 0xFF),
                UInt8((blockIndex >> 16) & 0xFF),
                UInt8((blockIndex >> 8) & 0xFF),
                UInt8(blockIndex & 0xFF),
            ]
            var u = SHA512Hash.hmac(key: password, data: salt + blockBytes)
            var t = u

            // U2...Uc
            for _ in 1..<rounds {
                u = SHA512Hash.hmac(key: password, data: u)
                for j in 0..<hLen {
                    t[j] ^= u[j]
                }
            }

            result.append(contentsOf: t)
        }

        return Array(result.prefix(keyLength))
    }
}
