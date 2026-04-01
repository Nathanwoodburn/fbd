import Foundation
import ExtCrypto
import Crypto
#if canImport(Security)
import Security
#endif
#if canImport(Glibc)
import Glibc
#endif

/// Wallet encryption using PBKDF2-SHA512 + ChaCha20-Poly1305.
///
/// Encrypts the combined wallet key material (seed + mnemonic + accountKey)
/// into a single authenticated blob for storage in metaDB.
enum WalletCrypto {

    /// Format version for the encrypted blob.
    private static let version: UInt8 = 1

    /// PBKDF2 iteration count (OWASP 2023 recommendation for SHA-512).
    static let kdfRounds = 600_000

    /// Encrypted payload layout:
    /// `[version:1][salt:32][nonce:12][ciphertext:var][tag:16]`
    struct EncryptedPayload {
        let version: UInt8
        let salt: [UInt8]      // 32 bytes
        let nonce: [UInt8]     // 12 bytes
        let ciphertext: [UInt8]
        let tag: [UInt8]       // 16 bytes

        func serialize() -> [UInt8] {
            var buf = [UInt8]()
            buf.reserveCapacity(1 + 32 + 12 + ciphertext.count + 16)
            buf.append(version)
            buf.append(contentsOf: salt)
            buf.append(contentsOf: nonce)
            buf.append(contentsOf: ciphertext)
            buf.append(contentsOf: tag)
            return buf
        }

        static func deserialize(_ data: [UInt8]) -> EncryptedPayload? {
            // Minimum: version(1) + salt(32) + nonce(12) + tag(16) = 61
            guard data.count >= 61 else { return nil }
            let version = data[0]
            guard version == WalletCrypto.version else { return nil }
            let salt = Array(data[1..<33])
            let nonce = Array(data[33..<45])
            let tag = Array(data[data.count - 16..<data.count])
            let ciphertext = Array(data[45..<data.count - 16])
            return EncryptedPayload(version: version, salt: salt, nonce: nonce,
                                    ciphertext: ciphertext, tag: tag)
        }
    }

    /// Plaintext payload layout:
    /// `[seedLen:2 LE][seed:var][mnemonicLen:2 LE][mnemonic:var][accountKeyLen:2 LE][accountKey:var]`
    struct KeyMaterial {
        let seed: [UInt8]?          // 64 bytes (nil for xpriv-only imports)
        let mnemonic: String?       // BIP39 phrase (nil for xpriv-only imports)
        let accountKey: [UInt8]?    // 73 bytes serialized ExtendedPrivateKey

        func serialize() -> [UInt8] {
            var buf = [UInt8]()
            buf.reserveCapacity(200)

            let seedBytes = seed ?? []
            let seedLen = UInt16(seedBytes.count)
            buf.append(UInt8(seedLen & 0xFF))
            buf.append(UInt8(seedLen >> 8))
            buf.append(contentsOf: seedBytes)

            let mnemonicBytes = mnemonic.map { Array($0.utf8) } ?? []
            let mnemonicLen = UInt16(mnemonicBytes.count)
            buf.append(UInt8(mnemonicLen & 0xFF))
            buf.append(UInt8(mnemonicLen >> 8))
            buf.append(contentsOf: mnemonicBytes)

            let akBytes = accountKey ?? []
            let akLen = UInt16(akBytes.count)
            buf.append(UInt8(akLen & 0xFF))
            buf.append(UInt8(akLen >> 8))
            buf.append(contentsOf: akBytes)

            return buf
        }

        static func deserialize(_ data: [UInt8]) -> KeyMaterial? {
            var offset = 0

            func readField() -> [UInt8]? {
                guard offset + 2 <= data.count else { return nil }
                let len = Int(UInt16(data[offset]) | UInt16(data[offset + 1]) << 8)
                offset += 2
                guard offset + len <= data.count else { return nil }
                let field = Array(data[offset..<offset + len])
                offset += len
                return field
            }

            guard let seedBytes = readField() else { return nil }
            guard let mnemonicBytes = readField() else { return nil }
            guard let akBytes = readField() else { return nil }

            return KeyMaterial(
                seed: seedBytes.isEmpty ? nil : seedBytes,
                mnemonic: mnemonicBytes.isEmpty ? nil : String(bytes: mnemonicBytes, encoding: .utf8),
                accountKey: akBytes.isEmpty ? nil : akBytes
            )
        }
    }

    /// Derive a 32-byte encryption key from a passphrase and salt.
    static func deriveKey(passphrase: String, salt: [UInt8]) -> [UInt8] {
        PBKDF2.sha512(
            password: Array(passphrase.utf8),
            salt: salt,
            rounds: kdfRounds,
            keyLength: 32
        )
    }

    /// Compute a verify token: BLAKE2b-256 of the derived key.
    static func verifyToken(_ encKey: [UInt8]) -> [UInt8] {
        // Blake2bHash.hash can only fail for invalid size params; 32 is always valid.
        try! Blake2bHash.hash(encKey, size: 32)
    }

    /// Encrypt key material with a passphrase.
    ///
    /// - Returns: `(encryptedBlob, verifyToken)` for storage.
    static func encrypt(material: KeyMaterial, passphrase: String) throws -> (blob: [UInt8], check: [UInt8]) {
        var salt = [UInt8](repeating: 0, count: 32)
        #if canImport(Security)
        let status = SecRandomCopyBytes(kSecRandomDefault, 32, &salt)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        #elseif os(Linux)
        guard let fp = fopen("/dev/urandom", "r") else {
            preconditionFailure("cannot open /dev/urandom")
        }
        defer { fclose(fp) }
        precondition(fread(&salt, 1, 32, fp) == 32, "/dev/urandom short read")
        #else
        for i in 0..<32 { salt[i] = UInt8.random(in: 0...255) }
        #endif

        let encKey = deriveKey(passphrase: passphrase, salt: salt)
        let check = verifyToken(encKey)

        let plaintext = material.serialize()

        let symmetricKey = SymmetricKey(data: encKey)
        let sealed = try ChaChaPoly.seal(plaintext, using: symmetricKey)

        let payload = EncryptedPayload(
            version: version,
            salt: salt,
            nonce: Array(sealed.nonce),
            ciphertext: Array(sealed.ciphertext),
            tag: Array(sealed.tag)
        )

        return (payload.serialize(), check)
    }

    /// Decrypt key material using a passphrase.
    ///
    /// - Throws: `WalletError.wrongPassphrase` if the passphrase is incorrect.
    /// Legacy PBKDF2 rounds used before the security audit increased to 600,000.
    private static let legacyKdfRounds = 100_000

    static func decrypt(blob: [UInt8], passphrase: String, expectedCheck: [UInt8]) throws -> KeyMaterial {
        guard let payload = EncryptedPayload.deserialize(blob) else {
            throw WalletError.databaseError("corrupt encrypted payload")
        }

        var encKey = deriveKey(passphrase: passphrase, salt: payload.salt)
        var check = verifyToken(encKey)

        // If current rounds don't match, try legacy rounds (wallet may have
        // been encrypted before the PBKDF2 iteration increase).
        if check != expectedCheck {
            encKey = PBKDF2.sha512(
                password: Array(passphrase.utf8),
                salt: payload.salt,
                rounds: legacyKdfRounds,
                keyLength: 32
            )
            check = verifyToken(encKey)
        }

        guard check == expectedCheck else {
            throw WalletError.wrongPassphrase
        }

        let symmetricKey = SymmetricKey(data: encKey)
        let nonce = try ChaChaPoly.Nonce(data: payload.nonce)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce,
                                                   ciphertext: payload.ciphertext,
                                                   tag: payload.tag)
        let plaintext = try ChaChaPoly.open(sealedBox, using: symmetricKey)

        guard let material = KeyMaterial.deserialize(Array(plaintext)) else {
            throw WalletError.databaseError("corrupt decrypted payload")
        }

        return material
    }
}
