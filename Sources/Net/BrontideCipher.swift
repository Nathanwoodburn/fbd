import Base
import ExtCrypto
import Crypto

/// HKDF-SHA256 expand operation — derives two 32-byte keys.
///
/// Uses HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)
/// with SHA-256 as the underlying hash.
public enum HKDF256 {
    /// Extract and expand a secret into two 32-byte keys.
    ///
    /// - Parameters:
    ///   - secret: The input key material.
    ///   - salt: The salt (chaining key in Noise).
    /// - Returns: A tuple of two 32-byte keys (k1, k2).
    public static func expand(secret: [UInt8], salt: [UInt8]) -> ([UInt8], [UInt8]) {
        let symmetricSalt = SymmetricKey(data: salt)
        let prk = Crypto.HMAC<Crypto.SHA256>.authenticationCode(
            for: secret,
            using: symmetricSalt
        )
        let prkData = Array(prk)
        let prkKey = SymmetricKey(data: prkData)

        // Expand: T1 = HMAC(PRK, 0x01)
        let t1 = Crypto.HMAC<Crypto.SHA256>.authenticationCode(
            for: [0x01],
            using: prkKey
        )
        let t1Data = Array(t1)

        // T2 = HMAC(PRK, T1 || 0x02)
        let t2 = Crypto.HMAC<Crypto.SHA256>.authenticationCode(
            for: t1Data + [0x02],
            using: prkKey
        )
        let t2Data = Array(t2)

        return (t1Data, t2Data)
    }
}

/// ChaCha20-Poly1305 AEAD cipher state for Brontide.
///
/// Manages a symmetric key, nonce counter, and salt for the
/// encrypted transport layer. Automatically rotates keys after
/// every 1000 encrypt/decrypt operations.
public struct CipherState: Sendable {
    /// The current nonce counter.
    public var nonce: UInt32 = 0

    /// The 12-byte IV (nonce written at bytes 4..8).
    public var iv: [UInt8] = [UInt8](repeating: 0, count: 12)

    /// The 32-byte symmetric encryption key.
    public var key: [UInt8] = [UInt8](repeating: 0, count: 32)

    /// The 32-byte salt for key rotation.
    public var salt: [UInt8] = [UInt8](repeating: 0, count: 32)

    public init() {}

    // MARK: - Nonce Management

    /// Update the IV with the current nonce value (LE at offset 4).
    mutating func update() {
        iv[4] = UInt8(nonce & 0xFF)
        iv[5] = UInt8((nonce >> 8) & 0xFF)
        iv[6] = UInt8((nonce >> 16) & 0xFF)
        iv[7] = UInt8((nonce >> 24) & 0xFF)
    }

    /// Initialize the key and reset the nonce.
    public mutating func initKey(_ newKey: [UInt8]) {
        key = newKey
        nonce = 0
        update()
    }

    /// Initialize both salt and key.
    public mutating func initSalt(_ newKey: [UInt8], _ newSalt: [UInt8]) {
        salt = newSalt
        initKey(newKey)
    }

    /// Rotate the key using HKDF.
    mutating func rotateKey() {
        let (newSalt, newKey) = HKDF256.expand(secret: key, salt: salt)
        salt = newSalt
        initKey(newKey)
    }

    // MARK: - Encrypt / Decrypt

    /// Encrypt plaintext in-place and return the 16-byte authentication tag.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt (modified in-place to ciphertext).
    ///   - ad: Additional authenticated data.
    /// - Returns: The 16-byte Poly1305 tag.
    public mutating func encrypt(_ plaintext: inout [UInt8], ad: [UInt8] = []) throws -> [UInt8] {
        let symmetricKey = Crypto.SymmetricKey(data: key)
        let nonceData = try Crypto.ChaChaPoly.Nonce(data: iv)
        let sealed = try Crypto.ChaChaPoly.seal(
            plaintext,
            using: symmetricKey,
            nonce: nonceData,
            authenticating: ad
        )
        plaintext = Array(sealed.ciphertext)
        let tag = Array(sealed.tag)

        nonce += 1
        update()
        if nonce >= NetConstants.rotationInterval {
            rotateKey()
        }
        return tag
    }

    /// Decrypt ciphertext in-place, verifying the authentication tag.
    ///
    /// - Parameters:
    ///   - ciphertext: The data to decrypt (modified in-place to plaintext).
    ///   - tag: The 16-byte Poly1305 tag.
    ///   - ad: Additional authenticated data.
    /// - Returns: `true` if decryption succeeded, `false` if tag is invalid.
    public mutating func decrypt(_ ciphertext: inout [UInt8], tag: [UInt8], ad: [UInt8] = []) -> Bool {
        let symmetricKey = Crypto.SymmetricKey(data: key)
        do {
            let nonceData = try Crypto.ChaChaPoly.Nonce(data: iv)
            let sealedBox = try Crypto.ChaChaPoly.SealedBox(
                nonce: nonceData,
                ciphertext: ciphertext,
                tag: tag
            )
            let decrypted = try Crypto.ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: ad)
            ciphertext = Array(decrypted)
        } catch {
            return false
        }

        nonce += 1
        update()
        if nonce >= NetConstants.rotationInterval {
            rotateKey()
        }
        return true
    }
}

/// Noise symmetric state — extends CipherState with handshake digest tracking.
public struct SymmetricState: Sendable {
    /// The underlying cipher state.
    public var cipher: CipherState

    /// The chaining key.
    public var chain: [UInt8]

    /// The handshake digest (h).
    public var digest: [UInt8]

    public init() {
        cipher = CipherState()
        chain = [UInt8](repeating: 0, count: 32)
        digest = [UInt8](repeating: 0, count: 32)
    }

    /// Initialize the symmetric state with the protocol name.
    public mutating func initProtocol(_ name: String) {
        let nameBytes = Array(name.utf8)
        digest = Array(SHA256Hash.hash(nameBytes).bytes)
        chain = digest
        cipher.initKey([UInt8](repeating: 0, count: 32))
    }

    /// Mix a key into the chaining key and cipher.
    public mutating func mixKey(_ input: [UInt8]) {
        let (newChain, temp) = HKDF256.expand(secret: input, salt: chain)
        chain = newChain
        cipher.initKey(temp)
    }

    /// Mix data (and optional tag) into the handshake digest.
    public mutating func mixHash(_ data: [UInt8], tag: [UInt8] = []) {
        digest = Array(SHA256Hash.hash(digest + data + tag).bytes)
    }

    /// Compute a prospective digest (without modifying state).
    func mixDigest(_ data: [UInt8], tag: [UInt8] = []) -> [UInt8] {
        Array(SHA256Hash.hash(digest + data + tag).bytes)
    }

    /// Encrypt plaintext using the digest as additional data, then mix the result.
    public mutating func encryptHash(_ plaintext: inout [UInt8]) throws -> [UInt8] {
        let tag = try cipher.encrypt(&plaintext, ad: digest)
        mixHash(plaintext, tag: tag)
        return tag
    }

    /// Decrypt ciphertext using the digest as additional data, then mix the result.
    public mutating func decryptHash(_ ciphertext: inout [UInt8], tag: [UInt8]) -> Bool {
        let newDigest = mixDigest(ciphertext, tag: tag)
        guard cipher.decrypt(&ciphertext, tag: tag, ad: digest) else {
            return false
        }
        digest = newDigest
        return true
    }
}
