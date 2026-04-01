import Base

/// BIP32 HD (Hierarchical Deterministic) key derivation.

/// An extended private key for BIP32 child key derivation.
public struct ExtendedPrivateKey: Sendable {
    /// The 32-byte private key.
    public let key: [UInt8]

    /// The 32-byte chain code.
    public let chainCode: [UInt8]

    /// Depth in the derivation tree (0 = master).
    public let depth: UInt8

    /// First 4 bytes of the parent key's identifier (0 for master).
    public let fingerprint: UInt32

    /// The child index (0 for master).
    public let index: UInt32

    public init(key: [UInt8], chainCode: [UInt8], depth: UInt8, fingerprint: UInt32, index: UInt32) {
        self.key = key
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.index = index
    }

    /// Derive the master key from a BIP39 seed.
    ///
    /// Uses HMAC-SHA512 with key "Bitcoin seed".
    public static func fromSeed(_ seed: [UInt8]) -> ExtendedPrivateKey {
        let hmac = SHA512Hash.hmac(key: Array("Bitcoin seed".utf8), data: seed)
        return ExtendedPrivateKey(
            key: Array(hmac[0..<32]),
            chainCode: Array(hmac[32..<64]),
            depth: 0,
            fingerprint: 0,
            index: 0
        )
    }

    /// Derive a child key at the given index.
    ///
    /// If `index >= 0x80000000`, this performs hardened derivation.
    public func derive(_ childIndex: UInt32) throws -> ExtendedPrivateKey {
        guard depth < 255 else {
            throw BIP32Error.invalidPath("maximum derivation depth (255) exceeded")
        }

        var data = [UInt8]()
        data.reserveCapacity(37)

        if childIndex >= 0x8000_0000 {
            // Hardened: 0x00 || ser256(key) || ser32(index)
            data.append(0x00)
            data.append(contentsOf: key)
        } else {
            // Normal: serP(point(key)) || ser32(index)
            let pubKey = try ECDSASigner.publicKey(from: key)
            data.append(contentsOf: pubKey.bytes)
        }

        data.append(UInt8((childIndex >> 24) & 0xFF))
        data.append(UInt8((childIndex >> 16) & 0xFF))
        data.append(UInt8((childIndex >> 8) & 0xFF))
        data.append(UInt8(childIndex & 0xFF))

        let hmac = SHA512Hash.hmac(key: chainCode, data: data)
        let il = Array(hmac[0..<32])
        let ir = Array(hmac[32..<64])

        guard let childKey = ECDSASigner.tweakAddPrivateKey(key, tweak: il) else {
            throw BIP32Error.invalidChild
        }

        // Fingerprint = first 4 bytes of Hash160(parentPubKey)
        let parentPub = try ECDSASigner.publicKey(from: key)
        let parentId = keyIdentifier(parentPub.bytes)
        let fp = UInt32(parentId[0]) << 24
            | UInt32(parentId[1]) << 16
            | UInt32(parentId[2]) << 8
            | UInt32(parentId[3])

        return ExtendedPrivateKey(
            key: childKey,
            chainCode: ir,
            depth: depth + 1,
            fingerprint: fp,
            index: childIndex
        )
    }

    /// Derive a child key from a BIP32 path string (e.g., "m/44'/0'/0'/0/0").
    public func derivePath(_ path: String) throws -> ExtendedPrivateKey {
        var components = path.split(separator: "/").map(String.init)
        if components.first == "m" {
            components.removeFirst()
        }

        var current = self
        for component in components {
            let hardened = component.hasSuffix("'")
            let indexStr = hardened ? String(component.dropLast()) : component
            guard let idx = UInt32(indexStr) else {
                throw BIP32Error.invalidPath(path)
            }
            let childIndex = hardened ? idx | 0x8000_0000 : idx
            current = try current.derive(childIndex)
        }
        return current
    }

    /// Get the corresponding extended public key.
    public func publicKey() throws -> ExtendedPublicKey {
        let pub = try ECDSASigner.publicKey(from: key)
        return ExtendedPublicKey(
            key: pub.bytes,
            chainCode: chainCode,
            depth: depth,
            fingerprint: fingerprint,
            index: index
        )
    }

    /// Serialize as a Base58Check-encoded xpriv string (BIP32).
    ///
    /// Uses version bytes 0x0488ADE4 (Bitcoin mainnet).
    public func serialized() -> String {
        var data = [UInt8]()
        data.reserveCapacity(78)
        // 4 bytes: version (xprv)
        data.append(contentsOf: [0x04, 0x88, 0xAD, 0xE4])
        // 1 byte: depth
        data.append(depth)
        // 4 bytes: fingerprint
        data.append(UInt8((fingerprint >> 24) & 0xFF))
        data.append(UInt8((fingerprint >> 16) & 0xFF))
        data.append(UInt8((fingerprint >> 8) & 0xFF))
        data.append(UInt8(fingerprint & 0xFF))
        // 4 bytes: child index
        data.append(UInt8((index >> 24) & 0xFF))
        data.append(UInt8((index >> 16) & 0xFF))
        data.append(UInt8((index >> 8) & 0xFF))
        data.append(UInt8(index & 0xFF))
        // 32 bytes: chain code
        data.append(contentsOf: chainCode)
        // 33 bytes: 0x00 || private key
        data.append(0x00)
        data.append(contentsOf: key)
        // 4-byte checksum (first 4 bytes of double-SHA256)
        let checksum = SHA256Hash.doubleHash(data)
        data.append(contentsOf: checksum.bytes[0..<4])
        return base58Encode(data)
    }

    /// Deserialize a Base58Check-encoded xpriv string.
    ///
    /// Expects version bytes 0x0488ADE4 and 82-byte payload (78 + 4 checksum).
    public static func deserialize(_ xpriv: String) throws -> ExtendedPrivateKey {
        guard let raw = base58Decode(xpriv) else {
            throw BIP32Error.invalidXpriv
        }
        guard raw.count == 82 else {
            throw BIP32Error.invalidXpriv
        }
        // Verify checksum
        let payload = Array(raw[0..<78])
        let checksum = SHA256Hash.doubleHash(payload)
        guard raw[78] == checksum.bytes[0],
              raw[79] == checksum.bytes[1],
              raw[80] == checksum.bytes[2],
              raw[81] == checksum.bytes[3] else {
            throw BIP32Error.invalidXpriv
        }
        // Verify version bytes (0x0488ADE4 = xprv)
        guard raw[0] == 0x04, raw[1] == 0x88, raw[2] == 0xAD, raw[3] == 0xE4 else {
            throw BIP32Error.invalidXpriv
        }
        let depth = raw[4]
        let fingerprint = UInt32(raw[5]) << 24 | UInt32(raw[6]) << 16
            | UInt32(raw[7]) << 8 | UInt32(raw[8])
        let index = UInt32(raw[9]) << 24 | UInt32(raw[10]) << 16
            | UInt32(raw[11]) << 8 | UInt32(raw[12])
        let chainCode = Array(raw[13..<45])
        // Byte 45 must be 0x00 (private key padding)
        guard raw[45] == 0x00 else {
            throw BIP32Error.invalidXpriv
        }
        let key = Array(raw[46..<78])
        return ExtendedPrivateKey(
            key: key, chainCode: chainCode,
            depth: depth, fingerprint: fingerprint, index: index
        )
    }

    /// The compressed public key for this private key.
    public var compressedPublicKey: PublicKey {
        get throws {
            try ECDSASigner.publicKey(from: key)
        }
    }
}

/// An extended public key for BIP32 public child derivation.
public struct ExtendedPublicKey: Sendable {
    /// The 33-byte compressed public key.
    public let key: [UInt8]

    /// The 32-byte chain code.
    public let chainCode: [UInt8]

    /// Depth in the derivation tree.
    public let depth: UInt8

    /// First 4 bytes of the parent key's identifier.
    public let fingerprint: UInt32

    /// The child index.
    public let index: UInt32

    /// Serialize as a Base58Check-encoded xpub string (BIP32).
    ///
    /// Uses version bytes 0x0488B21E (Bitcoin mainnet).
    public func serialized() -> String {
        var data = [UInt8]()
        data.reserveCapacity(78)
        // 4 bytes: version
        data.append(contentsOf: [0x04, 0x88, 0xB2, 0x1E])
        // 1 byte: depth
        data.append(depth)
        // 4 bytes: fingerprint
        data.append(UInt8((fingerprint >> 24) & 0xFF))
        data.append(UInt8((fingerprint >> 16) & 0xFF))
        data.append(UInt8((fingerprint >> 8) & 0xFF))
        data.append(UInt8(fingerprint & 0xFF))
        // 4 bytes: child index
        data.append(UInt8((index >> 24) & 0xFF))
        data.append(UInt8((index >> 16) & 0xFF))
        data.append(UInt8((index >> 8) & 0xFF))
        data.append(UInt8(index & 0xFF))
        // 32 bytes: chain code
        data.append(contentsOf: chainCode)
        // 33 bytes: public key
        data.append(contentsOf: key)
        // 4-byte checksum (first 4 bytes of double-SHA256)
        let checksum = SHA256Hash.doubleHash(data)
        data.append(contentsOf: checksum.bytes[0..<4])
        return base58Encode(data)
    }

    /// Deserialize a Base58Check-encoded xpub string.
    ///
    /// Expects version bytes 0x0488B21E and 82-byte payload (78 + 4 checksum).
    public static func deserialize(_ xpub: String) throws -> ExtendedPublicKey {
        guard let raw = base58Decode(xpub) else {
            throw BIP32Error.invalidXpub
        }
        guard raw.count == 82 else {
            throw BIP32Error.invalidXpub
        }
        // Verify checksum
        let payload = Array(raw[0..<78])
        let checksum = SHA256Hash.doubleHash(payload)
        guard raw[78] == checksum.bytes[0],
              raw[79] == checksum.bytes[1],
              raw[80] == checksum.bytes[2],
              raw[81] == checksum.bytes[3] else {
            throw BIP32Error.invalidXpub
        }
        // Verify version bytes (0x0488B21E = xpub)
        guard raw[0] == 0x04, raw[1] == 0x88, raw[2] == 0xB2, raw[3] == 0x1E else {
            throw BIP32Error.invalidXpub
        }
        let depth = raw[4]
        let fingerprint = UInt32(raw[5]) << 24 | UInt32(raw[6]) << 16
            | UInt32(raw[7]) << 8 | UInt32(raw[8])
        let index = UInt32(raw[9]) << 24 | UInt32(raw[10]) << 16
            | UInt32(raw[11]) << 8 | UInt32(raw[12])
        let chainCode = Array(raw[13..<45])
        let key = Array(raw[45..<78])
        // Verify it's a valid compressed public key (02 or 03 prefix)
        guard key.count == 33, (key[0] == 0x02 || key[0] == 0x03) else {
            throw BIP32Error.invalidXpub
        }
        return ExtendedPublicKey(
            key: key, chainCode: chainCode,
            depth: depth, fingerprint: fingerprint, index: index
        )
    }

    /// Derive a child public key from a path string (e.g., "0/5").
    ///
    /// Only non-hardened derivation is supported from a public key.
    public func derivePath(_ path: String) throws -> ExtendedPublicKey {
        var components = path.split(separator: "/").map(String.init)
        if components.first == "m" {
            components.removeFirst()
        }

        var current = self
        for component in components {
            guard !component.hasSuffix("'") else {
                throw BIP32Error.hardenedFromPublic
            }
            guard let idx = UInt32(component) else {
                throw BIP32Error.invalidPath(path)
            }
            current = try current.derive(idx)
        }
        return current
    }

    /// Derive a non-hardened child public key.
    ///
    /// Hardened derivation (index >= 0x80000000) is not possible from a public key.
    public func derive(_ childIndex: UInt32) throws -> ExtendedPublicKey {
        guard childIndex < 0x8000_0000 else {
            throw BIP32Error.hardenedFromPublic
        }

        var data = [UInt8]()
        data.reserveCapacity(37)
        data.append(contentsOf: key)
        data.append(UInt8((childIndex >> 24) & 0xFF))
        data.append(UInt8((childIndex >> 16) & 0xFF))
        data.append(UInt8((childIndex >> 8) & 0xFF))
        data.append(UInt8(childIndex & 0xFF))

        guard depth < 255 else {
            throw BIP32Error.invalidPath("maximum derivation depth (255) exceeded")
        }

        let hmac = SHA512Hash.hmac(key: chainCode, data: data)
        let il = Array(hmac[0..<32])
        let ir = Array(hmac[32..<64])

        guard let childKey = ECDSASigner.tweakAddPublicKey(key, tweak: il) else {
            throw BIP32Error.invalidChild
        }

        let parentId = keyIdentifier(key)
        let fp = UInt32(parentId[0]) << 24
            | UInt32(parentId[1]) << 16
            | UInt32(parentId[2]) << 8
            | UInt32(parentId[3])

        return ExtendedPublicKey(
            key: childKey,
            chainCode: ir,
            depth: depth + 1,
            fingerprint: fp,
            index: childIndex
        )
    }
}

/// BIP32 errors.
public enum BIP32Error: Error, Sendable {
    case invalidChild
    case hardenedFromPublic
    case invalidPath(String)
    case invalidXpriv
    case invalidXpub
}

/// Compute the key identifier: BLAKE2b-160 of the compressed public key.
///
/// Handshake uses BLAKE2b-160 for address hashes (not RIPEMD160(SHA256(x))).
private func keyIdentifier(_ pubKey: [UInt8]) -> [UInt8] {
    do {
        return try Blake2bHash.hash(pubKey, size: 20)
    } catch {
        // BLAKE2b should not fail for valid inputs
        return [UInt8](repeating: 0, count: 20)
    }
}
