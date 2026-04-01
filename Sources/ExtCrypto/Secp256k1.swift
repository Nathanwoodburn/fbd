import CSecp256k1
import Base
#if canImport(Security)
import Security
#elseif canImport(Android)
import Android
#elseif canImport(Glibc)
import Glibc
#elseif canImport(WinSDK)
import WinSDK
#endif

/// Module-level secp256k1 context (thread-safe for signing + verification).
private let ctx = secp256k1_context_create(
    UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
)!

/// secp256k1 ECDSA signing and verification.
///
/// Uses the raw C secp256k1 API for sign/verify to avoid the Swift wrapper's
/// `DataProtocol` overloads which add an unwanted SHA256 hash.
public enum ECDSASigner {

    // MARK: - Key Generation

    /// Generate a new random private key (32 bytes).
    public static func generatePrivateKey() throws -> PrivateKey {
        var key = [UInt8](repeating: 0, count: 32)
        while true {
            #if canImport(Security)
            guard SecRandomCopyBytes(kSecRandomDefault, 32, &key) == errSecSuccess else {
                throw CryptoError.signingFailed
            }
            #elseif canImport(Android) || canImport(Glibc)
            guard let fp = fopen("/dev/urandom", "r") else {
                throw CryptoError.signingFailed
            }
            defer { fclose(fp) }
            guard fread(&key, 1, 32, fp) == 32 else {
                throw CryptoError.signingFailed
            }
            #elseif canImport(WinSDK)
            guard BCryptGenRandom(nil, &key, 32, ULONG(BCRYPT_USE_SYSTEM_PREFERRED_RNG)) == 0 else {
                throw CryptoError.signingFailed
            }
            #endif
            if secp256k1_ec_seckey_verify(ctx, key) == 1 {
                return PrivateKey(unchecked: key)
            }
        }
    }

    /// Derive the compressed public key (33 bytes) from a private key.
    public static func publicKey(from privateKey: PrivateKey) throws -> PublicKey {
        var pubkey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey.bytes) == 1 else {
            throw CryptoError.invalidPrivateKey
        }
        var output = [UInt8](repeating: 0, count: 33)
        var outputLen = 33
        guard secp256k1_ec_pubkey_serialize(
            ctx, &output, &outputLen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED)
        ) == 1 else {
            throw CryptoError.invalidPrivateKey
        }
        return PublicKey(unchecked: output)
    }

    /// Derive the compressed public key (33 bytes) from raw private key bytes.
    ///
    /// Convenience overload for callers that have raw `[UInt8]` key material
    /// (e.g. BIP32 internal derivation).
    public static func publicKey(from privateKeyBytes: [UInt8]) throws -> PublicKey {
        var pubkey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_create(ctx, &pubkey, privateKeyBytes) == 1 else {
            throw CryptoError.invalidPrivateKey
        }
        var output = [UInt8](repeating: 0, count: 33)
        var outputLen = 33
        guard secp256k1_ec_pubkey_serialize(
            ctx, &output, &outputLen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED)
        ) == 1 else {
            throw CryptoError.invalidPrivateKey
        }
        return PublicKey(unchecked: output)
    }

    /// Derive the uncompressed public key (65 bytes) from a private key.
    public static func uncompressedPublicKey(from privateKey: PrivateKey) throws -> [UInt8] {
        var pubkey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey.bytes) == 1 else {
            throw CryptoError.invalidPrivateKey
        }
        var output = [UInt8](repeating: 0, count: 65)
        var outputLen = 65
        guard secp256k1_ec_pubkey_serialize(
            ctx, &output, &outputLen, &pubkey, UInt32(SECP256K1_EC_UNCOMPRESSED)
        ) == 1 else {
            throw CryptoError.invalidPrivateKey
        }
        return output
    }

    // MARK: - Signing (raw C API)

    /// Sign a 32-byte message hash with a private key, returning a compact (64-byte) signature.
    ///
    /// Uses the raw C `secp256k1_ecdsa_sign` directly to ensure the hash bytes
    /// are passed as-is (no additional SHA256 hashing).
    public static func sign(hash: Hash256, privateKey: PrivateKey) throws -> [UInt8] {
        var sig = secp256k1_ecdsa_signature()

        guard secp256k1_ecdsa_sign(
            ctx,
            &sig,
            hash.bytes,
            privateKey.bytes,
            nil,
            nil
        ) == 1 else {
            throw CryptoError.signingFailed
        }

        // Normalize to low-S form (BIP 62 / consensus rule)
        var normalizedCompactSig = secp256k1_ecdsa_signature()
        secp256k1_ecdsa_signature_normalize(ctx, &normalizedCompactSig, &sig)
        sig = normalizedCompactSig

        // Serialize to compact format (64 bytes)
        var compact = [UInt8](repeating: 0, count: 64)
        guard secp256k1_ecdsa_signature_serialize_compact(
            ctx,
            &compact,
            &sig
        ) == 1 else {
            throw CryptoError.signingFailed
        }

        return compact
    }

    /// Sign a 32-byte message hash, returning a DER-encoded signature.
    public static func signDER(hash: Hash256, privateKey: PrivateKey) throws -> [UInt8] {
        var sig = secp256k1_ecdsa_signature()

        guard secp256k1_ecdsa_sign(
            ctx,
            &sig,
            hash.bytes,
            privateKey.bytes,
            nil,
            nil
        ) == 1 else {
            throw CryptoError.signingFailed
        }

        // Normalize to low-S form (BIP 62 / consensus rule)
        var normalizedDERSig = secp256k1_ecdsa_signature()
        secp256k1_ecdsa_signature_normalize(ctx, &normalizedDERSig, &sig)
        sig = normalizedDERSig

        // Serialize to DER format
        var derSig = [UInt8](repeating: 0, count: 80)
        var derLen = 80

        guard secp256k1_ecdsa_signature_serialize_der(
            ctx,
            &derSig,
            &derLen,
            &sig
        ) == 1 else {
            throw CryptoError.signingFailed
        }

        return Array(derSig.prefix(derLen))
    }

    // MARK: - Verification (raw C API)

    /// Verify a compact (64-byte) ECDSA signature against a message hash and public key.
    ///
    /// Uses the raw C `secp256k1_ecdsa_verify` directly to ensure the hash bytes
    /// are passed as-is (no additional SHA256 hashing).
    public static func verify(signature: [UInt8], hash: Hash256, publicKey: PublicKey) throws -> Bool {
        // Parse public key
        var pubkey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_parse(
            ctx,
            &pubkey,
            publicKey.bytes,
            publicKey.bytes.count
        ) == 1 else {
            throw CryptoError.invalidSignature
        }

        // Parse compact signature
        var sig = secp256k1_ecdsa_signature()
        guard secp256k1_ecdsa_signature_parse_compact(
            ctx,
            &sig,
            signature
        ) == 1 else {
            throw CryptoError.invalidSignature
        }

        // Reject high-S signatures (consensus rule — must already be low-S)
        var normalizedSig = secp256k1_ecdsa_signature()
        if secp256k1_ecdsa_signature_normalize(ctx, &normalizedSig, &sig) == 1 {
            return false
        }

        return secp256k1_ecdsa_verify(ctx, &sig, hash.bytes, &pubkey) == 1
    }

    /// Verify a DER-encoded ECDSA signature against a message hash and public key.
    public static func verifyDER(signature: [UInt8], hash: Hash256, publicKey: PublicKey) throws -> Bool {
        // Parse public key
        var pubkey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_parse(
            ctx,
            &pubkey,
            publicKey.bytes,
            publicKey.bytes.count
        ) == 1 else {
            throw CryptoError.invalidSignature
        }

        // Parse DER signature
        var sig = secp256k1_ecdsa_signature()
        guard secp256k1_ecdsa_signature_parse_der(
            ctx,
            &sig,
            signature,
            signature.count
        ) == 1 else {
            throw CryptoError.invalidSignature
        }

        // Reject high-S signatures (consensus rule — must already be low-S)
        var normalizedSig = secp256k1_ecdsa_signature()
        if secp256k1_ecdsa_signature_normalize(ctx, &normalizedSig, &sig) == 1 {
            return false
        }

        return secp256k1_ecdsa_verify(ctx, &sig, hash.bytes, &pubkey) == 1
    }

    // MARK: - Recoverable Signatures (raw C API)

    /// Sign a 32-byte message hash with a private key, returning a recoverable signature.
    ///
    /// Returns 65 bytes: [recovery_id (1 byte)] + [compact signature (64 bytes)].
    public static func signRecoverable(hash: Hash256, privateKey: PrivateKey) throws -> [UInt8] {
        var rsig = secp256k1_ecdsa_recoverable_signature()

        guard secp256k1_ecdsa_sign_recoverable(
            ctx,
            &rsig,
            hash.bytes,
            privateKey.bytes,
            nil,
            nil
        ) == 1 else {
            throw CryptoError.signingFailed
        }

        var compact = [UInt8](repeating: 0, count: 64)
        var recid: Int32 = 0
        guard secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx,
            &compact,
            &recid,
            &rsig
        ) == 1 else {
            throw CryptoError.signingFailed
        }

        // Prepend recovery ID byte
        var result = [UInt8(recid)]
        result.append(contentsOf: compact)
        return result
    }

    /// Recover a compressed public key (33 bytes) from a recoverable signature.
    ///
    /// Input: 65 bytes [recovery_id (1 byte)] + [compact signature (64 bytes)].
    /// Returns the 33-byte compressed public key, or nil if recovery fails.
    public static func recoverPublicKey(signature: [UInt8], hash: Hash256) -> PublicKey? {
        guard signature.count == 65 else { return nil }

        let recid = Int32(signature[0])
        guard recid >= 0 && recid <= 3 else { return nil }
        let compact = Array(signature[1...])

        var rsig = secp256k1_ecdsa_recoverable_signature()
        guard secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx,
            &rsig,
            compact,
            recid
        ) == 1 else { return nil }

        var pubkey = secp256k1_pubkey()
        guard secp256k1_ecdsa_recover(
            ctx,
            &pubkey,
            &rsig,
            hash.bytes
        ) == 1 else { return nil }

        // Serialize to compressed format
        var output = [UInt8](repeating: 0, count: 33)
        var outputLen = 33
        guard secp256k1_ec_pubkey_serialize(
            ctx, &output, &outputLen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED)
        ) == 1 else { return nil }

        return PublicKey(unchecked: output)
    }

    // MARK: - BIP32 Key Tweaking (raw C API)

    /// Add a 32-byte scalar tweak to a private key (mod curve order).
    ///
    /// Used by BIP32 child key derivation: child_key = parent_key + tweak.
    /// Returns `nil` if the result is invalid (zero or overflow).
    public static func tweakAddPrivateKey(_ key: [UInt8], tweak: [UInt8]) -> [UInt8]? {
        guard key.count == 32, tweak.count == 32 else { return nil }
        var result = key
        let rc = secp256k1_ec_seckey_tweak_add(ctx, &result, tweak)
        guard rc == 1 else { return nil }
        return result
    }

    /// Add tweak*G to a compressed public key (EC point addition).
    ///
    /// Used by BIP32 public child key derivation.
    /// Returns `nil` if the result is the point at infinity.
    public static func tweakAddPublicKey(_ key: [UInt8], tweak: [UInt8]) -> [UInt8]? {
        guard key.count == 33, tweak.count == 32 else { return nil }

        // Parse compressed public key
        var pubkey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_parse(ctx, &pubkey, key, key.count) == 1 else {
            return nil
        }

        // Add tweak
        guard secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak) == 1 else {
            return nil
        }

        // Serialize back to compressed format
        var output = [UInt8](repeating: 0, count: 33)
        var outputLen = 33
        guard secp256k1_ec_pubkey_serialize(
            ctx, &output, &outputLen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED)
        ) == 1 else {
            return nil
        }

        return output
    }
}
