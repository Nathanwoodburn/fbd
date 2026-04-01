import CSecp256k1
import Base

/// Module-level secp256k1 context for ECDH operations.
private let ecdhCtx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!

/// Elliptic Curve Diffie-Hellman key agreement on secp256k1.
///
/// Used by the Brontide (Noise NK) encrypted transport to establish
/// shared secrets between peers.
public enum ECDH {
    /// Compute a shared secret from a local private key and a remote public key.
    ///
    /// - Parameters:
    ///   - privateKey: The local private key.
    ///   - publicKey: The remote compressed public key.
    /// - Returns: The 32-byte shared secret.
    public static func sharedSecret(privateKey: PrivateKey, publicKey: PublicKey) throws -> [UInt8] {
        var pubkey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_parse(ecdhCtx, &pubkey, publicKey.bytes, publicKey.bytes.count) == 1 else {
            throw CryptoError.keyAgreementFailed
        }
        var secret = [UInt8](repeating: 0, count: 32)
        guard secp256k1_ecdh(ecdhCtx, &secret, &pubkey, privateKey.bytes, nil, nil) == 1 else {
            throw CryptoError.keyAgreementFailed
        }
        return secret
    }

    /// Compute a shared secret from raw key bytes.
    ///
    /// Convenience overload for callers that have raw `[UInt8]` key material
    /// (e.g. Brontide ephemeral keys).
    public static func sharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        var pubkey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_parse(ecdhCtx, &pubkey, publicKey, publicKey.count) == 1 else {
            throw CryptoError.keyAgreementFailed
        }
        var secret = [UInt8](repeating: 0, count: 32)
        guard secp256k1_ecdh(ecdhCtx, &secret, &pubkey, privateKey, nil, nil) == 1 else {
            throw CryptoError.keyAgreementFailed
        }
        return secret
    }
}
