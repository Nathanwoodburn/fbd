/// Errors thrown by Crypto operations.
public enum CryptoError: Error, Sendable {
    /// A private key was invalid (wrong size or not on the curve).
    case invalidPrivateKey

    /// A public key was invalid (wrong size or not on the curve).
    case invalidPublicKey

    /// A signature was invalid or could not be parsed.
    case invalidSignature

    /// An ECDSA signing operation failed.
    case signingFailed

    /// An ECDH key agreement operation failed.
    case keyAgreementFailed

    /// A hashing operation failed.
    case hashingFailed

    /// A key had the wrong byte length.
    case invalidKeyLength(expected: Int, got: Int)
}
