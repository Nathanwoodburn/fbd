import Base

/// A 32-byte secp256k1 private key.
public struct PrivateKey: Hashable, Sendable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw CryptoError.invalidKeyLength(expected: 32, got: bytes.count)
        }
        self.bytes = bytes
    }

    public init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public static let zero = PrivateKey(unchecked: [UInt8](repeating: 0, count: 32))
}

extension PrivateKey: CustomStringConvertible {
    /// Always returns "<redacted>" to prevent accidental logging of key material.
    public var description: String { "<redacted>" }
}

/// A 33-byte compressed secp256k1 public key.
public struct PublicKey: Hashable, Sendable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 33 else {
            throw CryptoError.invalidKeyLength(expected: 33, got: bytes.count)
        }
        self.bytes = bytes
    }

    public init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public static let zero = PublicKey(unchecked: [UInt8](repeating: 0, count: 33))

    public var hex: String { HexEncoding.encode(bytes) }
}

extension PublicKey: CustomStringConvertible {
    public var description: String { hex }
}
