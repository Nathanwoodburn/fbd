import Base

/// A 32-byte SHA3-256 hash of a domain name.
///
/// Distinct from Hash256 (which is SHA256-based) to prevent accidentally
/// passing a transaction hash where a name hash is expected.
public struct NameHash: Hashable, Sendable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw BaseError.invalidHashLength(expected: 32, got: bytes.count)
        }
        self.bytes = bytes
    }

    public init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// Bridge from Hash256 (e.g. when NameRules.hashName returns Hash256).
    public init(_ hash: Hash256) {
        self.bytes = hash.bytes
    }

    /// Bridge to Hash256 for APIs that haven't been migrated yet.
    public var asHash256: Hash256 {
        Hash256(unchecked: bytes)
    }

    public static let zero = NameHash(unchecked: [UInt8](repeating: 0, count: 32))

    public var hex: String { HexEncoding.encode(bytes) }

    public static func fromHex(_ hex: String) throws -> NameHash {
        let bytes = try HexEncoding.decode(hex)
        return try NameHash(bytes)
    }
}

extension NameHash: CustomStringConvertible {
    public var description: String { hex }
}
