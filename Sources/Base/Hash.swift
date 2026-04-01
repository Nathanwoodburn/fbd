/// A 256-bit (32-byte) hash value, used for block hashes, tx hashes, etc.
public struct Hash256: Hashable, Sendable {
    /// The raw 32 bytes.
    public let bytes: [UInt8]

    /// The zero hash (32 zero bytes).
    public static let zero = Hash256(unchecked: [UInt8](repeating: 0, count: 32))

    /// Create a Hash256 from exactly 32 bytes.
    ///
    /// - Throws: `BaseError.invalidHashLength` if the array is not 32 bytes.
    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw BaseError.invalidHashLength(expected: 32, got: bytes.count)
        }
        self.bytes = bytes
    }

    /// Initializer that skips the length check.
    ///
    /// - Precondition: `bytes.count == 32`. Violating this is a programmer error.
    public init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// The hash as a lowercase hex string.
    public var hex: String {
        HexEncoding.encode(bytes)
    }

    /// The hash as a reversed hex string (Bitcoin-style display order).
    public var reversedHex: String {
        HexEncoding.encode(bytes.reversed())
    }

    /// Create a Hash256 from a hex string (64 characters).
    ///
    /// - Throws: `BaseError.invalidHexString` or `BaseError.invalidHashLength`.
    public static func fromHex(_ hex: String) throws -> Hash256 {
        let bytes = try HexEncoding.decode(hex)
        return try Hash256(bytes)
    }
}

extension Hash256: CustomStringConvertible {
    public var description: String { hex }
}

extension Hash256: WireSerializable {
    public var serializedSize: Int { 32 }

    public func write(to writer: inout BufferWriter) {
        writer.writeBytes(bytes)
    }

    public static func read(from reader: inout BufferReader) throws -> Hash256 {
        let bytes = try reader.readBytes(32)
        return Hash256(unchecked: bytes)
    }
}

// MARK: - Hash160

/// A 160-bit (20-byte) hash value, used for address hashes.
public struct Hash160: Hashable, Sendable {
    /// The raw 20 bytes.
    public let bytes: [UInt8]

    /// The zero hash (20 zero bytes).
    public static let zero = Hash160(unchecked: [UInt8](repeating: 0, count: 20))

    /// Create a Hash160 from exactly 20 bytes.
    ///
    /// - Throws: `BaseError.invalidHashLength` if the array is not 20 bytes.
    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 20 else {
            throw BaseError.invalidHashLength(expected: 20, got: bytes.count)
        }
        self.bytes = bytes
    }

    /// Initializer that skips the length check.
    ///
    /// - Precondition: `bytes.count == 20`. Violating this is a programmer error.
    public init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// The hash as a lowercase hex string.
    public var hex: String {
        HexEncoding.encode(bytes)
    }

    /// Create a Hash160 from a hex string (40 characters).
    ///
    /// - Throws: `BaseError.invalidHexString` or `BaseError.invalidHashLength`.
    public static func fromHex(_ hex: String) throws -> Hash160 {
        let bytes = try HexEncoding.decode(hex)
        return try Hash160(bytes)
    }
}

extension Hash160: CustomStringConvertible {
    public var description: String { hex }
}

extension Hash160: WireSerializable {
    public var serializedSize: Int { 20 }

    public func write(to writer: inout BufferWriter) {
        writer.writeBytes(bytes)
    }

    public static func read(from reader: inout BufferReader) throws -> Hash160 {
        let bytes = try reader.readBytes(20)
        return Hash160(unchecked: bytes)
    }
}
