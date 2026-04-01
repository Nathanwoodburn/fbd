import Base

/// A Fistbump output address (witness program).
///
/// Wire format:
/// ```
/// [1 byte]    version (0...31)
/// [1 byte]    hash length (2...40)
/// [N bytes]   hash
/// ```
public struct Address: Equatable, Hashable, Sendable {
    /// The witness program version (0...31).
    public let version: UInt8

    /// The address hash (BLAKE2b-160 for P2WPKH, SHA3-256 for P2WSH).
    public let hash: [UInt8]

    /// Create an address with the given version and hash.
    ///
    /// - Throws: `ProtocolError` if version > 31 or hash length is out of range.
    public init(version: UInt8, hash: [UInt8]) throws {
        guard version <= 31 else {
            throw ProtocolError.invalidAddressVersion(version)
        }
        guard hash.count >= 2, hash.count <= 40 else {
            throw ProtocolError.invalidAddressHashLength(UInt8(min(hash.count, 255)))
        }
        self.version = version
        self.hash = hash
    }

    /// Init that skips validation (caller must ensure version/hash are valid).
    public init(unchecked version: UInt8, hash: [UInt8]) {
        self.version = version
        self.hash = hash
    }

    /// The null address (version 0, empty 20-byte hash).
    public static let null = Address(unchecked: 0, hash: [UInt8](repeating: 0, count: 20))
}

// MARK: - Bech32

extension Address {
    /// Encode this address as a Bech32 string for the given network.
    ///
    /// Format: `<hrp>1<version><hash_5bit><checksum>`
    public func toBech32(network: NetworkType) -> String {
        // Convert version + hash bytes to 5-bit groups
        var data = [version]
        if let converted = Bech32.convertBits(from: 8, to: 5, data: hash, pad: true) {
            data.append(contentsOf: converted)
        }
        return Bech32.encode(hrp: network.addressHRP, data: data)
    }

    /// Decode a Bech32 address string.
    ///
    /// - Parameters:
    ///   - bech32: The Bech32-encoded address string.
    ///   - network: The expected network (validates HRP).
    /// - Throws: `ProtocolError` if the string is invalid or HRP doesn't match.
    public init(bech32: String, network: NetworkType) throws {
        guard let decoded = Bech32.decode(bech32) else {
            throw ProtocolError.invalidBech32Address
        }
        guard decoded.hrp == network.addressHRP else {
            throw ProtocolError.invalidBech32Address
        }
        guard !decoded.data.isEmpty else {
            throw ProtocolError.invalidBech32Address
        }

        let ver = decoded.data[0]
        guard let hashBytes = Bech32.convertBits(
            from: 5, to: 8, data: Array(decoded.data.dropFirst()), pad: false
        ) else {
            throw ProtocolError.invalidBech32Address
        }

        try self.init(version: ver, hash: hashBytes)
    }
}

extension Address: WireSerializable {
    public var serializedSize: Int {
        1 + 1 + hash.count
    }

    public func write(to writer: inout BufferWriter) {
        writer.writeUInt8(version)
        writer.writeUInt8(UInt8(hash.count))
        writer.writeBytes(hash)
    }

    public static func read(from reader: inout BufferReader) throws -> Address {
        let version = try reader.readUInt8()
        let hashLen = try reader.readUInt8()
        let hash = try reader.readBytes(Int(hashLen))
        return try Address(version: version, hash: hash)
    }
}
