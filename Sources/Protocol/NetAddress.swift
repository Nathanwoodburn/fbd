import Base

/// A network address for P2P peer communication.
///
/// Wire format (88 bytes):
/// ```
/// [8 bytes]   time (uint64 LE)
/// [4 bytes]   services (uint32 LE)
/// [4 bytes]   servicesHi (uint32 LE, reserved)
/// [1 byte]    format (0 = IPv4/IPv6)
/// [16 bytes]  IP address (IPv6-mapped)
/// [20 bytes]  reserved (zero-padded)
/// [2 bytes]   port (uint16 LE)
/// [33 bytes]  key (Brontide identity pubkey, compressed secp256k1)
/// ```
public struct NetAddress: Equatable, Sendable {
    /// Discovery timestamp (seconds since epoch).
    public let time: UInt64

    /// The advertised services bitmask.
    public let services: UInt32

    /// The IP address as 16 bytes (IPv4 addresses are IPv6-mapped).
    public let ip: [UInt8]

    /// The port number.
    public let port: UInt16

    /// The peer's Brontide identity public key (33 bytes, compressed secp256k1).
    /// Zero key (33 zero bytes) means no identity key is known.
    public let key: [UInt8]

    /// The null (zero) key — 33 bytes of zeros.
    public static let zeroKey = [UInt8](repeating: 0, count: 33)

    public init(
        time: UInt64 = 0,
        services: UInt32 = 0,
        ip: [UInt8] = [UInt8](repeating: 0, count: 16),
        port: UInt16 = 0,
        key: [UInt8] = zeroKey
    ) {
        self.time = time
        self.services = services
        self.ip = ip
        self.port = port
        self.key = key
    }

    /// Whether the key is a zero (null) key.
    public var hasKey: Bool {
        key != NetAddress.zeroKey
    }

    /// IPv4 address string, or nil if this is IPv6.
    public var ipv4String: String? {
        // IPv4-mapped IPv6: ::ffff:a.b.c.d
        let prefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        guard ip.prefix(12) == prefix[...] else { return nil }
        return "\(ip[12]).\(ip[13]).\(ip[14]).\(ip[15])"
    }
}

extension NetAddress: WireSerializable {
    public var serializedSize: Int { 88 }

    public func write(to writer: inout BufferWriter) {
        writer.writeUInt64LE(time)
        writer.writeUInt32LE(services)
        writer.writeUInt32LE(0) // servicesHi (reserved)
        writer.writeUInt8(0) // format
        writer.writeBytes(ip) // 16 bytes
        writer.writeBytes([UInt8](repeating: 0, count: 20)) // reserved
        writer.writeUInt16LE(port)
        writer.writeBytes(key) // 33 bytes
    }

    public static func read(from reader: inout BufferReader) throws -> NetAddress {
        let time = try reader.readUInt64LE()
        let services = try reader.readUInt32LE()
        _ = try reader.readUInt32LE() // servicesHi (reserved)
        _ = try reader.readUInt8() // format
        let ip = try reader.readBytes(16)
        _ = try reader.readBytes(20) // reserved
        let port = try reader.readUInt16LE()
        let key = try reader.readBytes(33)
        return NetAddress(time: time, services: services, ip: ip, port: port, key: key)
    }
}
