import Base

/// A decoded P2P message carrying a packet type and raw payload.
public struct PeerMessage: Sendable {
    /// The packet type.
    public let type: PacketType
    /// The raw payload bytes (after framing header is stripped).
    public let payload: [UInt8]

    public init(type: PacketType, payload: [UInt8]) {
        self.type = type
        self.payload = payload
    }
}

/// Encodes and decodes the Fistbump packet framing layer.
///
/// Each packet has a 9-byte header:
/// ```
/// [4 bytes]  magic (uint32 LE)
/// [1 byte]   command (PacketType)
/// [4 bytes]  payload size (uint32 LE)
/// ```
///
/// No checksum — integrity is provided by Brontide's AEAD.
public enum PacketFramer {

    /// Encode a packet frame (header + payload).
    ///
    /// - Parameters:
    ///   - type: The packet type.
    ///   - payload: The serialized payload bytes.
    ///   - network: The network type (for magic bytes).
    /// - Returns: The complete frame bytes (9-byte header + payload).
    public static func encode(
        type: PacketType,
        payload: [UInt8],
        network: NetworkType
    ) -> [UInt8] {
        var writer = BufferWriter(capacity: NetConstants.headerSize + payload.count)
        writer.writeUInt32LE(network.magic)
        writer.writeUInt8(type.rawValue)
        writer.writeUInt32LE(UInt32(payload.count))
        writer.writeBytes(payload)
        return writer.data
    }

    /// The result of parsing a packet frame header.
    public struct FrameHeader: Sendable {
        /// The packet type.
        public let type: PacketType
        /// The payload size in bytes.
        public let payloadSize: Int
    }

    /// Parse the 9-byte frame header.
    ///
    /// - Parameters:
    ///   - data: At least 9 bytes of header data.
    ///   - network: The expected network (for magic byte validation).
    /// - Returns: The parsed header with type and payload size.
    public static func decodeHeader(
        _ data: [UInt8],
        network: NetworkType
    ) throws -> FrameHeader {
        guard data.count >= NetConstants.headerSize else {
            throw NetError.messageTooLarge(0)
        }

        var reader = BufferReader(data)
        let magic = try reader.readUInt32LE()
        guard magic == network.magic else {
            throw NetError.badMagic(magic)
        }

        let cmd = try reader.readUInt8()
        guard let type = PacketType(rawValue: cmd) else {
            throw NetError.unknownPacketType(cmd)
        }

        let size = Int(try reader.readUInt32LE())
        guard size <= NetConstants.maxMessage else {
            throw NetError.messageTooLarge(size)
        }

        return FrameHeader(type: type, payloadSize: size)
    }
}
