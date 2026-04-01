/// Errors that can occur during networking operations.
public enum NetError: Error, Equatable, Sendable {
    /// The network magic bytes don't match.
    case badMagic(UInt32)

    /// The packet type is unknown.
    case unknownPacketType(UInt8)

    /// The message payload exceeds the maximum size.
    case messageTooLarge(Int)

    /// The Brontide handshake failed.
    case handshakeFailed(String)

    /// AEAD authentication tag verification failed.
    case badTag

    /// The peer sent an invalid version message.
    case badVersion(String)

    /// The peer's protocol version is too old.
    case obsoleteVersion(UInt32)

    /// The peer was banned.
    case banned

    /// Connection timed out.
    case timeout(String)

    /// The peer disconnected.
    case disconnected

    /// Too many items in an inventory message.
    case tooManyInvItems(Int)

    /// Too many headers in a headers message.
    case tooManyHeaders(Int)

    /// Too many addresses in an addr message.
    case tooManyAddresses(Int)

    /// A required field is missing or malformed in a packet.
    case malformedPacket(String)
}
