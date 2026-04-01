import Base

/// Protocol and networking constants for the Fistbump P2P layer.
public enum NetConstants {
    /// Current protocol version.
    public static let protocolVersion: UInt32 = Constants.protocolVersion

    /// Minimum accepted protocol version.
    public static let minVersion: UInt32 = Constants.minProtocolVersion

    /// Maximum payload size in bytes (8 MB).
    public static let maxMessage: Int = Constants.maxMessageSize

    /// Maximum inventory items per INV/GETDATA/NOTFOUND message.
    public static let maxInv: Int = Constants.maxInvItems

    /// Maximum headers per HEADERS message.
    /// Each header (236 B) + BalloonProof (5376 B) = 5612 B per entry.
    /// 1000 entries ≈ 5.6 MB, safely under the 8 MB message limit.
    public static let maxHeaders: Int = 1_000

    /// Maximum addresses per ADDR message.
    public static let maxAddresses: Int = 1_000

    /// Maximum pending block requests.
    public static let maxBlockRequest: Int = 51_000

    /// Maximum pending transaction requests.
    public static let maxTxRequest: Int = 10_000

    // MARK: - Timeouts (milliseconds)

    /// Timeout for TCP connection establishment.
    public static let connectTimeout: UInt64 = 5_000

    /// Timeout for version/verack handshake.
    public static let handshakeTimeout: UInt64 = 5_000

    /// Generic response timeout.
    public static let responseTimeout: UInt64 = 30_000

    /// Block delivery timeout.
    public static let blockTimeout: UInt64 = 120_000

    /// Transaction delivery timeout.
    public static let txTimeout: UInt64 = 120_000

    /// Inactivity timeout (no send/recv).
    public static let inactivityTimeout: UInt64 = 1_200_000

    /// Ping interval.
    public static let pingInterval: UInt64 = 30_000

    /// Pong timeout — disconnect if no pong received within this time (ms).
    public static let pongTimeout: UInt64 = 120_000

    /// Stall check interval.
    public static let stallInterval: UInt64 = 5_000

    // MARK: - Peer Management

    /// Default maximum outbound connections.
    public static let maxOutbound: Int = 8

    /// Default maximum inbound connections.
    public static let maxInbound: Int = 20

    /// Ban score threshold — peer is banned when score reaches this.
    public static let banScore: Int = 100

    /// Ban duration in seconds (24 hours).
    public static let banTime: UInt64 = 86_400

    /// Size of the packet framing header (magic + type + size).
    public static let headerSize: Int = 9

    /// User agent string.
    public static let userAgent: String = "/fbd:\(Constants.version)/"

    // MARK: - Brontide

    /// Brontide Act 1 size: 33-byte compressed key + 16-byte tag.
    public static let actOneSize: Int = 49

    /// Brontide Act 2 size: 33-byte compressed key + 16-byte tag.
    public static let actTwoSize: Int = 49

    /// Brontide Act 3 size: 33-byte encrypted pubkey + 16-byte tag1 + 16-byte tag2.
    public static let actThreeSize: Int = 65

    /// Brontide encrypted frame header size: 4-byte encrypted length + 16-byte tag.
    public static let brontideHeaderSize: Int = 20

    /// Brontide max message (inner frame header included).
    public static let brontideMaxMessage: Int = maxMessage + headerSize

    /// Cipher key rotation interval (rotate after this many encrypt/decrypt ops).
    public static let rotationInterval: UInt32 = 1_000

    /// Noise protocol name for Handshake Brontide.
    public static let noiseProtocol = "Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared"

    /// Noise prologue for Fistbump.
    public static let noisePrologue: [UInt8] = Array("fbd".utf8)
}
