import Base
import Protocol

/// The connection state of a peer.
public enum ConnectionState: Sendable {
    /// Not yet connected.
    case disconnected
    /// TCP connected, Brontide handshake in progress.
    case connecting
    /// Brontide handshake complete, version/verack in progress.
    case connected
    /// Version/verack exchange complete — fully operational.
    case handshaked
    /// Connection destroyed.
    case destroyed
}

/// Tracks the state and metadata of a connected peer.
public struct PeerState: Sendable {
    /// The peer's network address.
    public let address: NetAddress

    /// Whether we initiated the connection (outbound).
    public let outbound: Bool

    /// Current connection state.
    public var connectionState: ConnectionState

    /// The peer's protocol version (from their VERSION message).
    public var version: UInt32

    /// The peer's service flags.
    public var services: UInt32

    /// The peer's user agent string.
    public var agent: String

    /// The peer's best block height at handshake time.
    public var height: UInt32

    /// Whether the peer supports relay (from VERSION).
    public var relay: Bool

    /// Ban score — incremented for misbehavior, banned at threshold.
    public var banScore: Int

    /// Minimum observed ping round-trip time (milliseconds).
    public var minPing: UInt64

    /// Last observed ping round-trip time (milliseconds).
    public var lastPing: UInt64

    /// Last ping nonce we sent (for matching pong).
    public var lastPingNonce: [UInt8]

    /// Timestamp of last ping sent.
    public var lastPingSent: UInt64

    /// Timestamp of last message received.
    public var lastRecv: UInt64

    /// Timestamp of last message sent.
    public var lastSend: UInt64

    /// Whether this peer prefers headers-first announcements.
    public var preferHeaders: Bool

    /// Whether this peer supports compact blocks.
    public var compactMode: UInt8

    /// The peer's fee filter rate.
    public var feeRate: Int64

    /// The peer's advertised listen port (from VERSION).
    public var listenPort: UInt16

    /// Timestamp (ms) when the connection was established (for handshake timeout).
    public var connectedAt: UInt64

    /// Last time (ms) we served a getheaders request for this peer.
    public var lastGetHeadersTime: UInt64

    /// Last time (ms) we served a mempool request for this peer.
    public var lastMempoolTime: UInt64

    /// Last time (ms) we served a getaddr request for this peer.
    public var lastGetAddrTime: UInt64

    public init(address: NetAddress, outbound: Bool) {
        self.address = address
        self.outbound = outbound
        self.connectionState = .disconnected
        self.version = 0
        self.services = 0
        self.agent = ""
        self.height = 0
        self.relay = true
        self.banScore = 0
        self.minPing = UInt64.max
        self.lastPing = UInt64.max
        self.lastPingNonce = []
        self.lastPingSent = 0
        self.lastRecv = 0
        self.lastSend = 0
        self.preferHeaders = false
        self.compactMode = 0
        self.feeRate = 0
        self.listenPort = 0
        self.connectedAt = 0
        self.lastGetHeadersTime = 0
        self.lastMempoolTime = 0
        self.lastGetAddrTime = 0
    }

    /// Whether the peer has been fully handshaked.
    public var isHandshaked: Bool {
        connectionState == .handshaked
    }

    /// Whether the peer is banned.
    public var isBanned: Bool {
        banScore >= NetConstants.banScore
    }

    /// Add to the peer's ban score and return whether they should be banned.
    @discardableResult
    public mutating func increaseBanScore(_ score: Int) -> Bool {
        banScore += score
        return isBanned
    }

    /// Record that we received data from this peer.
    public mutating func markRecv(time: UInt64) {
        lastRecv = time
    }

    /// Record that we sent data to this peer.
    public mutating func markSend(time: UInt64) {
        lastSend = time
    }

    /// Record a ping round-trip time.
    public mutating func recordPing(rtt: UInt64) {
        lastPing = rtt
        if rtt < minPing {
            minPing = rtt
        }
    }

    /// Apply the peer's version message.
    public mutating func applyVersion(_ pkt: VersionPacket) {
        version = pkt.version
        services = pkt.services
        agent = pkt.agent
        height = pkt.height
        relay = !pkt.noRelay
        listenPort = pkt.listenPort
    }
}

/// Tracks banned peer addresses.
public struct BanMap: Sendable {
    /// Banned IP → ban expiry timestamp.
    public var entries: [[UInt8]: UInt64]

    public init() {
        entries = [:]
    }

    /// Check if an IP is banned.
    public func isBanned(_ ip: [UInt8], now: UInt64) -> Bool {
        guard let expiry = entries[ip] else { return false }
        return now < expiry
    }

    /// Ban an IP for the default duration.
    public mutating func ban(_ ip: [UInt8], now: UInt64) {
        entries[ip] = now + NetConstants.banTime
    }

    /// Remove expired bans.
    public mutating func cleanup(now: UInt64) {
        entries = entries.filter { $0.value > now }
    }
}
