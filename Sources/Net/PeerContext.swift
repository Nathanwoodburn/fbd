import Base
import Foundation
import Protocol

/// Delegate for peer lifecycle and message events.
public protocol PeerMessageDelegate: AnyObject, Sendable {
    /// Called when the peer has completed the version/verack handshake.
    func peerDidHandshake(_ peerContext: PeerContext)
    /// Called when the peer disconnects.
    func peerDidDisconnect(_ peerContext: PeerContext)
    /// Called for messages not handled internally (forwarded to higher layers).
    func peerDidReceiveMessage(_ peerContext: PeerContext, type: PacketType, payload: [UInt8])
    /// Return the local chain height (for version messages).
    func currentHeight() -> UInt32
    /// Return the local nonce (for self-connection detection).
    func localNonce() -> [UInt8]
    /// Return the local P2P listen port.
    func localListenPort() -> UInt16
    /// Called when a self-connection is detected (nonce match).
    func peerIsSelf(_ peerContext: PeerContext)
}

/// Per-connection context wrapping peer state, connection, and metadata.
public final class PeerContext: @unchecked Sendable {
    /// Unique peer id.
    public let id: UInt64

    /// The peer's tracked protocol state.
    public var state: PeerState

    /// Whether this is an outbound connection.
    public let outbound: Bool

    /// The peer connection (set after creation).
    public var connection: PeerConnection?

    /// The remote static key (set after Brontide handshake).
    public var remoteStaticKey: [UInt8] = []

    // -- Block serving serialization --
    /// Queued block items waiting to be served.
    public var blockServeQueue: [InvItem] = []
    /// Lock protecting blockServeQueue and isServingBlocks.
    public let blockServeLock = NSLock()
    /// Whether a block-serving Task is currently running.
    public var isServingBlocks = false
    /// The block-serving Task (cancelled on disconnect).
    public var blockServeTask: Task<Void, Never>?

    public init(id: UInt64, state: PeerState, outbound: Bool) {
        self.id = id
        self.state = state
        self.outbound = outbound
    }

    /// Send a packet to this peer.
    public func send<P: Packet>(_ packet: P) {
        connection?.send(packet)
    }

    /// Close this peer's connection.
    public func close() {
        connection?.close()
    }

    /// Wait for the read loop to finish after close().
    public func awaitDisconnect() async {
        await connection?.awaitDisconnect()
    }
}
