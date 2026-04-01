import Base

/// The running state of a full node.
///
/// Provides a snapshot of the node's current operational state,
/// useful for RPC responses and health monitoring.
public struct NodeState: Sendable {
    /// Whether the node is currently running.
    public var isRunning: Bool

    /// The current chain height.
    public var chainHeight: Int

    /// The best block hash.
    public var bestHash: Hash256

    /// The current tree root.
    public var treeRoot: Hash256

    /// The current difficulty bits.
    public var bits: UInt32

    /// The number of connected peers.
    public var peerCount: Int

    /// The number of transactions in the mempool.
    public var mempoolSize: Int

    /// The mempool memory usage in bytes.
    public var mempoolBytes: Int

    /// The estimated sync progress (0.0 to 1.0).
    public var syncProgress: Double

    /// The node start time (unix timestamp).
    public var startTime: UInt64

    /// The node uptime in seconds.
    public var uptime: UInt64

    public init() {
        self.isRunning = false
        self.chainHeight = 0
        self.bestHash = .zero
        self.treeRoot = .zero
        self.bits = 0
        self.peerCount = 0
        self.mempoolSize = 0
        self.mempoolBytes = 0
        self.syncProgress = 0
        self.startTime = 0
        self.uptime = 0
    }
}

/// Node lifecycle phases.
public enum NodePhase: String, Sendable {
    /// Node is initializing subsystems.
    case initializing

    /// Node is loading chain data from disk.
    case loading

    /// Node is connecting to peers and syncing.
    case syncing

    /// Node is fully synced and operational.
    case running

    /// Node is shutting down.
    case stopping

    /// Node has stopped.
    case stopped
}
