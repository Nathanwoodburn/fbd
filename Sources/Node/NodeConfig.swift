import Base
import Foundation
import Logging

/// Configuration for a full Fistbump node.
///
/// Combines all subsystem configuration into a single top-level struct.
/// Can be constructed from CLI arguments or loaded from a config file.
public struct NodeConfig: Sendable {

    // MARK: - Network

    /// The network to connect to.
    public let network: NetworkType

    // MARK: - Data

    /// The base data directory for chain, mempool, and tree storage.
    public let dataDir: String

    // MARK: - P2P

    /// The P2P listen host.
    public let host: String

    /// The P2P listen port (0 = use network default).
    public let port: UInt16

    /// Maximum number of outbound peers.
    public let maxOutbound: Int

    /// Maximum number of inbound peers.
    public let maxInbound: Int

    /// Seed peer addresses to always connect to (DNS seeds still run).
    public let seeds: [String]

    /// Exclusive peer addresses — connect ONLY to these (no DNS seeds).
    public let nodes: [String]

    /// Custom user agent suffix (appended to /fbd:version/).
    public let agent: String?

    // MARK: - RPC

    /// The RPC listen host.
    public let rpcHost: String

    /// The RPC listen port (0 = use network default).
    public let rpcPort: UInt16

    /// The RPC API key (nil = auto-generate).
    public let rpcApiKey: String?

    /// Whether to disable RPC authentication.
    public let rpcNoAuth: Bool

    // MARK: - DNS

    /// The authoritative DNS listen host.
    public let nsHost: String

    /// The authoritative DNS listen port (0 = use network default).
    public let nsPort: UInt16

    // MARK: - Mining

    /// The coinbase payout address for mining (nil = mining disabled).
    public let minerAddress: String?

    /// The number of CPU miner threads (0 = all cores - 1).
    public let minerThreads: Int

    // MARK: - Logging

    /// The log level.
    public let logLevel: Logger.Level

    // MARK: - Indexing

    /// Whether to maintain a transaction index.
    public let indexTx: Bool

    /// Whether to maintain an address index.
    public let indexAddress: Bool

    /// Whether to maintain a persistent auction index (LevelDB-backed).
    public let indexAuctions: Bool

    /// The platform-appropriate default data directory.
    public static var defaultDataDir: String {
        #if os(Windows)
        if let localAppData = ProcessInfo.processInfo.environment["LOCALAPPDATA"] {
            return localAppData + "\\fbd"
        }
        return "C:\\fbd"
        #else
        return "~/.fbd"
        #endif
    }

    public init(
        network: NetworkType = .main,
        dataDir: String = NodeConfig.defaultDataDir,
        host: String = "0.0.0.0",
        port: UInt16 = 0,
        maxOutbound: Int = 8,
        maxInbound: Int = 64,
        seeds: [String] = [],
        nodes: [String] = [],
        agent: String? = nil,
        rpcHost: String = "127.0.0.1",
        rpcPort: UInt16 = 0,
        rpcApiKey: String? = nil,
        rpcNoAuth: Bool = false,
        nsHost: String = "127.0.0.1",
        nsPort: UInt16 = 0,
        minerAddress: String? = nil,
        minerThreads: Int = 0,
        logLevel: Logger.Level = .info,
        indexTx: Bool = false,
        indexAddress: Bool = false,
        indexAuctions: Bool = false
    ) {
        self.network = network
        self.dataDir = dataDir
        self.host = host
        self.port = port
        self.maxOutbound = maxOutbound
        self.maxInbound = maxInbound
        self.seeds = seeds
        self.nodes = nodes
        self.agent = agent
        self.rpcHost = rpcHost
        self.rpcPort = rpcPort
        self.rpcApiKey = rpcApiKey
        self.rpcNoAuth = rpcNoAuth
        self.nsHost = nsHost
        self.nsPort = nsPort
        self.minerAddress = minerAddress
        self.minerThreads = minerThreads
        self.logLevel = logLevel
        self.indexTx = indexTx
        self.indexAddress = indexAddress
        self.indexAuctions = indexAuctions
    }

    /// The effective P2P port (config value or network default).
    public var effectivePort: UInt16 {
        port != 0 ? port : network.defaultPort
    }

    /// The effective RPC port (config value or network default).
    public var effectiveRPCPort: UInt16 {
        rpcPort != 0 ? rpcPort : network.rpcPort
    }

    /// The effective DNS port (config value or network default).
    public var effectiveNSPort: UInt16 {
        nsPort != 0 ? nsPort : network.nsPort
    }

    /// The data directory for this specific network.
    public var networkDataDir: String {
        switch network {
        case .main: return dataDir
        default:    return "\(dataDir)/\(network.rawValue)"
        }
    }
}
