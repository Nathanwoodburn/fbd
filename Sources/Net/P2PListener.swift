import Base
import Logging

/// TCP listener for P2P connections.
///
/// Accepts inbound connections and wires them through PeerManager
/// for Brontide handshake + version exchange + message dispatch.
public final class P2PListener: Sendable {
    private let host: String
    private let port: Int
    private let network: NetworkType
    private let useBrontide: Bool
    private let logger: Logger
    private let peerManager: PeerManager

    nonisolated(unsafe) private var listener: TCPListener?

    public init(host: String, port: Int, network: NetworkType, useBrontide: Bool = false, peerManager: PeerManager, logger: Logger) {
        self.host = host
        self.port = port
        self.network = network
        self.useBrontide = useBrontide
        self.peerManager = peerManager
        self.logger = logger
    }

    /// Start the P2P listener.
    public func start() throws {
        let tcp = try TCPListener(host: host, port: port)
        self.listener = tcp

        let peerManager = self.peerManager
        let logger = self.logger
        let useBrontide = self.useBrontide

        tcp.accept { stream, ip, port in
            logger.debug("Inbound \(useBrontide ? "Brontide" : "P2P") connection", metadata: [
                "remote": "\(ip):\(port)",
            ])
            peerManager.handleInboundConnection(stream: stream, remoteHost: ip, remotePort: port, useBrontide: useBrontide)
        }
    }

    /// Shut down the listener.
    public func shutdown() {
        listener?.shutdown()
        listener = nil
    }
}
