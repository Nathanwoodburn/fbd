import Base
import Logging

/// Closure that looks up a Fistbump name and returns its raw resource data (or nil).
public typealias NameLookup = @Sendable (String) throws -> [UInt8]?

/// UDP server that serves authoritative DNS responses.
///
/// Binds a UDP socket and runs a receive loop, delegating to `DNSResolver`.
public final class DNSServer: Sendable {
    private let host: String
    private let port: Int
    private let logger: Logger
    private let lookup: NameLookup?

    nonisolated(unsafe) private var socket: UDPSocket?

    public init(host: String, port: Int, logger: Logger, lookup: NameLookup? = nil) {
        self.host = host
        self.port = port
        self.logger = logger
        self.lookup = lookup
    }

    /// Start the DNS server.
    public func start() throws {
        let udp = try UDPSocket(host: host, port: port)
        self.socket = udp

        let resolver = DNSResolver(logger: logger, lookup: lookup)

        udp.receiveLoop { [logger] data, senderIP, senderPort in
            let sender = "\(senderIP):\(senderPort)"
            guard let response = resolver.resolve(query: data, from: sender) else {
                logger.warning("Failed to process DNS query", metadata: [
                    "from": "\(sender)",
                ])
                return nil
            }
            return response
        }
    }

    /// Shut down the server.
    public func shutdown() {
        socket?.shutdown()
        socket = nil
    }
}
