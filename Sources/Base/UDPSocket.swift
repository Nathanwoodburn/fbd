import Foundation

/// Bound UDP socket for async send/receive.
///
/// Replaces NIO's DatagramBootstrap. Binds a UDP socket and provides
/// async receive/send methods.
public final class UDPSocket: @unchecked Sendable {
    private let handle: SocketHandle
    private var receiveTask: Task<Void, Never>?
    private let lock = NSLock()
    private var stopped = false

    /// GCD queue for blocking UDP I/O.
    private static let ioQueue = DispatchQueue.global(qos: .utility)

    /// Create and bind a UDP socket.
    public init(host: String, port: Int) throws {
        let sock = try SocketHandle.udp()
        try sock.setReuseAddr()
        try sock.bind(host: host, port: port)
        self.handle = sock
    }

    /// Run a receive loop, calling the handler for each datagram.
    /// Runs until `shutdown()` is called.
    public func receiveLoop(handler: @escaping @Sendable ([UInt8], String, Int) -> [UInt8]?) {
        let h = self.handle
        // Run blocking recvFrom/sendTo on GCD to avoid starving
        // Swift's cooperative thread pool.
        Self.ioQueue.async { [weak self] in
            while true {
                do {
                    let (data, senderIP, senderPort) = try h.recvFrom()
                    guard !data.isEmpty else { continue }

                    if let response = handler(data, senderIP, senderPort) {
                        try h.sendTo(response, host: senderIP, port: senderPort)
                    }
                } catch {
                    guard let self = self else { break }
                    self.lock.lock()
                    let isStopped = self.stopped
                    self.lock.unlock()
                    if isStopped { break }
                }
            }
        }
    }

    /// Shut down the UDP socket.
    public func shutdown() {
        lock.lock()
        stopped = true
        lock.unlock()
        receiveTask?.cancel()
        receiveTask = nil
        handle.close()
    }
}
