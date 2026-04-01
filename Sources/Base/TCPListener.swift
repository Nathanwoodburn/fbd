import Foundation

/// TCP server that accepts connections as an AsyncStream.
///
/// Replaces NIO's ServerBootstrap. Binds a TCP socket, listens, and
/// yields accepted connections as `(SocketStream, remoteIP, remotePort)`.
public final class TCPListener: @unchecked Sendable {
    private let handle: SocketHandle
    private var acceptTask: Task<Void, Never>?
    private let lock = NSLock()
    private var stopped = false

    /// GCD queue for blocking accept() calls.
    private static let acceptQueue = DispatchQueue(label: "fbd.tcp-accept", attributes: .concurrent)

    /// The bound port (useful when binding to port 0).
    public let port: Int

    /// Create and bind a TCP listener.
    public init(host: String, port: Int) throws {
        let sock = try SocketHandle.tcp()
        try sock.setReuseAddr()
        try sock.bind(host: host, port: port)
        try sock.listen()
        self.handle = sock
        self.port = port
    }

    /// Accept connections in a loop, calling the handler for each one.
    /// Runs until `shutdown()` is called.
    public func accept(handler: @escaping @Sendable (SocketStream, String, Int) async -> Void) {
        acceptTask = Task {
            while !Task.isCancelled {
                do {
                    // Run blocking accept() on GCD so it doesn't consume
                    // a cooperative thread pool slot.
                    let (clientHandle, ip, port) = try await withCheckedThrowingContinuation {
                        (cont: CheckedContinuation<(SocketHandle, String, Int), any Error>) in
                        Self.acceptQueue.async {
                            do {
                                let result = try self.handle.accept()
                                cont.resume(returning: result)
                            } catch {
                                cont.resume(throwing: error)
                            }
                        }
                    }
                    try? clientHandle.setNoDelay()
                    try? clientHandle.setKeepalive()
                    let stream = SocketStream(handle: clientHandle, remoteAddress: "\(ip):\(port)")
                    // Spawn each connection in its own task so accept loop isn't blocked
                    Task { await handler(stream, ip, port) }
                } catch {
                    // Check if we've been shut down
                    self.lock.lock()
                    let isStopped = self.stopped
                    self.lock.unlock()
                    if isStopped || Task.isCancelled { break }
                    // Brief pause on transient errors
                    try? await Task.sleep(nanoseconds: 100_000_000)
                }
            }
        }
    }

    /// Shut down the listener.
    public func shutdown() {
        lock.lock()
        stopped = true
        lock.unlock()
        acceptTask?.cancel()
        acceptTask = nil
        handle.close()
    }
}
