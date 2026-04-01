import Foundation

/// Protocol for async byte stream read/write, used by P2P, RPC, and tests.
public protocol AsyncByteStream: Sendable {
    /// Read up to `maxBytes` bytes. Returns empty array on EOF.
    func read(maxBytes: Int) async throws -> [UInt8]

    /// Write all bytes.
    func write(_ data: [UInt8]) async throws

    /// Close the stream.
    func close() async
}

public extension AsyncByteStream {
    /// Read up to 65536 bytes. Returns empty array on EOF.
    func read() async throws -> [UInt8] {
        try await read(maxBytes: 65536)
    }
}

/// Real implementation wrapping a SocketHandle.
///
/// Blocking POSIX I/O is dispatched to GCD's global queue (not Swift's
/// cooperative thread pool) so that blocked recv/send calls don't starve
/// other async Tasks.
public final class SocketStream: AsyncByteStream, @unchecked Sendable {
    private let handle: SocketHandle
    private let lock = NSLock()
    private var closed = false

    /// Dedicated GCD queue for blocking socket I/O.  Using a concurrent
    /// global queue lets GCD grow its thread pool for blocked calls,
    /// unlike Swift's fixed-size cooperative thread pool.
    private static let ioQueue = DispatchQueue.global(qos: .utility)

    /// The remote address string ("ip:port").
    public let remoteAddress: String

    public init(handle: SocketHandle, remoteAddress: String = "") {
        self.handle = handle
        self.remoteAddress = remoteAddress
    }

    public func read(maxBytes: Int = 65536) async throws -> [UInt8] {
        let h = handle
        return try await withCheckedThrowingContinuation { cont in
            Self.ioQueue.async {
                do {
                    let data = try h.recv(maxBytes: maxBytes)
                    cont.resume(returning: data)
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }
    }

    public func write(_ data: [UInt8]) async throws {
        let h = handle
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, any Error>) in
            Self.ioQueue.async {
                do {
                    var offset = 0
                    while offset < data.count {
                        let sent = try h.send(data[offset...])
                        guard sent > 0 else {
                            throw SocketError.sendFailed("sent 0 bytes")
                        }
                        offset += sent
                    }
                    cont.resume()
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }
    }

    public func close() async {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        lock.unlock()
        // Shutdown first to interrupt any blocking recv/send, then close.
        handle.shutdown()
        handle.close()
    }
}

/// Test implementation with paired in/out buffers.
public final class MockByteStream: AsyncByteStream, @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: [UInt8] = []
    private var isClosed = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    /// Bytes that were written to this stream (captured for assertions).
    public var written: [UInt8] = []

    public init() {}

    /// Feed data into the stream (simulates remote peer sending data).
    public func feed(_ data: [UInt8]) {
        lock.lock()
        buffer.append(contentsOf: data)
        let w = waiters
        waiters.removeAll()
        lock.unlock()
        for waiter in w {
            waiter.resume()
        }
    }

    /// Feed EOF into the stream.
    public func feedEOF() {
        lock.lock()
        isClosed = true
        let w = waiters
        waiters.removeAll()
        lock.unlock()
        for waiter in w {
            waiter.resume()
        }
    }

    public func read(maxBytes: Int = 65536) async throws -> [UInt8] {
        while true {
            lock.lock()
            if !buffer.isEmpty {
                let count = min(buffer.count, maxBytes)
                let data = Array(buffer.prefix(count))
                buffer.removeFirst(count)
                lock.unlock()
                return data
            }
            if isClosed {
                lock.unlock()
                return []
            }
            // Wait for data
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                waiters.append(cont)
                lock.unlock()
            }
        }
    }

    public func write(_ data: [UInt8]) async throws {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            throw SocketError.sendFailed("stream closed")
        }
        written.append(contentsOf: data)
        lock.unlock()
    }

    public func close() async {
        feedEOF()
    }
}
