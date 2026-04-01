#if os(Windows)
import WinSDK
#else
import Foundation
#if canImport(Android)
import Android
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Darwin)
import Darwin
#endif
#endif

/// Cross-platform raw socket wrapper.
///
/// Provides a thin abstraction over POSIX sockets (macOS/Linux) and WinSock (Windows).
/// Methods are blocking — offload to `Task.detached` for async use.
public struct SocketHandle: Sendable {

    #if os(Windows)
    public typealias NativeHandle = SOCKET
    private static let invalidHandle: SOCKET = INVALID_SOCKET
    #else
    public typealias NativeHandle = Int32
    private static let invalidHandle: Int32 = -1
    #endif

    public let fd: NativeHandle

    public init(fd: NativeHandle) {
        self.fd = fd
    }

    public var isValid: Bool {
        fd != Self.invalidHandle
    }

    // MARK: - Factory

    /// Create a TCP (stream) socket.
    public static func tcp(ipv6: Bool = false) throws -> SocketHandle {
        #if os(Windows)
        ensureWSAStartup()
        let fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP.rawValue)
        guard fd != INVALID_SOCKET else {
            throw SocketError.createFailed(Self.platformError())
        }
        #else
        let family: Int32 = ipv6 ? AF_INET6 : AF_INET
        #if canImport(Glibc) || canImport(Musl)
        let fd = socket(family, Int32(SOCK_STREAM.rawValue), Int32(IPPROTO_TCP))
        #elseif canImport(Android)
        let fd = socket(family, SOCK_STREAM, Int32(IPPROTO_TCP))
        #else
        let fd = socket(family, SOCK_STREAM, IPPROTO_TCP)
        #endif
        guard fd >= 0 else {
            throw SocketError.createFailed(Self.platformError())
        }
        // Prevent SIGPIPE on write to closed socket (macOS).
        // Linux uses MSG_NOSIGNAL instead; we also ignore SIGPIPE globally.
        #if canImport(Darwin)
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        #endif
        #endif
        return SocketHandle(fd: fd)
    }

    /// Create a UDP (datagram) socket.
    public static func udp(ipv6: Bool = false) throws -> SocketHandle {
        #if os(Windows)
        ensureWSAStartup()
        let fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP.rawValue)
        guard fd != INVALID_SOCKET else {
            throw SocketError.createFailed(Self.platformError())
        }
        #else
        let family: Int32 = ipv6 ? AF_INET6 : AF_INET
        #if canImport(Glibc) || canImport(Musl)
        let fd = socket(family, Int32(SOCK_DGRAM.rawValue), Int32(IPPROTO_UDP))
        #elseif canImport(Android)
        let fd = socket(family, SOCK_DGRAM, Int32(IPPROTO_UDP))
        #else
        let fd = socket(family, SOCK_DGRAM, IPPROTO_UDP)
        #endif
        guard fd >= 0 else {
            throw SocketError.createFailed(Self.platformError())
        }
        #endif
        return SocketHandle(fd: fd)
    }

    // MARK: - Options

    /// Set SO_REUSEADDR on the socket.
    public func setReuseAddr() throws {
        var val: Int32 = 1
        #if os(Windows)
        let result = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, Int32(MemoryLayout<Int32>.size))
        guard result == 0 else {
            throw SocketError.optionFailed(Self.platformError())
        }
        #else
        let result = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, socklen_t(MemoryLayout<Int32>.size))
        guard result == 0 else {
            throw SocketError.optionFailed(Self.platformError())
        }
        #endif
    }

    /// Enable TCP keepalive with the given idle time in seconds.
    ///
    /// The OS will send keepalive probes after `idle` seconds of inactivity,
    /// detecting dead connections even after system sleep/wake.
    public func setKeepalive(idle: Int32 = 60) throws {
        var on: Int32 = 1
        #if os(Windows)
        let r1 = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, Int32(MemoryLayout<Int32>.size))
        guard r1 == 0 else { throw SocketError.optionFailed(Self.platformError()) }
        #else
        let r1 = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, socklen_t(MemoryLayout<Int32>.size))
        guard r1 == 0 else { throw SocketError.optionFailed(Self.platformError()) }

        #if canImport(Darwin)
        var idleVal = idle
        setsockopt(fd, Int32(IPPROTO_TCP), TCP_KEEPALIVE, &idleVal, socklen_t(MemoryLayout<Int32>.size))
        #elseif canImport(Glibc) || canImport(Musl) || canImport(Android)
        var idleVal = idle
        setsockopt(fd, Int32(IPPROTO_TCP), TCP_KEEPIDLE, &idleVal, socklen_t(MemoryLayout<Int32>.size))
        var intvl: Int32 = 10
        setsockopt(fd, Int32(IPPROTO_TCP), TCP_KEEPINTVL, &intvl, socklen_t(MemoryLayout<Int32>.size))
        var cnt: Int32 = 3
        setsockopt(fd, Int32(IPPROTO_TCP), TCP_KEEPCNT, &cnt, socklen_t(MemoryLayout<Int32>.size))
        #endif
        #endif
    }

    /// Set TCP_NODELAY on the socket.
    public func setNoDelay() throws {
        var val: Int32 = 1
        #if os(Windows)
        let result = setsockopt(fd, IPPROTO_TCP.rawValue, Int32(TCP_NODELAY), &val, Int32(MemoryLayout<Int32>.size))
        guard result == 0 else {
            throw SocketError.optionFailed(Self.platformError())
        }
        #else
        let result = setsockopt(fd, Int32(IPPROTO_TCP), TCP_NODELAY, &val, socklen_t(MemoryLayout<Int32>.size))
        guard result == 0 else {
            throw SocketError.optionFailed(Self.platformError())
        }
        #endif
    }

    // MARK: - Server

    /// Bind the socket to an address and port.
    public func bind(host: String, port: Int) throws {
        var addr = sockaddr_in()
        #if os(Windows)
        addr.sin_family = ADDRESS_FAMILY(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        #else
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        #endif

        if host == "0.0.0.0" || host.isEmpty {
            #if os(Windows)
            addr.sin_addr = in_addr()
            #else
            addr.sin_addr = in_addr(s_addr: 0)
            #endif
        } else {
            var inAddr = in_addr()
            guard inet_pton(AF_INET, host, &inAddr) == 1 else {
                throw SocketError.invalidAddress(host)
            }
            addr.sin_addr = inAddr
        }

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                platform_bind(fd, sockPtr, SockLen(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard result == 0 else {
            throw SocketError.bindFailed(Self.platformError())
        }
    }

    /// Listen for incoming connections.
    public func listen(backlog: Int32 = 128) throws {
        let result = platform_listen(fd, backlog)
        guard result == 0 else {
            throw SocketError.listenFailed(Self.platformError())
        }
    }

    /// Accept a connection. Returns (clientSocket, remoteIP, remotePort).
    /// Blocks until a connection arrives.
    public func accept() throws -> (SocketHandle, String, Int) {
        var clientAddr = sockaddr_in()
        var addrLen = SockLen(MemoryLayout<sockaddr_in>.size)

        let clientFd = withUnsafeMutablePointer(to: &clientAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                platform_accept(fd, sockPtr, &addrLen)
            }
        }

        guard clientFd != Self.invalidHandle else {
            throw SocketError.acceptFailed(Self.platformError())
        }

        var ipBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &clientAddr.sin_addr, &ipBuf, numericCast(INET_ADDRSTRLEN))
        let ip = String(cString: ipBuf)
        let port = Int(clientAddr.sin_port.bigEndian)

        return (SocketHandle(fd: clientFd), ip, port)
    }

    // MARK: - Client

    /// Connect to a remote host and port. Blocks until connected or fails.
    public func connect(host: String, port: Int) throws {
        var addr = sockaddr_in()
        #if os(Windows)
        addr.sin_family = ADDRESS_FAMILY(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        #else
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        #endif

        var inAddr = in_addr()
        guard inet_pton(AF_INET, host, &inAddr) == 1 else {
            // Try DNS resolution
            let resolved = try resolveHost(host)
            guard inet_pton(AF_INET, resolved, &inAddr) == 1 else {
                throw SocketError.invalidAddress(host)
            }
            addr.sin_addr = inAddr
            try connectWithAddr(&addr)
            return
        }
        addr.sin_addr = inAddr
        try connectWithAddr(&addr)
    }

    private func connectWithAddr(_ addr: inout sockaddr_in) throws {
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                platform_connect(fd, sockPtr, SockLen(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard result == 0 else {
            throw SocketError.connectFailed(Self.platformError())
        }
    }

    // MARK: - TCP I/O

    /// Send data. Returns number of bytes sent.
    @discardableResult
    public func send(_ data: [UInt8]) throws -> Int {
        guard !data.isEmpty else { return 0 }
        let sent = data.withUnsafeBufferPointer { ptr in
            platform_send(fd, ptr.baseAddress!, data.count, 0)
        }

        guard sent >= 0 else {
            throw SocketError.sendFailed(Self.platformError())
        }
        return sent
    }

    /// Send data from an ArraySlice without copying. Returns number of bytes sent.
    @discardableResult
    public func send(_ data: ArraySlice<UInt8>) throws -> Int {
        guard !data.isEmpty else { return 0 }
        let sent = data.withUnsafeBufferPointer { ptr in
            platform_send(fd, ptr.baseAddress!, data.count, 0)
        }

        guard sent >= 0 else {
            throw SocketError.sendFailed(Self.platformError())
        }
        return sent
    }

    /// Receive data into a buffer. Returns number of bytes read, or 0 on EOF.
    public func recv(maxBytes: Int = 65536) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: maxBytes)
        let n = buffer.withUnsafeMutableBufferPointer { ptr in
            platform_recv(fd, ptr.baseAddress!, maxBytes, 0)
        }

        guard n >= 0 else {
            throw SocketError.recvFailed(Self.platformError())
        }
        guard n > 0 else { return [] }
        return Array(buffer.prefix(n))
    }

    // MARK: - UDP I/O

    /// Send a datagram to a specific address.
    @discardableResult
    public func sendTo(_ data: [UInt8], host: String, port: Int) throws -> Int {
        var addr = sockaddr_in()
        #if os(Windows)
        addr.sin_family = ADDRESS_FAMILY(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        #else
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        #endif
        inet_pton(AF_INET, host, &addr.sin_addr)

        let sent = data.withUnsafeBufferPointer { ptr in
            withUnsafePointer(to: &addr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    platform_sendto(fd, ptr.baseAddress!, data.count, 0, sockPtr, SockLen(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        guard sent >= 0 else {
            throw SocketError.sendFailed(Self.platformError())
        }
        return sent
    }

    /// Receive a datagram. Returns (data, senderIP, senderPort).
    public func recvFrom(maxBytes: Int = 65536) throws -> ([UInt8], String, Int) {
        var buffer = [UInt8](repeating: 0, count: maxBytes)
        var senderAddr = sockaddr_in()
        var addrLen = SockLen(MemoryLayout<sockaddr_in>.size)

        let n = buffer.withUnsafeMutableBufferPointer { ptr in
            withUnsafeMutablePointer(to: &senderAddr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    platform_recvfrom(fd, ptr.baseAddress!, maxBytes, 0, sockPtr, &addrLen)
                }
            }
        }

        guard n >= 0 else {
            throw SocketError.recvFailed(Self.platformError())
        }

        var ipBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &senderAddr.sin_addr, &ipBuf, numericCast(INET_ADDRSTRLEN))
        let ip = String(cString: ipBuf)
        let port = Int(senderAddr.sin_port.bigEndian)

        return (Array(buffer.prefix(n)), ip, port)
    }

    // MARK: - Close

    /// Shutdown the socket for both reads and writes.
    /// This interrupts any blocking recv/send without closing the fd.
    public func shutdown() {
        platform_shutdown(fd)
    }

    /// Close the socket.
    public func close() {
        platform_close(fd)
    }

    // MARK: - DNS Resolution

    private func resolveHost(_ hostname: String) throws -> String {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        #if canImport(Glibc) || canImport(Musl)
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #else
        hints.ai_socktype = SOCK_STREAM
        #endif
        var result: UnsafeMutablePointer<addrinfo>?

        let status = getaddrinfo(hostname, nil, &hints, &result)
        guard status == 0, let addrList = result else {
            throw SocketError.invalidAddress(hostname)
        }
        defer { freeaddrinfo(addrList) }

        if addrList.pointee.ai_family == AF_INET {
            var sa = addrList.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &sa.sin_addr, &buf, numericCast(INET_ADDRSTRLEN))
            return String(cString: buf)
        }
        throw SocketError.invalidAddress(hostname)
    }

    // MARK: - Helpers

    #if os(Windows)
    static var wsaInitialized = false
    static func ensureWSAStartup() {
        guard !wsaInitialized else { return }
        var wsaData = WSADATA()
        WSAStartup(UInt16(0x0202), &wsaData)
        wsaInitialized = true
    }
    #endif

    static func platformError() -> String {
        #if os(Windows)
        "WSA error \(WSAGetLastError())"
        #elseif canImport(Android)
        String(cString: strerror(__errno().pointee))
        #else
        String(cString: strerror(errno))
        #endif
    }
}

// MARK: - Platform-specific shims

// Unified socket call wrappers. Normalizes Windows (WinSDK) and POSIX
// (Darwin/Glibc/Android/Musl) type differences behind a common interface.
// Also disambiguates POSIX socket symbols from NIO on Darwin/Glibc.

#if os(Windows)
private typealias SockFD = SOCKET
private typealias SockLen = Int32
#else
private typealias SockFD = Int32
private typealias SockLen = socklen_t
#endif

private func platform_bind(_ fd: SockFD, _ addr: UnsafePointer<sockaddr>, _ len: SockLen) -> Int32 {
    #if os(Windows)
    WinSDK.bind(fd, addr, len)
    #elseif canImport(Android)
    Android.bind(fd, addr, len)
    #elseif canImport(Darwin)
    Darwin.bind(fd, addr, len)
    #elseif canImport(Glibc)
    Glibc.bind(fd, addr, len)
    #elseif canImport(Musl)
    Musl.bind(fd, addr, len)
    #endif
}

private func platform_listen(_ fd: SockFD, _ backlog: Int32) -> Int32 {
    #if os(Windows)
    WinSDK.listen(fd, backlog)
    #elseif canImport(Android)
    Android.listen(fd, backlog)
    #elseif canImport(Darwin)
    Darwin.listen(fd, backlog)
    #elseif canImport(Glibc)
    Glibc.listen(fd, backlog)
    #elseif canImport(Musl)
    Musl.listen(fd, backlog)
    #endif
}

private func platform_accept(_ fd: SockFD, _ addr: UnsafeMutablePointer<sockaddr>?, _ len: inout SockLen) -> SockFD {
    #if os(Windows)
    WinSDK.accept(fd, addr, &len)
    #elseif canImport(Android)
    Android.accept(fd, addr, &len)
    #elseif canImport(Darwin)
    Darwin.accept(fd, addr, &len)
    #elseif canImport(Glibc)
    Glibc.accept(fd, addr, &len)
    #elseif canImport(Musl)
    Musl.accept(fd, addr, &len)
    #endif
}

private func platform_connect(_ fd: SockFD, _ addr: UnsafePointer<sockaddr>, _ len: SockLen) -> Int32 {
    #if os(Windows)
    WinSDK.connect(fd, addr, len)
    #elseif canImport(Android)
    Android.connect(fd, addr, len)
    #elseif canImport(Darwin)
    Darwin.connect(fd, addr, len)
    #elseif canImport(Glibc)
    Glibc.connect(fd, addr, len)
    #elseif canImport(Musl)
    Musl.connect(fd, addr, len)
    #endif
}

private func platform_send(_ fd: SockFD, _ buf: UnsafeRawPointer?, _ len: Int, _ flags: Int32) -> Int {
    #if os(Windows)
    Int(WinSDK.send(fd, buf, Int32(len), flags))
    #elseif canImport(Android)
    Android.send(fd, buf!, len, flags)
    #elseif canImport(Darwin)
    Darwin.send(fd, buf, len, flags)
    #elseif canImport(Glibc)
    Glibc.send(fd, buf, len, flags)
    #elseif canImport(Musl)
    Musl.send(fd, buf, len, flags)
    #endif
}

private func platform_recv(_ fd: SockFD, _ buf: UnsafeMutableRawPointer?, _ len: Int, _ flags: Int32) -> Int {
    #if os(Windows)
    Int(WinSDK.recv(fd, buf, Int32(len), flags))
    #elseif canImport(Android)
    Android.recv(fd, buf!, len, flags)
    #elseif canImport(Darwin)
    Darwin.recv(fd, buf, len, flags)
    #elseif canImport(Glibc)
    Glibc.recv(fd, buf, len, flags)
    #elseif canImport(Musl)
    Musl.recv(fd, buf, len, flags)
    #endif
}

private func platform_sendto(_ fd: SockFD, _ buf: UnsafeRawPointer?, _ len: Int, _ flags: Int32, _ addr: UnsafePointer<sockaddr>?, _ addrLen: SockLen) -> Int {
    #if os(Windows)
    Int(WinSDK.sendto(fd, buf, Int32(len), flags, addr, addrLen))
    #elseif canImport(Android)
    Android.sendto(fd, buf!, len, flags, addr, addrLen)
    #elseif canImport(Darwin)
    Darwin.sendto(fd, buf, len, flags, addr, addrLen)
    #elseif canImport(Glibc)
    Glibc.sendto(fd, buf, len, flags, addr, addrLen)
    #elseif canImport(Musl)
    Musl.sendto(fd, buf, len, flags, addr, addrLen)
    #endif
}

private func platform_recvfrom(_ fd: SockFD, _ buf: UnsafeMutableRawPointer?, _ len: Int, _ flags: Int32, _ addr: UnsafeMutablePointer<sockaddr>?, _ addrLen: inout SockLen) -> Int {
    #if os(Windows)
    Int(WinSDK.recvfrom(fd, buf, Int32(len), flags, addr, &addrLen))
    #elseif canImport(Android)
    Android.recvfrom(fd, buf!, len, flags, addr, &addrLen)
    #elseif canImport(Darwin)
    Darwin.recvfrom(fd, buf, len, flags, addr, &addrLen)
    #elseif canImport(Glibc)
    Glibc.recvfrom(fd, buf, len, flags, addr, &addrLen)
    #elseif canImport(Musl)
    Musl.recvfrom(fd, buf, len, flags, addr, &addrLen)
    #endif
}

private func platform_shutdown(_ fd: SockFD) {
    #if os(Windows)
    WinSDK.shutdown(fd, SD_BOTH)
    #elseif canImport(Android)
    Android.shutdown(fd, Int32(SHUT_RDWR))
    #else
    Foundation.shutdown(fd, Int32(SHUT_RDWR))
    #endif
}

private func platform_close(_ fd: SockFD) {
    #if os(Windows)
    closesocket(fd)
    #elseif canImport(Android)
    Android.close(fd)
    #else
    Foundation.close(fd)
    #endif
}

/// Socket operation errors.
public enum SocketError: Error, CustomStringConvertible {
    case createFailed(String)
    case optionFailed(String)
    case bindFailed(String)
    case listenFailed(String)
    case acceptFailed(String)
    case connectFailed(String)
    case sendFailed(String)
    case recvFailed(String)
    case invalidAddress(String)

    public var description: String {
        switch self {
        case .createFailed(let s): return "socket create failed: \(s)"
        case .optionFailed(let s): return "socket option failed: \(s)"
        case .bindFailed(let s): return "bind failed: \(s)"
        case .listenFailed(let s): return "listen failed: \(s)"
        case .acceptFailed(let s): return "accept failed: \(s)"
        case .connectFailed(let s): return "connect failed: \(s)"
        case .sendFailed(let s): return "send failed: \(s)"
        case .recvFailed(let s): return "recv failed: \(s)"
        case .invalidAddress(let s): return "invalid address: \(s)"
        }
    }
}
