import XCTest
@testable import Net
import Base
import ExtCrypto
import Protocol
import Logging

/// Mock delegate for capturing PeerMessageHandler callbacks.
private final class MockDelegate: PeerMessageDelegate, @unchecked Sendable {
    var handshaked: [UInt64] = []
    var disconnected: [UInt64] = []
    var messages: [(UInt64, PacketType, [UInt8])] = []
    var height: UInt32 = 100
    var nonce: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]

    func peerDidHandshake(_ peerContext: PeerContext) {
        handshaked.append(peerContext.id)
    }

    func peerDidDisconnect(_ peerContext: PeerContext) {
        disconnected.append(peerContext.id)
    }

    func peerDidReceiveMessage(_ peerContext: PeerContext, type: PacketType, payload: [UInt8]) {
        messages.append((peerContext.id, type, payload))
    }

    func currentHeight() -> UInt32 { height }
    func localNonce() -> [UInt8] { nonce }
    func localListenPort() -> UInt16 { 0 }
    func peerIsSelf(_ peerContext: PeerContext) {}
}

final class PeerMessageHandlerTests: XCTestCase {

    private func makePeerContext(id: UInt64 = 1) -> PeerContext {
        let addr = NetAddress(time: 0, services: 1, port: 52867)
        let state = PeerState(address: addr, outbound: false)
        return PeerContext(id: id, state: state, outbound: false)
    }

    /// Feed a framed packet into a MockByteStream.
    private func feedPacket(_ stream: MockByteStream, type: PacketType, payload: [UInt8], network: NetworkType = .regtest) {
        let frame = PacketFramer.encode(type: type, payload: payload, network: network)
        stream.feed(frame)
    }

    func testVersionExchange() async throws {
        let delegate = MockDelegate()
        let stream = MockByteStream()
        let peerContext = makePeerContext()

        let conn = PeerConnection(
            stream: stream,
            peerContext: peerContext,
            network: .regtest,
            useBrontide: false,
            delegate: delegate,
            userAgent: "/fbd:test/",
            logger: Logger(label: "test")
        )
        peerContext.connection = conn
        conn.start()

        // Wait for version to be sent
        try await Task.sleep(nanoseconds: 200_000_000)

        // Feed a version from remote
        let remoteVersion = VersionPacket(
            version: 3,
            services: 1,
            time: 1000,
            nonce: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            agent: "/hsd:6.0.0/",
            height: 50000
        )
        feedPacket(stream, type: .version, payload: remoteVersion.encode())

        try await Task.sleep(nanoseconds: 200_000_000)

        // Feed verack from remote
        feedPacket(stream, type: .verack, payload: VerackPacket().encode())

        try await Task.sleep(nanoseconds: 200_000_000)

        // Peer should be handshaked
        XCTAssertEqual(peerContext.state.connectionState, .handshaked)
        XCTAssertEqual(delegate.handshaked, [1])

        // Applied version data
        XCTAssertEqual(peerContext.state.version, 3)
        XCTAssertEqual(peerContext.state.agent, "/hsd:6.0.0/")
        XCTAssertEqual(peerContext.state.height, 50000)

        conn.close()
    }

    func testSelfConnectionDetection() async throws {
        let delegate = MockDelegate()
        delegate.nonce = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
        let stream = MockByteStream()
        let peerContext = makePeerContext()

        let conn = PeerConnection(
            stream: stream,
            peerContext: peerContext,
            network: .regtest,
            useBrontide: false,
            delegate: delegate,
            userAgent: "/fbd:test/",
            logger: Logger(label: "test")
        )
        peerContext.connection = conn
        conn.start()

        try await Task.sleep(nanoseconds: 200_000_000)

        // Feed a version with our own nonce
        let selfVersion = VersionPacket(
            version: 3,
            nonce: delegate.nonce
        )
        feedPacket(stream, type: .version, payload: selfVersion.encode())

        try await Task.sleep(nanoseconds: 200_000_000)

        // Should NOT be handshaked (self-connection detected)
        XCTAssertNotEqual(peerContext.state.connectionState, .handshaked)

        conn.close()
    }

    func testPingPongResponse() async throws {
        let delegate = MockDelegate()
        let stream = MockByteStream()
        let peerContext = makePeerContext()

        let conn = PeerConnection(
            stream: stream,
            peerContext: peerContext,
            network: .regtest,
            useBrontide: false,
            delegate: delegate,
            userAgent: "/fbd:test/",
            logger: Logger(label: "test")
        )
        peerContext.connection = conn
        conn.start()

        // Complete handshake first
        try await Task.sleep(nanoseconds: 200_000_000)
        let remoteVersion = VersionPacket(version: 3, nonce: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        feedPacket(stream, type: .version, payload: remoteVersion.encode())
        try await Task.sleep(nanoseconds: 100_000_000)
        feedPacket(stream, type: .verack, payload: VerackPacket().encode())
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(peerContext.state.connectionState, .handshaked)

        // Clear written bytes to check for pong
        stream.written.removeAll()

        // Send a ping
        let pingNonce: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
        feedPacket(stream, type: .ping, payload: PingPacket(nonce: pingNonce).encode())

        try await Task.sleep(nanoseconds: 200_000_000)

        // Should have sent pong — check written bytes for pong frame
        let written = stream.written
        var foundPong = false
        var accum = AccumulationBuffer()
        accum.append(written)
        while accum.readableBytes >= NetConstants.headerSize {
            guard let headerBytes = accum.peek(NetConstants.headerSize) else { break }
            guard let header = try? PacketFramer.decodeHeader(headerBytes, network: .regtest) else { break }
            let totalSize = NetConstants.headerSize + header.payloadSize
            guard accum.readableBytes >= totalSize else { break }
            _ = accum.consume(NetConstants.headerSize)
            let payload = header.payloadSize > 0 ? accum.consume(header.payloadSize) ?? [] : []
            if header.type == .pong {
                let pong = try PongPacket.decode(from: payload)
                XCTAssertEqual(pong.nonce, pingNonce)
                foundPong = true
            }
        }
        XCTAssertTrue(foundPong, "Should have sent pong")

        conn.close()
    }

    func testUnhandledMessageForwarded() async throws {
        let delegate = MockDelegate()
        let stream = MockByteStream()
        let peerContext = makePeerContext()

        let conn = PeerConnection(
            stream: stream,
            peerContext: peerContext,
            network: .regtest,
            useBrontide: false,
            delegate: delegate,
            userAgent: "/fbd:test/",
            logger: Logger(label: "test")
        )
        peerContext.connection = conn
        conn.start()

        // Complete handshake
        try await Task.sleep(nanoseconds: 200_000_000)
        let remoteVersion = VersionPacket(version: 3, nonce: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        feedPacket(stream, type: .version, payload: remoteVersion.encode())
        try await Task.sleep(nanoseconds: 100_000_000)
        feedPacket(stream, type: .verack, payload: VerackPacket().encode())
        try await Task.sleep(nanoseconds: 200_000_000)

        // Send a getblocks message (not handled internally)
        let payload: [UInt8] = [0x01, 0x02, 0x03]
        feedPacket(stream, type: .getblocks, payload: payload)

        try await Task.sleep(nanoseconds: 200_000_000)

        // Should have been forwarded to delegate
        XCTAssertEqual(delegate.messages.count, 1)
        XCTAssertEqual(delegate.messages[0].1, .getblocks)
        XCTAssertEqual(delegate.messages[0].2, payload)

        conn.close()
    }
}
