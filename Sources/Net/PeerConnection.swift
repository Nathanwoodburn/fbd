import Foundation
import Base
import ExtCrypto
import Logging

/// A single P2P peer connection, replacing the entire NIO pipeline:
/// BrontideHandler + PacketDecoder + PacketEncoder + PeerMessageHandler.
///
/// Each connection runs an async read loop that:
/// 1. Reads bytes from the socket
/// 2. Optionally decrypts via Brontide
/// 3. Decodes packet frames
/// 4. Dispatches messages to the delegate
///
/// Writing encodes packet frames and optionally encrypts before sending.
public final class PeerConnection: @unchecked Sendable {

    /// Whether this side uses Brontide encryption.
    public let useBrontide: Bool

    /// The underlying byte stream.
    public let stream: AsyncByteStream

    /// The per-peer context.
    public let peerContext: PeerContext

    /// The network type (for packet framing).
    private let network: NetworkType

    /// Brontide handshake state — used only by the read loop after handshake.
    private var handshake: BrontideHandshake?

    /// Brontide send-side copy — protected by writeLock, used only for write().
    private var sendHandshake: BrontideHandshake?

    /// Logger.
    private let logger: Logger

    /// Delegate for peer lifecycle and message events.
    private weak var delegate: PeerMessageDelegate?

    /// User agent string for the version message.
    private let userAgent: String

    /// Accumulation buffer for incoming bytes.
    private var accumulator = AccumulationBuffer()

    /// Brontide decryption state: reading header or body.
    private enum BrontidePhase {
        case readingHeader
        case readingBody(Int) // payload length
    }
    private var brontidePhase: BrontidePhase = .readingHeader

    /// Version handshake state.
    private var versionSent = false
    private var versionReceived = false
    private var verackSent = false
    private var verackReceived = false

    /// Ping timer task.
    private var pingTask: Task<Void, Never>?

    /// Read loop task.
    private var readTask: Task<Void, Never>?

    /// Lock protecting writes (multiple tasks may call send).
    private let writeLock = NSLock()

    /// Queue of pending write data, drained by the write loop.
    private var writeQueue: [[UInt8]] = []
    private var writeWaiters: [CheckedContinuation<Void, Never>] = []
    private var writeTask: Task<Void, Never>?

    /// Whether the connection is closed.
    private var isClosed = false

    public init(
        stream: AsyncByteStream,
        peerContext: PeerContext,
        network: NetworkType,
        handshake: BrontideHandshake? = nil,
        useBrontide: Bool,
        delegate: PeerMessageDelegate,
        userAgent: String,
        logger: Logger
    ) {
        self.stream = stream
        self.peerContext = peerContext
        self.network = network
        self.handshake = handshake
        self.useBrontide = useBrontide
        self.delegate = delegate
        self.userAgent = userAgent
        self.logger = logger
    }

    // MARK: - Lifecycle

    /// Start the connection: perform Brontide handshake (if needed),
    /// then run the read loop.
    public func start() {
        startWriteLoop()
        readTask = Task { [weak self] in
            guard let self = self else { return }
            do {
                if self.useBrontide {
                    try await self.performBrontideHandshake()
                }

                // Start version exchange
                self.peerContext.state.connectionState = .connected
                self.peerContext.state.connectedAt = UInt64(Date().timeIntervalSince1970 * 1000)
                try await self.sendVersion()

                // Read loop
                try await self.readLoop()
            } catch {
                if !self.isClosed {
                    self.logger.warning("Peer \(self.peerContext.id) error: \(Self.cleanError(error))")
                }
            }
            self.handleDisconnect()
        }
    }

    /// Close the connection.
    public func close() {
        let wasAlreadyClosed: Bool
        let waiters: [CheckedContinuation<Void, Never>]
        do {
            writeLock.lock()
            defer { writeLock.unlock() }
            wasAlreadyClosed = isClosed
            isClosed = true
            waiters = writeWaiters
            writeWaiters.removeAll()
        }

        // Always resume pending write waiters to prevent leaked continuations.
        for w in waiters { w.resume() }

        guard !wasAlreadyClosed else { return }

        pingTask?.cancel()
        pingTask = nil
        readTask?.cancel()
        // Keep readTask handle — awaitDisconnect() needs it.
        writeTask?.cancel()
        writeTask = nil

        Task {
            await stream.close()
        }
    }

    /// Wait for the read loop to finish. Call after close() to ensure
    /// in-progress block processing completes before closing databases.
    public func awaitDisconnect() async {
        await readTask?.value
        readTask = nil
    }

    // MARK: - Sending

    /// Send a packet to this peer.
    public func send<P: Packet>(_ packet: P) {
        let msg = PeerMessage(type: P.type, payload: packet.encode())
        sendMessage(msg)
    }

    /// Send a PeerMessage (framed + optionally encrypted).
    public func sendMessage(_ msg: PeerMessage) {
        let frame = PacketFramer.encode(type: msg.type, payload: msg.payload, network: network)

        // Encrypt and enqueue under the write lock.
        let waiters: [CheckedContinuation<Void, Never>]
        do {
            writeLock.lock()
            defer { writeLock.unlock() }
            guard !isClosed else { return }
            if useBrontide, var hs = sendHandshake {
                let encrypted = try hs.write(frame)
                sendHandshake = hs
                writeQueue.append(encrypted)
            } else {
                writeQueue.append(frame)
            }
            waiters = writeWaiters
            writeWaiters.removeAll()
        } catch {
            logger.debug("Encrypt failed for peer \(peerContext.id): \(error)")
            close()
            return
        }
        for w in waiters { w.resume() }
    }

    /// Start the write loop that drains enqueued data serially.
    private func startWriteLoop() {
        writeTask = Task {
            // Strong self — the write loop must stay alive to resume
            // its continuation. Cleaned up via close()/handleDisconnect().
            while !self.isClosed && !Task.isCancelled {
                // Drain all queued data under lock.
                let pending: [[UInt8]]
                do {
                    self.writeLock.lock()
                    defer { self.writeLock.unlock() }
                    pending = self.writeQueue
                    self.writeQueue.removeAll(keepingCapacity: true)
                }

                if pending.isEmpty {
                    // Wait for new data or close signal.
                    await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                        self.writeLock.lock()
                        defer { self.writeLock.unlock() }
                        if !self.writeQueue.isEmpty || self.isClosed || Task.isCancelled {
                            cont.resume()
                        } else {
                            self.writeWaiters.append(cont)
                        }
                    }
                    continue
                }

                // Write each chunk serially.
                for data in pending {
                    do {
                        try await self.stream.write(data)
                    } catch {
                        if !self.isClosed {
                            self.logger.debug("Send failed to peer \(self.peerContext.id): \(error)")
                            self.close()
                        }
                        return
                    }
                }
            }
        }
    }

    // MARK: - Brontide Handshake

    private func performBrontideHandshake() async throws {
        guard var hs = handshake else { throw NetError.handshakeFailed("no handshake state") }

        // Handshake timeout
        let timeoutTask = Task {
            try await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
            self.logger.debug("Brontide handshake timeout for peer \(self.peerContext.id)")
            self.close()
        }

        defer { timeoutTask.cancel() }

        if hs.initiator {
            // Act 1: send
            let act1 = try hs.genActOne()
            try await stream.write(act1)

            // Act 2: receive
            let act2 = try await readExact(BrontideHandshake.actTwoSize)
            try hs.recvActTwo(act2)

            // Act 3: send
            let act3 = try hs.genActThree()
            try await stream.write(act3)
        } else {
            // Act 1: receive
            let act1 = try await readExact(BrontideHandshake.actOneSize)
            try hs.recvActOne(act1)

            // Act 2: send
            let act2 = try hs.genActTwo()
            try await stream.write(act2)

            // Act 3: receive
            let act3 = try await readExact(BrontideHandshake.actThreeSize)
            try hs.recvActThree(act3)
        }

        peerContext.remoteStaticKey = hs.remoteStatic
        // Split into separate send/receive copies to avoid data races.
        // write() uses sendHandshake (protected by writeLock),
        // readHeader()/readBody() use handshake (read loop only).
        handshake = hs
        sendHandshake = hs

        logger.debug("Brontide handshake complete", metadata: [
            "peer": "\(peerContext.id)",
        ])
    }

    /// Read exactly N bytes from the stream.
    private func readExact(_ count: Int) async throws -> [UInt8] {
        while accumulator.readableBytes < count {
            let data = try await stream.read()
            guard !data.isEmpty else {
                throw NetError.disconnected
            }
            accumulator.append(data)
        }
        guard let bytes = accumulator.consume(count) else {
            throw NetError.disconnected
        }
        return bytes
    }

    // MARK: - Read Loop

    private func readLoop() async throws {
        while !isClosed && !Task.isCancelled {
            let data = try await stream.read()
            guard !data.isEmpty else { break } // EOF
            accumulator.append(data)

            // Decode messages from the buffer
            var messages: [PeerMessage] = []
            if useBrontide {
                try drainBrontide(into: &messages)
            } else {
                try drainPlaintext(into: &messages)
            }

            // Process messages — heavy ones (headers/blocks) are dispatched
            // to a global queue so BalloonHash doesn't block the cooperative pool.
            for msg in messages {
                await processMessage(msg)
            }

            // Compact periodically to prevent unbounded growth
            if accumulator.readableBytes == 0 {
                accumulator.compact()
            }
        }
    }

    /// Drain accumulator for Brontide-encrypted connections.
    private func drainBrontide(into messages: inout [PeerMessage]) throws {
        guard var hs = handshake else { return }
        defer { handshake = hs }

        while accumulator.readableBytes > 0 {
            switch brontidePhase {
            case .readingHeader:
                let needed = NetConstants.brontideHeaderSize
                guard accumulator.readableBytes >= needed else { return }
                guard let bytes = accumulator.consume(needed) else { return }
                let payloadLen = try hs.readHeader(bytes)
                brontidePhase = .readingBody(payloadLen)

            case .readingBody(let payloadLen):
                let needed = payloadLen + 16
                guard accumulator.readableBytes >= needed else { return }
                guard let bytes = accumulator.consume(needed) else { return }
                let cleartext = try hs.readBody(bytes, length: payloadLen)
                // Feed cleartext into packet decoder
                try decodePackets(from: cleartext, into: &messages)
                brontidePhase = .readingHeader
            }
        }
    }

    /// Extract framed packets from a buffer, appending decoded messages.
    private func drainFrames(from buffer: inout AccumulationBuffer, into messages: inout [PeerMessage]) throws {
        while buffer.readableBytes >= NetConstants.headerSize {
            guard let headerBytes = buffer.peek(NetConstants.headerSize) else { return }
            let header = try PacketFramer.decodeHeader(headerBytes, network: network)
            let totalNeeded = NetConstants.headerSize + header.payloadSize
            guard buffer.readableBytes >= totalNeeded else { return }
            _ = buffer.consume(NetConstants.headerSize)
            let payload = header.payloadSize > 0 ? (buffer.consume(header.payloadSize) ?? []) : [UInt8]()
            messages.append(PeerMessage(type: header.type, payload: payload))
        }
    }

    /// Drain accumulator for plaintext connections — decode packets directly.
    private func drainPlaintext(into messages: inout [PeerMessage]) throws {
        try drainFrames(from: &accumulator, into: &messages)
    }

    /// Decode packet frames from decrypted cleartext bytes.
    /// Uses a local buffer since Brontide frames may contain partial/multiple packets.
    private var packetBuffer = AccumulationBuffer()

    private func decodePackets(from cleartext: [UInt8], into messages: inout [PeerMessage]) throws {
        packetBuffer.append(cleartext)
        guard packetBuffer.readableBytes <= 4_000_000 else { close(); return }
        try drainFrames(from: &packetBuffer, into: &messages)
        if packetBuffer.readableBytes == 0 { packetBuffer.compact() }
    }

    // MARK: - Message Handling

    /// Process a decoded message. Light messages (version, ping, etc.) are handled
    /// inline on the cooperative pool. Heavy messages (headers, blocks, etc.) are
    /// dispatched to a global queue so BalloonHash doesn't starve other async Tasks.
    private func processMessage(_ msg: PeerMessage) async {
        let now = currentTimeMillis()
        peerContext.state.markRecv(time: now)

        switch msg.type {
        case .version:
            handleVersion(payload: msg.payload)
        case .verack:
            handleVerack()
        case .ping:
            handlePing(payload: msg.payload)
        case .pong:
            handlePong(payload: msg.payload)
        case .sendheaders:
            peerContext.state.preferHeaders = true
        case .sendcmpct:
            if let pkt = try? SendCmpctPacket.decode(from: msg.payload) {
                peerContext.state.compactMode = pkt.mode
            }
        case .feefilter:
            if let pkt = try? FeeFilterPacket.decode(from: msg.payload) {
                peerContext.state.feeRate = pkt.rate
            }
        default:
            // Dispatch heavy message processing to global queue.
            // This prevents BalloonHash (in chain.add during header/block
            // processing) from blocking the Swift cooperative thread pool,
            // keeping pings, block serving, and other I/O responsive.
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                DispatchQueue.global(qos: .userInitiated).async { [self] in
                    self.delegate?.peerDidReceiveMessage(self.peerContext, type: msg.type, payload: msg.payload)
                    cont.resume()
                }
            }
        }
    }

    // MARK: - Version Handshake

    private func sendVersion() async throws {
        let height = delegate?.currentHeight() ?? 0
        let nonce = delegate?.localNonce() ?? [UInt8](repeating: 0, count: 8)
        let listenPort = delegate?.localListenPort() ?? 0

        let version = VersionPacket(
            version: NetConstants.protocolVersion,
            services: ServiceFlags.localServices.rawValue,
            time: UInt64(currentTimeMillis() / 1000),
            remote: peerContext.state.address,
            nonce: nonce,
            agent: userAgent,
            height: height,
            noRelay: false,
            listenPort: listenPort
        )

        let msg = PeerMessage(type: .version, payload: version.encode())
        try await sendMessageAsync(msg)
        versionSent = true
        peerContext.state.markSend(time: currentTimeMillis())
    }

    /// Async send for use in the read loop (version exchange).
    private func sendMessageAsync(_ msg: PeerMessage) async throws {
        // Use the same write queue to ensure serialized writes.
        sendMessage(msg)
    }

    private func handleVersion(payload: [UInt8]) {
        guard !versionReceived else {
            logger.debug("Duplicate version from peer \(peerContext.id)")
            return
        }

        do {
            let pkt = try VersionPacket.decode(from: payload)

            guard pkt.version >= NetConstants.minVersion else {
                logger.info("Peer \(peerContext.id) obsolete version: \(pkt.version)")
                close()
                return
            }

            // Self-connection detection
            if let localNonce = delegate?.localNonce(), pkt.nonce == localNonce {
                logger.info("Self-connection detected, closing peer \(peerContext.id)")
                delegate?.peerIsSelf(peerContext)
                close()
                return
            }

            peerContext.state.applyVersion(pkt)
            versionReceived = true

            logger.debug("Received version", metadata: [
                "peer": "\(peerContext.id)",
                "version": "\(pkt.version)",
                "agent": "\(pkt.agent)",
                "height": "\(pkt.height)",
            ])

            // Send verack
            sendMessage(PeerMessage(type: .verack, payload: VerackPacket().encode()))
            verackSent = true

            if !versionSent {
                // Responder — send version (shouldn't happen with our flow, but safe)
                sendMessage(PeerMessage(type: .version, payload: VersionPacket(
                    version: NetConstants.protocolVersion,
                    services: ServiceFlags.localServices.rawValue,
                    time: UInt64(currentTimeMillis() / 1000),
                    remote: peerContext.state.address,
                    nonce: delegate?.localNonce() ?? [UInt8](repeating: 0, count: 8),
                    agent: userAgent,
                    height: delegate?.currentHeight() ?? 0,
                    noRelay: false,
                    listenPort: delegate?.localListenPort() ?? 0
                ).encode()))
                versionSent = true
            }

            checkHandshakeComplete()
        } catch {
            logger.debug("Bad version from peer \(peerContext.id): \(error)")
            close()
        }
    }

    private func handleVerack() {
        verackReceived = true
        checkHandshakeComplete()
    }

    private func checkHandshakeComplete() {
        guard versionSent && versionReceived && verackSent && verackReceived else { return }
        guard peerContext.state.connectionState != .handshaked else { return }

        peerContext.state.connectionState = .handshaked

        // Send post-handshake negotiation
        sendMessage(PeerMessage(type: .sendheaders, payload: SendHeadersPacket().encode()))
        sendMessage(PeerMessage(type: .sendcmpct, payload: SendCmpctPacket(mode: 0, version: 1).encode()))

        // Start ping timer
        startPingTimer()

        delegate?.peerDidHandshake(peerContext)
    }

    // MARK: - Ping/Pong

    private func startPingTimer() {
        pingTask?.cancel()
        pingTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(NetConstants.pingInterval) * 1_000_000)
                guard let self = self, !self.isClosed else { break }

                // Check if last ping went unanswered (pong timeout)
                if !self.peerContext.state.lastPingNonce.isEmpty {
                    let elapsed = self.currentTimeMillis() - self.peerContext.state.lastPingSent
                    if elapsed > NetConstants.pongTimeout {
                        self.logger.info("Peer \(self.peerContext.id) pong timeout (\(elapsed)ms)")
                        self.close()
                        break
                    }
                }

                self.sendPing()
            }
        }
    }

    private func sendPing() {
        var nonce = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 { nonce[i] = UInt8.random(in: 0...255) }

        peerContext.state.lastPingNonce = nonce
        peerContext.state.lastPingSent = currentTimeMillis()

        sendMessage(PeerMessage(type: .ping, payload: PingPacket(nonce: nonce).encode()))
        peerContext.state.markSend(time: currentTimeMillis())
    }

    private func handlePing(payload: [UInt8]) {
        guard let pkt = try? PingPacket.decode(from: payload) else { return }
        sendMessage(PeerMessage(type: .pong, payload: PongPacket(nonce: pkt.nonce).encode()))
        peerContext.state.markSend(time: currentTimeMillis())
    }

    private func handlePong(payload: [UInt8]) {
        guard let pkt = try? PongPacket.decode(from: payload) else { return }
        guard pkt.nonce == peerContext.state.lastPingNonce else { return }

        let now = currentTimeMillis()
        let rtt = now - peerContext.state.lastPingSent
        peerContext.state.recordPing(rtt: rtt)
        peerContext.state.lastPingNonce = []
    }

    // MARK: - Disconnect

    /// Whether the disconnect delegate callback has already fired.
    private var disconnectFired = false

    private func handleDisconnect() {
        let wasAlreadyClosed: Bool
        let waiters: [CheckedContinuation<Void, Never>]
        do {
            writeLock.lock()
            defer { writeLock.unlock() }
            guard !disconnectFired else { return }
            disconnectFired = true
            wasAlreadyClosed = isClosed
            isClosed = true
            waiters = writeWaiters
            writeWaiters.removeAll()
        }

        // Always resume pending write waiters.
        for w in waiters { w.resume() }

        if !wasAlreadyClosed {
            pingTask?.cancel()
            writeTask?.cancel()
            Task { await stream.close() }
        }
        pingTask = nil
        peerContext.state.connectionState = .destroyed
        delegate?.peerDidDisconnect(peerContext)
        // Break retain cycle: PeerConnection ↔ PeerContext
        peerContext.connection = nil
    }

    // MARK: - Helpers

    private func currentTimeMillis() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }

    /// Extract a human-readable message from socket errors.
    static func cleanError(_ error: Error) -> String {
        String(describing: error)
    }
}
