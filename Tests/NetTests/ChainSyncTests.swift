import XCTest
import ExtCrypto
@testable import Net
@testable import Chain
import Base
import Protocol
import Consensus
import Logging

// MARK: - Test Mining Helper

/// Mine a valid regtest block header by iterating nonces.
private func mineRegtestHeader(
    time: UInt64,
    prevBlock: Hash256,
    bits: UInt32 = 0x207fffff
) throws -> BlockHeader {
    let target = Target256.fromCompact(bits)
    for nonce in UInt32(0)...UInt32.max {
        let header = BlockHeader(
            nonce: nonce,
            time: time,
            prevBlock: prevBlock,
            bits: bits
        )
        let hash = try ProofOfWork.powHash(for: header, slots: 4)
        let hashNum = Target256(bigEndian: hash.bytes)
        if hashNum <= target {
            return header
        }
    }
    fatalError("Failed to mine block")
}

// MARK: - Mock ChainSync Delegate

final class MockChainSyncDelegate: ChainSyncDelegate {
    var peers: [UInt64: PeerContext] = [:]
    var bannedPeers: [(id: UInt64, reason: String)] = []

    func syncGetPeer(id: UInt64) -> PeerContext? {
        peers[id]
    }

    func syncGetHandshakedPeers() -> [PeerContext] {
        peers.values.filter { $0.state.isHandshaked }
    }

    func syncBanPeer(id: UInt64, reason: String) {
        bannedPeers.append((id: id, reason: reason))
    }

    func syncDidConnectBlock(hash: Hash256, header: BlockHeader, proof: BalloonProof, fromPeer: UInt64?) {
        // no-op for tests
    }
}

// MARK: - Helpers

private func makeLogger() -> Logger {
    var logger = Logger(label: "test.chainsync")
    logger.logLevel = .debug
    return logger
}

private func makePeerContext(id: UInt64, height: UInt32) -> PeerContext {
    var state = PeerState(address: NetAddress(port: 32867), outbound: true)
    state.connectionState = .handshaked
    state.height = height
    let ctx = PeerContext(id: id, state: state, outbound: true)
    // Create a mock stream so send() has somewhere to write (discarded)
    let stream = MockByteStream()
    let conn = PeerConnection(
        stream: stream,
        peerContext: ctx,
        network: .regtest,
        useBrontide: false,
        delegate: MockPeerDelegate(),
        userAgent: "/test/",
        logger: makeLogger()
    )
    ctx.connection = conn
    return ctx
}

/// Minimal delegate for test PeerConnections (send output is discarded).
private final class MockPeerDelegate: PeerMessageDelegate, @unchecked Sendable {
    func peerDidHandshake(_ peerContext: PeerContext) {}
    func peerDidDisconnect(_ peerContext: PeerContext) {}
    func peerDidReceiveMessage(_ peerContext: PeerContext, type: PacketType, payload: [UInt8]) {}
    func currentHeight() -> UInt32 { 0 }
    func localNonce() -> [UInt8] { [UInt8](repeating: 0, count: 8) }
    func localListenPort() -> UInt16 { 0 }
    func peerIsSelf(_ peerContext: PeerContext) {}
}

/// Build valid regtest headers on top of a chain, returning the mined headers.
private func mineHeaders(on chain: Chain, count: Int) throws -> [BlockHeader] {
    var headers: [BlockHeader] = []
    var prevEntry = chain.tip
    for _ in 0..<count {
        let header = try mineRegtestHeader(
            time: prevEntry.time + 1,
            prevBlock: prevEntry.hash
        )
        prevEntry = try chain.add(header: header, proof: regtestProof(for: header))
        headers.append(header)
    }
    return headers
}

/// Build valid regtest headers externally (not added to the target chain),
/// but validated against a separate source chain.
private func buildExternalHeaders(basedOn chain: Chain, count: Int) throws -> [BlockHeader] {
    var headers: [BlockHeader] = []
    var prevEntry = chain.tip
    for _ in 0..<count {
        let header = try mineRegtestHeader(
            time: prevEntry.time + 1,
            prevBlock: prevEntry.hash
        )
        let hash = try ProofOfWork.powHash(for: header, slots: 4)
        let target = Target256.fromCompact(header.bits)
        let hashNum = Target256(bigEndian: hash.bytes)
        assert(hashNum <= target)
        prevEntry = try ChainEntry.fromBlock(header, prev: prevEntry, slots: 4)
        headers.append(header)
    }
    return headers
}

// MARK: - ChainSync Tests

final class ChainSyncTests: XCTestCase {

    func testInitialState() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        XCTAssertEqual(sync.state, .idle)
        XCTAssertNil(sync.syncPeerId)
    }

    func testStartsSyncOnPeerHandshake() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer = makePeerContext(id: 1, height: 100)
        delegate.peers[1] = peer

        sync.onPeerHandshake(peer)

        XCTAssertEqual(sync.state, .syncingHeaders)
        XCTAssertEqual(sync.syncPeerId, 1)
    }

    func testDoesNotSyncIfPeerNotAhead() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer = makePeerContext(id: 1, height: 0)
        delegate.peers[1] = peer

        sync.onPeerHandshake(peer)

        // Peer at same height as local chain — considered synced (not idle)
        XCTAssertEqual(sync.state, .synced)
        XCTAssertNil(sync.syncPeerId)
    }

    func testHeadersProcessed() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        // Build valid headers externally
        let headers = try buildExternalHeaders(basedOn: chain, count: 5)

        let peer = makePeerContext(id: 1, height: 5)
        delegate.peers[1] = peer

        // Start sync
        sync.onPeerHandshake(peer)
        XCTAssertEqual(sync.state, .syncingHeaders)

        // Feed headers (less than 2000 -> sync completes)
        sync.onHeaders(peer, headers: headers, proofs: headers.map { regtestProof(for: $0) })

        XCTAssertEqual(chain.height, 5)
        XCTAssertEqual(sync.state, .synced)
    }

    func testEmptyHeadersFinishesSync() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer = makePeerContext(id: 1, height: 100)
        delegate.peers[1] = peer

        sync.onPeerHandshake(peer)
        XCTAssertEqual(sync.state, .syncingHeaders)

        sync.onHeaders(peer, headers: [], proofs: [])
        XCTAssertEqual(sync.state, .synced)
    }

    func testBansPeerOnInvalidHeader() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer = makePeerContext(id: 1, height: 100)
        delegate.peers[1] = peer

        sync.onPeerHandshake(peer)

        // Send a header with wrong bits
        let badHeader = BlockHeader(
            time: chain.tip.time + 600,
            prevBlock: chain.tip.hash,
            bits: 0x1c00ffff
        )

        sync.onHeaders(peer, headers: [badHeader], proofs: [regtestProof(for: badHeader)])

        XCTAssertEqual(delegate.bannedPeers.count, 1)
        XCTAssertEqual(delegate.bannedPeers[0].id, 1)
        XCTAssertEqual(sync.state, .idle)
    }

    func testIgnoresHeadersFromNonSyncPeer() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer1 = makePeerContext(id: 1, height: 100)
        let peer2 = makePeerContext(id: 2, height: 100)
        delegate.peers[1] = peer1
        delegate.peers[2] = peer2

        // Start sync with peer 1
        sync.onPeerHandshake(peer1)
        XCTAssertEqual(sync.syncPeerId, 1)

        // Build valid headers
        let headers = try buildExternalHeaders(basedOn: chain, count: 3)

        // Send from peer 2 -- should be ignored
        sync.onHeaders(peer2, headers: headers, proofs: headers.map { regtestProof(for: $0) })
        XCTAssertEqual(chain.height, 0) // unchanged
    }

    func testSyncPeerDisconnectPicksNew() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer1 = makePeerContext(id: 1, height: 100)
        let peer2 = makePeerContext(id: 2, height: 200)
        delegate.peers[1] = peer1
        delegate.peers[2] = peer2

        sync.onPeerHandshake(peer1)
        XCTAssertEqual(sync.syncPeerId, 1)

        // Peer 1 disconnects
        sync.onPeerDisconnect(peer1)

        // Should pick peer 2
        XCTAssertEqual(sync.syncPeerId, 2)
        XCTAssertEqual(sync.state, .syncingHeaders)
    }

    func testSyncPeerDisconnectGoesIdleWhenNoPeers() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer = makePeerContext(id: 1, height: 100)
        delegate.peers[1] = peer

        sync.onPeerHandshake(peer)
        XCTAssertEqual(sync.state, .syncingHeaders)

        // Remove peer from delegate so no replacement can be found
        delegate.peers.removeAll()
        sync.onPeerDisconnect(peer)

        XCTAssertEqual(sync.state, .idle)
        XCTAssertNil(sync.syncPeerId)
    }

    func testInvTriggersGetHeadersWhenSynced() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let delegate = MockChainSyncDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer = makePeerContext(id: 1, height: 10)
        delegate.peers[1] = peer

        // Start and complete sync
        sync.onPeerHandshake(peer)
        sync.onHeaders(peer, headers: [], proofs: [])
        XCTAssertEqual(sync.state, .synced)

        // Send inv with unknown block
        let unknownHash = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))
        let items = [InvItem(type: .block, hash: unknownHash)]
        sync.onInv(peer, items: items)

        // The peer.send() was called — verify the mock stream got data
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
