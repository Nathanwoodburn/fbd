import XCTest
import ExtCrypto
@testable import Net
@testable import Chain
@testable import Mining
import Base
import Protocol
import Consensus
import Mempool
import Logging

// MARK: - Test Helpers

/// Mine a valid regtest block header by iterating nonces.
private func mineRegtestHeader(
    time: UInt64,
    prevBlock: Hash256,
    merkleRoot: Hash256 = .zero,
    witnessRoot: Hash256 = .zero,
    treeRoot: Hash256 = .zero,
    bits: UInt32 = 0x207fffff
) throws -> BlockHeader {
    let target = Target256.fromCompact(bits)
    for nonce in UInt32(0)...UInt32.max {
        let header = BlockHeader(
            nonce: nonce,
            time: time,
            prevBlock: prevBlock,
            treeRoot: treeRoot,
            witnessRoot: witnessRoot,
            merkleRoot: merkleRoot,
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

private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}

private func makeLogger() -> Logger {
    var logger = Logger(label: "test.reorg")
    logger.logLevel = .debug
    return logger
}

private func makePeerContext(id: UInt64, height: UInt32) -> PeerContext {
    var state = PeerState(address: NetAddress(port: 32867), outbound: true)
    state.connectionState = .handshaked
    state.height = height
    let ctx = PeerContext(id: id, state: state, outbound: true)
    let stream = MockByteStream()
    let conn = PeerConnection(
        stream: stream,
        peerContext: ctx,
        network: .regtest,
        useBrontide: false,
        delegate: MockReorgPeerDelegate(),
        userAgent: "/test/",
        logger: makeLogger()
    )
    ctx.connection = conn
    return ctx
}

private final class MockReorgPeerDelegate: PeerMessageDelegate, @unchecked Sendable {
    func peerDidHandshake(_ peerContext: PeerContext) {}
    func peerDidDisconnect(_ peerContext: PeerContext) {}
    func peerDidReceiveMessage(_ peerContext: PeerContext, type: PacketType, payload: [UInt8]) {}
    func currentHeight() -> UInt32 { 0 }
    func localNonce() -> [UInt8] { [UInt8](repeating: 0, count: 8) }
    func localListenPort() -> UInt16 { 0 }
    func peerIsSelf(_ peerContext: PeerContext) {}
}

private final class MockReorgDelegate: ChainSyncDelegate {
    var peers: [UInt64: PeerContext] = [:]
    var bannedPeers: [(id: UInt64, reason: String)] = []
    var connectedBlocks: [(hash: Hash256, height: Int)] = []

    func syncGetPeer(id: UInt64) -> PeerContext? { peers[id] }
    func syncGetHandshakedPeers() -> [PeerContext] {
        peers.values.filter { $0.state.isHandshaked }
    }
    func syncBanPeer(id: UInt64, reason: String) {
        bannedPeers.append((id: id, reason: reason))
    }
    func syncDidConnectBlock(hash: Hash256, header: BlockHeader, proof: BalloonProof, fromPeer: UInt64?) {
        // Track connected blocks for assertions
    }
}

/// Build a full valid block (with coinbase, merkle roots, valid PoW) on top of a chain.
/// Returns the block and its chain entry.
private func mineFullBlock(
    chain: Chain,
    mempool: Mempool = Mempool(),
    time: UInt64? = nil
) throws -> (Block, ChainEntry) {
    let tip = chain.tip
    let bits = chain.getNextBits()
    let blockTime = time ?? (tip.time + 1)

    let treeRoot = try chain.getCurrentTreeRoot()

    let template = try BlockAssembler.assemble(
        tip: tip,
        mempool: mempool,
        address: .null,
        treeRoot: treeRoot,
        time: blockTime,
        bits: bits
    )

    let target = Target256.fromCompact(bits)
    for nonce in UInt32(0)...UInt32.max {
        let header = BlockHeader(
            nonce: nonce,
            time: template.header.time,
            prevBlock: template.header.prevBlock,
            treeRoot: template.header.treeRoot,
            reservedRoot: template.header.reservedRoot,
            witnessRoot: template.header.witnessRoot,
            merkleRoot: template.header.merkleRoot,
            version: template.header.version,
            bits: template.header.bits
        )
        let hash = try ProofOfWork.powHash(for: header, slots: 4)
        let hashNum = Target256(bigEndian: hash.bytes)
        if hashNum <= target {
            let proof = try ProofOfWork.powHashWithProof(
                for: header, params: ConsensusParams.params(for: .regtest)
            ).proof
            let txs = [template.coinbase] + template.transactions
            let block = Block(header: header, transactions: txs, balloonProof: proof)
            let entry = try chain.add(header: header, proof: proof)
            try chain.connectBlock(block, height: entry.height)
            return (block, entry)
        }
    }
    fatalError("Failed to mine block")
}

/// Build external headers (not added to any chain) from a given entry.
/// Returns the headers along with a scratch chain that tracks them.
private func buildForkHeaders(
    from entry: ChainEntry,
    count: Int,
    timeOffset: UInt64 = 0
) throws -> (headers: [BlockHeader], proofs: [BalloonProof]) {
    var headers: [BlockHeader] = []
    var proofs: [BalloonProof] = []
    var prevEntry = entry
    for i in 0..<count {
        let header = try mineRegtestHeader(
            time: prevEntry.time + 1 + timeOffset + UInt64(i),
            prevBlock: prevEntry.hash
        )
        let proof = regtestProof(for: header)
        prevEntry = try ChainEntry.fromBlock(header, prev: prevEntry, slots: 4)
        headers.append(header)
        proofs.append(proof)
    }
    return (headers, proofs)
}

// MARK: - Reorg Tests

final class ReorgTests: XCTestCase {

    private var tempDir: String!

    override func setUp() {
        super.setUp()
        tempDir = NSTemporaryDirectory() + "reorg_test_\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: tempDir)
        super.tearDown()
    }

    /// Create a chain with block store, UTXO, and name tree, then connect genesis.
    private func makeFullChain() throws -> Chain {
        let blocksDir = tempDir + "/blocks_\(UUID().uuidString)"
        let coinDir = tempDir + "/coins_\(UUID().uuidString)"
        let treeDir = tempDir + "/tree_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: blocksDir, withIntermediateDirectories: true)
        let blockStore = try BlockStore(blocksDir: blocksDir, network: .regtest)
        let coinDB = try CoinDatabase(path: coinDir, network: .regtest)
        let chain = try Chain(network: .regtest, blockStore: blockStore, coinDB: coinDB, treeDir: treeDir)
        chain.clockOverride = chain.tip.time
        let genesis = Genesis.block(for: .regtest)
        try chain.connectBlock(genesis, height: 0)
        return chain
    }

    /// Mine N full blocks on a chain, returning the blocks.
    @discardableResult
    private func buildFullChain(_ chain: Chain, count: Int) throws -> [Block] {
        var blocks: [Block] = []
        for _ in 0..<count {
            chain.clockOverride = chain.tip.time + 1
            let (block, _) = try mineFullBlock(chain: chain)
            blocks.append(block)
        }
        return blocks
    }

    // MARK: - Full Block Reorg with UTXO

    /// Test that a reorg with full blocks (block store + UTXO) properly truncates
    /// and reconnects. This is the basic reorg test with persistence.
    func testReorgWithBlockStoreAndUTXO() throws {
        let chain = try makeFullChain()

        // Build main chain: 5 blocks
        try buildFullChain(chain, count: 5)
        XCTAssertEqual(chain.tip.height, 5)
        XCTAssertEqual(chain.storedHeight, 5)
        let mainTipHash = chain.tip.hash

        // Track disconnect notifications
        var disconnectedHeights: [Int] = []
        chain.onBlockDisconnected = { _, height in
            disconnectedHeights.append(height)
        }

        // Build a longer fork from height 2 (fork point = block 2)
        let forkPoint = chain.getEntryByHeight(2)!
        let fork = try buildForkHeaders(from: forkPoint, count: 5, timeOffset: 100)

        // Add fork headers — this should trigger a reorg at the header that
        // pushes cumulative chainwork past our main chain
        for (i, header) in fork.headers.enumerated() {
            _ = try chain.add(header: header, proof: fork.proofs[i])
        }

        // Chain should have reorged: tip is on the fork, blocks truncated to fork point
        XCTAssertEqual(chain.tip.height, 7, "Tip should be at the fork tip (height 7)")
        XCTAssertEqual(chain.storedHeight, 2, "Blocks should be truncated to fork point")

        // Blocks 3, 4, 5 should have been disconnected
        XCTAssertEqual(disconnectedHeights.sorted(), [3, 4, 5])

        // Old main chain entries should still be in byHash
        XCTAssertTrue(chain.has(hash: mainTipHash))
    }

    // MARK: - ChainSync Reorg Recovery Tests

    /// Test the core bug: sync peer disconnects after a header reorg,
    /// no peer is ahead of the (inflated) header tip, and the node
    /// must recover via resetToStoredHeight.
    func testSyncPeerDisconnectAfterReorgRecovery() throws {
        let chain = try makeFullChain()

        let delegate = MockReorgDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        // Build 5 blocks
        try buildFullChain(chain, count: 5)
        XCTAssertEqual(chain.storedHeight, 5)

        // Set up two peers: peer 1 (the one that'll send the fork), peer 2 (the phone)
        let peer1 = makePeerContext(id: 1, height: 8)
        let peer2 = makePeerContext(id: 2, height: 5) // Phone at our stored height
        delegate.peers[1] = peer1
        delegate.peers[2] = peer2

        // Start header sync with peer 1
        sync.onPeerHandshake(peer1)
        XCTAssertEqual(sync.state, .syncingHeaders)

        // Peer 1 sends headers for a longer fork from height 2
        let forkPoint = chain.getEntryByHeight(2)!
        let fork = try buildForkHeaders(from: forkPoint, count: 6, timeOffset: 100)

        // Feed the fork headers — this triggers a reorg inside chain.add()
        sync.onHeaders(peer1, headers: fork.headers, proofs: fork.proofs)

        // After processing: tip is at fork height 8, blocks truncated to 2
        XCTAssertEqual(chain.tip.height, 8)
        XCTAssertEqual(chain.storedHeight, 2)
        // Should have transitioned to block download
        XCTAssertEqual(sync.state, .syncingBlocks)

        // Now peer 1 disconnects before sending any blocks
        delegate.peers.removeValue(forKey: 1)
        sync.onPeerDisconnect(peer1)

        // BEFORE FIX: node would be stuck in .idle with tip=8, stored=2
        // AFTER FIX: recoverOrphanedHeaders resets tip to stored height
        //            and starts syncing from peer 2

        // The tip should be reset to stored height (2)
        XCTAssertEqual(chain.tip.height, chain.storedHeight,
                       "Tip should be reset to stored height after recovery")

        // Sync should have started from peer 2 (height 5 > reset tip 2)
        XCTAssertEqual(sync.syncPeerId, 2,
                       "Should start syncing from peer 2 after recovery")
        XCTAssertEqual(sync.state, .syncingHeaders,
                       "Should be in syncingHeaders state after recovery")
    }

    /// Test that peer disconnect during syncingHeaders (after reorg already
    /// truncated blocks) triggers recovery. This covers the same code path
    /// as header timeout, which ultimately disconnects the peer.
    func testPeerDisconnectDuringSyncingHeadersAfterReorg() throws {
        let chain = try makeFullChain()

        let delegate = MockReorgDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        // Build 5 blocks
        try buildFullChain(chain, count: 5)

        // Set up peer 1 with fork, peer 2 at our height
        let peer1 = makePeerContext(id: 1, height: 10)
        let peer2 = makePeerContext(id: 2, height: 5)
        delegate.peers[1] = peer1
        delegate.peers[2] = peer2

        // Start sync, receive fork headers that cause partial reorg
        sync.onPeerHandshake(peer1)
        let forkPoint = chain.getEntryByHeight(2)!
        let fork = try buildForkHeaders(from: forkPoint, count: 4, timeOffset: 100)
        // Send partial headers — peer claims height 10 but only sends 4
        sync.onHeaders(peer1, headers: fork.headers, proofs: fork.proofs)

        // tip advanced via reorg, but peer claims more headers
        XCTAssertEqual(chain.tip.height, 6)
        XCTAssertEqual(chain.storedHeight, 2)
        XCTAssertEqual(sync.state, .syncingHeaders)

        // Peer 1 disconnects (simulates timeout behavior)
        delegate.peers.removeValue(forKey: 1)
        sync.onPeerDisconnect(peer1)

        // Recovery should reset tip to stored height
        XCTAssertEqual(chain.tip.height, chain.storedHeight,
                       "Tip should be reset after peer disconnect recovery")
        // Should start syncing from peer 2
        XCTAssertEqual(sync.syncPeerId, 2)
    }

    /// Test that invalid header during sync triggers recovery when blocks
    /// were already truncated by an earlier header in the same batch.
    func testInvalidHeaderAfterPartialReorgRecovery() throws {
        let chain = try makeFullChain()

        let delegate = MockReorgDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        // Build 5 blocks
        try buildFullChain(chain, count: 5)

        let peer1 = makePeerContext(id: 1, height: 10)
        let peer2 = makePeerContext(id: 2, height: 5)
        delegate.peers[1] = peer1
        delegate.peers[2] = peer2

        sync.onPeerHandshake(peer1)

        // Build fork headers that will cause a reorg
        let forkPoint = chain.getEntryByHeight(2)!
        let fork = try buildForkHeaders(from: forkPoint, count: 5, timeOffset: 100)

        // Feed the valid fork headers first — triggers reorg, truncates blocks to 2
        sync.onHeaders(peer1, headers: fork.headers, proofs: fork.proofs)
        XCTAssertEqual(chain.storedHeight, 2, "Blocks should be truncated after reorg")
        XCTAssertEqual(chain.tip.height, 7, "Tip should be at fork tip")

        // Now the last fork header's hash is the prevBlock for the bad header.
        // Send a bad header with wrong bits that chains off the fork tip.
        let lastForkEntry = chain.tip
        let badHeader = BlockHeader(
            time: lastForkEntry.time + 1,
            prevBlock: lastForkEntry.hash,
            bits: 0x1c00ffff  // Wrong difficulty for regtest
        )

        sync.onHeaders(peer1, headers: [badHeader], proofs: [regtestProof(for: badHeader)])

        // Peer 1 should be banned for the invalid header
        XCTAssertTrue(delegate.bannedPeers.contains(where: { $0.id == 1 }),
                       "Peer should be banned for bad header")

        // Recovery should have reset the orphaned headers
        let recovered = chain.tip.height == chain.storedHeight
                     || sync.syncPeerId == 2
        XCTAssertTrue(recovered, "Should recover from partial reorg + bad header")
    }

    /// Test that the miner check (storedHeight < tip.height) is unblocked
    /// after recovery resets the tip.
    func testMinerUnblockedAfterReorgRecovery() throws {
        let chain = try makeFullChain()

        let delegate = MockReorgDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        // Build 5 blocks
        try buildFullChain(chain, count: 5)

        let peer1 = makePeerContext(id: 1, height: 8)
        delegate.peers[1] = peer1

        // Start sync and receive fork that causes reorg
        sync.onPeerHandshake(peer1)
        let forkPoint = chain.getEntryByHeight(2)!
        let fork = try buildForkHeaders(from: forkPoint, count: 6, timeOffset: 100)
        sync.onHeaders(peer1, headers: fork.headers, proofs: fork.proofs)

        // Verify miner would be blocked
        XCTAssertTrue(chain.storedHeight < chain.tip.height,
                       "Miner should be blocked: stored < tip")

        // Peer disconnects, no replacement
        delegate.peers.removeAll()
        sync.onPeerDisconnect(peer1)

        // After recovery, miner should be unblocked
        XCTAssertEqual(chain.storedHeight, chain.tip.height,
                       "After recovery, stored should equal tip (miner unblocked)")
    }

    /// Test resetToStoredHeight properly cleans up chain state.
    func testResetToStoredHeightCleansUpState() throws {
        let chain = try makeFullChain()

        // Build 5 blocks
        try buildFullChain(chain, count: 5)

        // Add fork headers that cause a reorg (headers only, no blocks)
        let forkPoint = chain.getEntryByHeight(2)!
        let fork = try buildForkHeaders(from: forkPoint, count: 5, timeOffset: 100)
        for (i, header) in fork.headers.enumerated() {
            _ = try chain.add(header: header, proof: fork.proofs[i])
        }
        XCTAssertEqual(chain.tip.height, 7)
        XCTAssertEqual(chain.storedHeight, 2)

        // Reset to stored height
        try chain.resetToStoredHeight()

        // Tip should be at stored height
        XCTAssertEqual(chain.tip.height, 2)
        XCTAssertEqual(chain.tip.height, chain.storedHeight)

        // Fork entries above stored height should be removed from byHeight
        XCTAssertNil(chain.getEntryByHeight(3))
        XCTAssertNil(chain.getEntryByHeight(7))

        // Stored chain entries should still be accessible
        XCTAssertNotNil(chain.getEntryByHeight(0))
        XCTAssertNotNil(chain.getEntryByHeight(1))
        XCTAssertNotNil(chain.getEntryByHeight(2))
    }

    /// Test that recovery works when sync peer disconnect happens while in
    /// syncingBlocks state (the most likely real-world scenario).
    func testRecoveryFromSyncingBlocksState() throws {
        let chain = try makeFullChain()

        let delegate = MockReorgDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        // Build 10 blocks
        try buildFullChain(chain, count: 10)
        XCTAssertEqual(chain.storedHeight, 10)

        // Peer 1 has a longer fork, peer 2 is the "phone" at our height
        let peer1 = makePeerContext(id: 1, height: 15)
        let peer2 = makePeerContext(id: 2, height: 10)
        delegate.peers[1] = peer1
        delegate.peers[2] = peer2

        // Sync headers from peer 1 — includes fork that reorgs us
        sync.onPeerHandshake(peer1)
        let forkPoint = chain.getEntryByHeight(5)!
        let fork = try buildForkHeaders(from: forkPoint, count: 10, timeOffset: 100)
        sync.onHeaders(peer1, headers: fork.headers, proofs: fork.proofs)

        // Should be downloading blocks now
        XCTAssertEqual(sync.state, .syncingBlocks)
        XCTAssertEqual(chain.tip.height, 15)
        XCTAssertEqual(chain.storedHeight, 5) // Truncated to fork point

        // Peer 1 disconnects without sending any blocks
        delegate.peers.removeValue(forKey: 1)
        sync.onPeerDisconnect(peer1)

        // Recovery should kick in
        XCTAssertEqual(chain.tip.height, chain.storedHeight,
                       "Tip should be reset to stored height")

        // Should start syncing from peer 2
        XCTAssertEqual(sync.syncPeerId, 2)
        XCTAssertEqual(sync.state, .syncingHeaders)
    }

    /// Verify that recovery does NOT trigger when there's no header/block mismatch
    /// (normal peer disconnect without a reorg).
    func testNoRecoveryWhenNoOrphanedHeaders() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        let delegate = MockReorgDelegate()
        let sync = ChainSync(chain: chain, delegate: delegate, logger: makeLogger())

        let peer1 = makePeerContext(id: 1, height: 10)
        delegate.peers[1] = peer1

        sync.onPeerHandshake(peer1)
        XCTAssertEqual(sync.state, .syncingHeaders)

        // Peer disconnects normally (no reorg happened, no block store)
        delegate.peers.removeAll()
        sync.onPeerDisconnect(peer1)

        // Should just go idle, no recovery needed
        XCTAssertEqual(sync.state, .idle)
        XCTAssertEqual(chain.tip.height, 0) // Unchanged
    }
}
