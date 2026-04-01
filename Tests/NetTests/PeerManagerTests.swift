import XCTest
@testable import Net
import Base
import ExtCrypto
import Protocol
import Logging

final class PeerManagerTests: XCTestCase {

    private var tmpDir: String!

    override func setUp() {
        super.setUp()
        tmpDir = NSTemporaryDirectory() + "fbd-pm-test-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        if let dir = tmpDir {
            try? FileManager.default.removeItem(atPath: dir)
        }
        super.tearDown()
    }

    private func makePeerManager(
        maxOutbound: Int = 0,
        maxInbound: Int = 20,
        nodes: [String] = ["127.0.0.1:1:"],
        dataDir: String? = nil
    ) throws -> PeerManager {
        let config = PeerManagerConfig(
            network: .regtest,
            maxOutbound: maxOutbound,
            maxInbound: maxInbound,
            seeds: [],
            nodes: nodes,
            dataDir: dataDir ?? tmpDir
        )
        let key = try ECDSASigner.generatePrivateKey()
        return try PeerManager(config: config, identityKey: key, logger: Logger(label: "test"))
    }

    // MARK: - Initialization

    func testPeerManagerInitialization() throws {
        let pm = try makePeerManager()
        XCTAssertEqual(pm.peerCount, 0)
        XCTAssertEqual(pm.handshakedCount, 0)
        XCTAssertEqual(pm.network, .regtest)
    }

    func testIdentityKeyGeneration() throws {
        let pm = try makePeerManager()
        XCTAssertEqual(pm.identityKey.bytes.count, 32)
        XCTAssertEqual(pm.identityPub.bytes.count, 33)
    }

    func testConfigPreserved() throws {
        let pm = try makePeerManager(maxOutbound: 4, maxInbound: 10)
        XCTAssertEqual(pm.config.maxOutbound, 4)
        XCTAssertEqual(pm.config.maxInbound, 10)
    }

    // MARK: - Peer Count

    func testInitialPeerCountZero() throws {
        let pm = try makePeerManager()
        XCTAssertEqual(pm.peerCount, 0)
    }

    func testHandshakedCountZero() throws {
        let pm = try makePeerManager()
        XCTAssertEqual(pm.handshakedCount, 0)
    }

    // MARK: - Address Pool

    func testAddressPoolLoadSaveRoundTrip() throws {
        let path = tmpDir + "/peers.dat"
        let content = "1.2.3.4:32867:1700000000\n5.6.7.8:32867:1700001000\n"
        try content.write(toFile: path, atomically: true, encoding: .utf8)

        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()
        XCTAssertEqual(pm.addressPoolCount, 2)

        pm.saveAddressPool()
        let saved = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertTrue(saved.contains("1.2.3.4:32867:1700000000"))
        XCTAssertTrue(saved.contains("5.6.7.8:32867:1700001000"))
    }

    func testAddressPoolMaxLimit() throws {
        let path = tmpDir + "/peers.dat"
        var content = ""
        for i in 0..<1100 {
            let a = (i >> 8) & 0xFF
            let b = i & 0xFF
            content += "10.0.\(a).\(b):32867:1700000000\n"
        }
        try content.write(toFile: path, atomically: true, encoding: .utf8)

        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()
        XCTAssertEqual(pm.addressPoolCount, 1000)
    }

    func testAddressPoolMalformedLinesSkipped() throws {
        let path = tmpDir + "/peers.dat"
        let content = "bad-line\n1.2.3.4:32867:1700000000\n::\n"
        try content.write(toFile: path, atomically: true, encoding: .utf8)

        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()
        XCTAssertEqual(pm.addressPoolCount, 1)
    }

    func testAddressPoolEmptyFile() throws {
        let path = tmpDir + "/peers.dat"
        try "".write(toFile: path, atomically: true, encoding: .utf8)

        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()
        XCTAssertEqual(pm.addressPoolCount, 0)
    }

    func testAddressPoolNoFile() throws {
        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()
        XCTAssertEqual(pm.addressPoolCount, 0)
    }

    // MARK: - BanMap

    func testBanMapBanAndCheck() {
        var banMap = BanMap()
        let ip: [UInt8] = [10, 0, 0, 1] + [UInt8](repeating: 0, count: 12)

        XCTAssertFalse(banMap.isBanned(ip, now: 1000))

        banMap.ban(ip, now: 1000)
        XCTAssertTrue(banMap.isBanned(ip, now: 1000))
        XCTAssertTrue(banMap.isBanned(ip, now: 1000 + NetConstants.banTime - 1))
    }

    func testBanMapExpiry() {
        var banMap = BanMap()
        let ip: [UInt8] = [10, 0, 0, 1] + [UInt8](repeating: 0, count: 12)

        banMap.ban(ip, now: 1000)
        XCTAssertTrue(banMap.isBanned(ip, now: 1000))

        // After ban time expires
        XCTAssertFalse(banMap.isBanned(ip, now: 1000 + NetConstants.banTime + 1))
    }

    func testBanMapCleanup() {
        var banMap = BanMap()
        let ip1: [UInt8] = [10, 0, 0, 1] + [UInt8](repeating: 0, count: 12)
        let ip2: [UInt8] = [10, 0, 0, 2] + [UInt8](repeating: 0, count: 12)

        banMap.ban(ip1, now: 1000)
        banMap.ban(ip2, now: 2000)

        XCTAssertEqual(banMap.entries.count, 2)

        // Cleanup at a time after ip1 expires but before ip2
        banMap.cleanup(now: 1000 + NetConstants.banTime + 1)
        XCTAssertEqual(banMap.entries.count, 1)
        XCTAssertFalse(banMap.isBanned(ip1, now: 1000 + NetConstants.banTime + 1))
        XCTAssertTrue(banMap.isBanned(ip2, now: 1000 + NetConstants.banTime + 1))
    }

    // MARK: - PeerState

    func testPeerStateInitialValues() {
        let addr = NetAddress(ip: [UInt8](repeating: 0, count: 16), port: 32867)
        let state = PeerState(address: addr, outbound: true)

        XCTAssertEqual(state.outbound, true)
        XCTAssertEqual(state.connectionState, .disconnected)
        XCTAssertEqual(state.banScore, 0)
        XCTAssertFalse(state.isHandshaked)
        XCTAssertFalse(state.isBanned)
    }

    func testPeerStateBanScoreThreshold() {
        let addr = NetAddress(ip: [UInt8](repeating: 0, count: 16), port: 32867)
        var state = PeerState(address: addr, outbound: false)

        // Not banned at 99
        _ = state.increaseBanScore(99)
        XCTAssertFalse(state.isBanned)

        // Banned at 100
        let banned = state.increaseBanScore(1)
        XCTAssertTrue(banned)
        XCTAssertTrue(state.isBanned)
    }

    func testPeerStateHandshaked() {
        let addr = NetAddress(ip: [UInt8](repeating: 0, count: 16), port: 32867)
        var state = PeerState(address: addr, outbound: true)

        XCTAssertFalse(state.isHandshaked)
        state.connectionState = .handshaked
        XCTAssertTrue(state.isHandshaked)
    }

    func testPeerStateRecordPing() {
        let addr = NetAddress(ip: [UInt8](repeating: 0, count: 16), port: 32867)
        var state = PeerState(address: addr, outbound: false)

        state.recordPing(rtt: 100)
        XCTAssertEqual(state.minPing, 100)
        XCTAssertEqual(state.lastPing, 100)

        state.recordPing(rtt: 50)
        XCTAssertEqual(state.minPing, 50)
        XCTAssertEqual(state.lastPing, 50)

        state.recordPing(rtt: 200)
        XCTAssertEqual(state.minPing, 50, "minPing should not increase")
        XCTAssertEqual(state.lastPing, 200)
    }

    // MARK: - Disconnect

    func testDisconnectNonexistentPeerReturnsFalse() throws {
        let pm = try makePeerManager()
        XCTAssertFalse(pm.disconnectPeer(id: 999))
    }

    func testDisconnectNonexistentAddressReturnsFalse() throws {
        let pm = try makePeerManager()
        XCTAssertFalse(pm.disconnectPeer(address: "1.2.3.4:32867"))
    }

    // MARK: - Local Nonce

    func testLocalNonceLength() throws {
        let pm = try makePeerManager()
        let nonce = pm.localNonce()
        XCTAssertEqual(nonce.count, 8)
    }

    // MARK: - Current Height

    func testCurrentHeightWithoutChain() throws {
        let pm = try makePeerManager()
        XCTAssertEqual(pm.currentHeight(), 0)
    }

    // MARK: - Sync Delegate

    func testSyncGetPeerNonexistent() throws {
        let pm = try makePeerManager()
        XCTAssertNil(pm.syncGetPeer(id: 42))
    }

    func testSyncGetHandshakedPeersEmpty() throws {
        let pm = try makePeerManager()
        XCTAssertEqual(pm.syncGetHandshakedPeers().count, 0)
    }

    // MARK: - Config Parsing

    func testConfiguredNodesWithKey() throws {
        let config = PeerManagerConfig(
            network: .regtest,
            nodes: ["1.2.3.4:32867:aabbccdd"]
        )
        XCTAssertEqual(config.nodes.count, 1)
        XCTAssertEqual(config.nodes[0], "1.2.3.4:32867:aabbccdd")
    }

    func testConfiguredSeedsVsNodes() throws {
        let configWithSeeds = PeerManagerConfig(
            network: .regtest,
            seeds: ["1.2.3.4:32867"]
        )
        XCTAssertEqual(configWithSeeds.seeds.count, 1)
        XCTAssertTrue(configWithSeeds.nodes.isEmpty)

        let configWithNodes = PeerManagerConfig(
            network: .regtest,
            nodes: ["5.6.7.8:32867"]
        )
        XCTAssertEqual(configWithNodes.nodes.count, 1)
        XCTAssertTrue(configWithNodes.seeds.isEmpty)
    }

    // MARK: - Network Type Properties

    func testRegTestDefaultPort() {
        XCTAssertEqual(NetworkType.regtest.defaultPort, 52867)
    }

    func testMainDefaultPort() {
        XCTAssertEqual(NetworkType.main.defaultPort, 32867)
    }

    // MARK: - Clean Error

    func testCleanErrorExtractsMessage() {
        let msg = PeerManager.cleanError(NetError.disconnected)
        XCTAssertFalse(msg.isEmpty)
    }
}
