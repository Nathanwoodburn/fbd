import XCTest
@testable import Net
import Base
import ExtCrypto
import Protocol
import Logging

final class PeerAddressTests: XCTestCase {

    private var tmpDir: String!

    override func setUp() {
        super.setUp()
        tmpDir = NSTemporaryDirectory() + "fbd-test-peers-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: tmpDir)
        super.tearDown()
    }

    private func makePeerManager(dataDir: String?) throws -> PeerManager {
        let config = PeerManagerConfig(
            network: .regtest,
            maxOutbound: 0,
            seeds: [],
            nodes: ["127.0.0.1:1:"],
            dataDir: dataDir
        )
        let key = try ExtCrypto.ECDSASigner.generatePrivateKey()
        let logger = Logger(label: "test")
        return try PeerManager(config: config, identityKey: key, logger: logger)
    }

    func testRoundTrip() throws {
        let path = tmpDir + "/peers.dat"
        let content = "1.2.3.4:32867:1700000000\n5.6.7.8:32867:1700001000\n"
        try content.write(toFile: path, atomically: true, encoding: .utf8)

        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()

        // Verify loaded
        XCTAssertEqual(pm.addressPoolCount, 2)

        // Save and read back
        pm.saveAddressPool()
        let saved = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertTrue(saved.contains("1.2.3.4:32867:1700000000"))
        XCTAssertTrue(saved.contains("5.6.7.8:32867:1700001000"))
    }

    func testMalformedLinesSkipped() throws {
        let path = tmpDir + "/peers.dat"
        let content = "bad-line\n1.2.3.4:32867:1700000000\n::\nnot:a:number:extra\n"
        try content.write(toFile: path, atomically: true, encoding: .utf8)

        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()
        XCTAssertEqual(pm.addressPoolCount, 1)
    }

    func testEmptyFile() throws {
        let path = tmpDir + "/peers.dat"
        try "".write(toFile: path, atomically: true, encoding: .utf8)

        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()
        XCTAssertEqual(pm.addressPoolCount, 0)
    }

    func testNoFile() throws {
        let pm = try makePeerManager(dataDir: tmpDir)
        pm.loadAddressPool()
        XCTAssertEqual(pm.addressPoolCount, 0)
    }

    func testMaxPoolRespected() throws {
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
}
