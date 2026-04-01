import XCTest
@testable import Net
import Base
import Protocol

final class BanScoreTests: XCTestCase {

    func testInitialBanScore() {
        let addr = NetAddress(time: 0, services: 0, ip: [UInt8](repeating: 0, count: 16), port: 0)
        let state = PeerState(address: addr, outbound: true)
        XCTAssertEqual(state.banScore, 0)
        XCTAssertFalse(state.isBanned)
    }

    func testBelowThreshold() {
        let addr = NetAddress(time: 0, services: 0, ip: [UInt8](repeating: 0, count: 16), port: 0)
        var state = PeerState(address: addr, outbound: true)
        state.increaseBanScore(50)
        XCTAssertEqual(state.banScore, 50)
        XCTAssertFalse(state.isBanned)

        state.increaseBanScore(49)
        XCTAssertEqual(state.banScore, 99)
        XCTAssertFalse(state.isBanned)
    }

    func testAtThreshold() {
        let addr = NetAddress(time: 0, services: 0, ip: [UInt8](repeating: 0, count: 16), port: 0)
        var state = PeerState(address: addr, outbound: true)
        let banned = state.increaseBanScore(100)
        XCTAssertTrue(banned)
        XCTAssertTrue(state.isBanned)
        XCTAssertEqual(state.banScore, 100)
    }

    func testAboveThreshold() {
        let addr = NetAddress(time: 0, services: 0, ip: [UInt8](repeating: 0, count: 16), port: 0)
        var state = PeerState(address: addr, outbound: true)
        let banned = state.increaseBanScore(200)
        XCTAssertTrue(banned)
        XCTAssertTrue(state.isBanned)
    }

    func testBanMapBanAndExpiry() {
        var banMap = BanMap()
        let ip: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4]
        let now: UInt64 = 1_000_000

        XCTAssertFalse(banMap.isBanned(ip, now: now))

        banMap.ban(ip, now: now)
        XCTAssertTrue(banMap.isBanned(ip, now: now))
        XCTAssertTrue(banMap.isBanned(ip, now: now + 86_399))

        // After 24 hours, should no longer be banned
        XCTAssertFalse(banMap.isBanned(ip, now: now + 86_400))
    }

    func testBanMapCleanup() {
        var banMap = BanMap()
        let ip1: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4]
        let ip2: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 5, 6, 7, 8]

        banMap.ban(ip1, now: 1_000_000)
        banMap.ban(ip2, now: 1_050_000)

        // Before cleanup, both are banned
        XCTAssertEqual(banMap.entries.count, 2)

        // Cleanup after ip1 expires but ip2 is still active
        banMap.cleanup(now: 1_090_000)
        XCTAssertEqual(banMap.entries.count, 1)
        XCTAssertFalse(banMap.isBanned(ip1, now: 1_090_000))
        XCTAssertTrue(banMap.isBanned(ip2, now: 1_090_000))
    }
}
