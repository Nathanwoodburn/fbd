import XCTest
@testable import Covenants
import Base
@testable import Consensus
import ExtCrypto
import Protocol

// MARK: - Name Rules Tests

final class NameRulesTests: XCTestCase {

    func testValidNames() {
        XCTAssertTrue(NameRules.verifyName("alice"))
        XCTAssertTrue(NameRules.verifyName("bob123"))
        XCTAssertTrue(NameRules.verifyName("my-name"))
        XCTAssertTrue(NameRules.verifyName("myname"))
        XCTAssertTrue(NameRules.verifyName("a"))
        XCTAssertTrue(NameRules.verifyName("0"))
        XCTAssertTrue(NameRules.verifyName("a-b-c"))
    }

    func testInvalidNames() {
        // Empty
        XCTAssertFalse(NameRules.verifyName(""))
        // Too long
        XCTAssertFalse(NameRules.verifyName(String(repeating: "a", count: 64)))
        // Uppercase
        XCTAssertFalse(NameRules.verifyName("Alice"))
        XCTAssertFalse(NameRules.verifyName("HELLO"))
        // Hyphen at start/end
        XCTAssertFalse(NameRules.verifyName("-name"))
        XCTAssertFalse(NameRules.verifyName("name-"))
        // Underscores not allowed
        XCTAssertFalse(NameRules.verifyName("_name"))
        XCTAssertFalse(NameRules.verifyName("name_"))
        XCTAssertFalse(NameRules.verifyName("my_name"))
        // Invalid characters
        XCTAssertFalse(NameRules.verifyName("hello world"))
        XCTAssertFalse(NameRules.verifyName("hello@world"))
        XCTAssertFalse(NameRules.verifyName("héllo"))
        // Dot edge cases
        XCTAssertFalse(NameRules.verifyName(".hello"))
        XCTAssertFalse(NameRules.verifyName("hello."))
        XCTAssertFalse(NameRules.verifyName("hello..fistbump"))
    }

    func testValidSubdomainNames() {
        XCTAssertTrue(NameRules.verifyName("example.fistbump"))
        XCTAssertTrue(NameRules.verifyName("shop.mail.fistbump"))
        XCTAssertTrue(NameRules.verifyName("a.b"))
        XCTAssertTrue(NameRules.isSubdomain("example.fistbump"))
        XCTAssertFalse(NameRules.isSubdomain("hello"))
    }

    func testBlacklistedNames() {
        XCTAssertFalse(NameRules.verifyName("example"))
        XCTAssertFalse(NameRules.verifyName("invalid"))
        XCTAssertFalse(NameRules.verifyName("local"))
        XCTAssertFalse(NameRules.verifyName("localhost"))
        XCTAssertFalse(NameRules.verifyName("test"))
    }

    func testMaxLengthName() {
        let name = String(repeating: "a", count: 63)
        XCTAssertTrue(NameRules.verifyName(name))
    }

    func testHashName() {
        let hash = NameRules.hashName("alice")
        XCTAssertEqual(hash.bytes.count, 32)
        // Should be SHA3-256 of "alice"
        let expected = SHA3Hash.sha3_256(Array("alice".utf8))
        XCTAssertEqual(hash.bytes, expected.bytes)
    }

    func testHashNameDeterministic() {
        let hash1 = NameRules.hashName("bob")
        let hash2 = NameRules.hashName("bob")
        XCTAssertEqual(hash1, hash2)
    }

    func testHashNameDifferent() {
        let hash1 = NameRules.hashName("alice")
        let hash2 = NameRules.hashName("bob")
        XCTAssertNotEqual(hash1, hash2)
    }

    func testRolloutMainnet() {
        let nameHash = NameRules.hashName("alice")
        let (height, day) = NameRules.getRollout(nameHash: nameHash, params: .mainnet)
        // Day should be 0-59
        XCTAssertTrue(day >= 0 && day < 60)
        // Height should be auctionStart + day * rolloutInterval
        XCTAssertEqual(height, 10_080 + day * 720)
    }

    func testRolloutRegtest() {
        let nameHash = NameRules.hashName("alice")
        let (height, day) = NameRules.getRollout(nameHash: nameHash, params: .regtest)
        // Regtest has noRollout = true, so height=0
        XCTAssertEqual(height, 0)
        XCTAssertEqual(day, 0)
    }

    func testIsAvailable() {
        let nameHash = NameRules.hashName("alice")
        let (rolloutHeight, _) = NameRules.getRollout(nameHash: nameHash, params: .mainnet)

        XCTAssertFalse(NameRules.isAvailable(nameHash: nameHash, height: rolloutHeight - 1, params: .mainnet))
        XCTAssertTrue(NameRules.isAvailable(nameHash: nameHash, height: rolloutHeight, params: .mainnet))
        XCTAssertTrue(NameRules.isAvailable(nameHash: nameHash, height: rolloutHeight + 1, params: .mainnet))
    }
}

// MARK: - Name State Tests

final class NameStateTests: XCTestCase {

    func testInitialState() {
        let ns = NameState()
        XCTAssertEqual(ns.height, 0)
        XCTAssertEqual(ns.renewal, 0)
        XCTAssertNil(ns.owner)
        XCTAssertFalse(ns.registered)
        XCTAssertFalse(ns.expired)
    }

    func testAuctionStateOpening() {
        var ns = NameState()
        ns.height = 1000
        // Opening period = 30 blocks (1 hour)
        XCTAssertEqual(ns.state(at: 1000, params: .mainnet), .opening)
        XCTAssertEqual(ns.state(at: 1029, params: .mainnet), .opening) // last opening block
    }

    func testAuctionStateBidding() {
        var ns = NameState()
        ns.height = 1000
        // Bidding starts at height + 30
        XCTAssertEqual(ns.state(at: 1030, params: .mainnet), .bidding)
        // Bidding ends at height + 30 + 2160 - 1
        XCTAssertEqual(ns.state(at: 3189, params: .mainnet), .bidding)
    }

    func testAuctionStateReveal() {
        var ns = NameState()
        ns.height = 1000
        // Reveal starts at height + 30 + 2160
        XCTAssertEqual(ns.state(at: 3190, params: .mainnet), .reveal)
        // Reveal ends at height + 30 + 2160 + 720 - 1
        XCTAssertEqual(ns.state(at: 3909, params: .mainnet), .reveal)
    }

    func testAuctionStateClosed() {
        var ns = NameState()
        ns.height = 1000
        // Closed at height + 30 + 2160 + 720
        XCTAssertEqual(ns.state(at: 3910, params: .mainnet), .closed)
    }

    func testAuctionStateRevoked() {
        var ns = NameState()
        ns.height = 1000
        ns.revoked = 2000
        // Always revoked once set
        XCTAssertEqual(ns.state(at: 1000, params: .mainnet), .revoked)
        XCTAssertEqual(ns.state(at: 9999, params: .mainnet), .revoked)
    }

    func testIsExpired() {
        var ns = NameState()
        ns.height = 1000
        ns.renewal = 1000
        // Not expired during auction
        XCTAssertFalse(ns.isExpired(at: 1100, params: .mainnet))
        // No owner (nobody revealed) → expired once closed
        // Closed at 3910 (openEnd=1030, bidEnd=3190, revealEnd=3910)
        XCTAssertTrue(ns.isExpired(at: 3910, params: .mainnet))
        // With an owner but not registered → expires at register deadline
        // Register deadline = revealEnd + 2130 = 3910 + 2130 = 6040
        ns.owner = NameState.Outpoint(hash: [UInt8](repeating: 0xAA, count: 32), index: 0)
        XCTAssertFalse(ns.isExpired(at: 3910, params: .mainnet))
        XCTAssertFalse(ns.isExpired(at: 6039, params: .mainnet))
        XCTAssertFalse(ns.isExpired(at: 6040, params: .mainnet))
        XCTAssertTrue(ns.isExpired(at: 6041, params: .mainnet))
        // Once registered, not expired until renewal window
        ns.registered = true
        XCTAssertFalse(ns.isExpired(at: 6040, params: .mainnet))
        XCTAssertTrue(ns.isExpired(at: 1000 + 262_801, params: .mainnet))
    }

    func testIsExpiredAfterRevoke() {
        var ns = NameState()
        ns.height = 1000
        ns.revoked = 2000
        // Expired after auctionMaturity (5040)
        XCTAssertFalse(ns.isExpired(at: 2000 + 5_039, params: .mainnet))
        XCTAssertTrue(ns.isExpired(at: 2000 + 5_040, params: .mainnet))
    }

    func testSerializeDeserializeEmpty() throws {
        let ns = NameState()
        let data = ns.serialize()
        let decoded = try NameState.deserialize(from: data)
        XCTAssertEqual(decoded.height, 0)
        XCTAssertEqual(decoded.renewal, 0)
        XCTAssertNil(decoded.owner)
        XCTAssertFalse(decoded.registered)
    }

    func testCompactSizeVarintEncoding() throws {
        // Verify our serialization uses Bitcoin CompactSize format (matching hsd's bufio)
        // by checking specific byte patterns for a known name state.
        var ns = NameState()
        ns.name = Array("x".utf8)
        ns.height = 100
        ns.renewal = 100
        ns.value = 300  // > 252, so CompactSize = 0xFD + 2 bytes LE
        ns.highest = 500
        ns.owner = NameState.Outpoint(hash: [UInt8](repeating: 0, count: 32), index: 0)

        let data = ns.serialize()

        // Find the value field in serialized data:
        // name(1+1) + data(2+0) + height(4) + renewal(4) + bitfield(1) + owner(32+1) = 46
        // value at offset 46
        let valueOffset = 1 + 1 + 2 + 4 + 4 + 1 + 32 + 1  // = 46
        // CompactSize for 300 (0x012C): 0xFD 0x2C 0x01
        XCTAssertEqual(data[valueOffset], 0xFD, "CompactSize prefix for value 300")
        XCTAssertEqual(data[valueOffset + 1], 0x2C, "CompactSize low byte")
        XCTAssertEqual(data[valueOffset + 2], 0x01, "CompactSize high byte")

        // Round-trip
        let decoded = try NameState.deserialize(from: data)
        XCTAssertEqual(decoded.value, 300)
        XCTAssertEqual(decoded.highest, 500)
    }

    func testSerializeMatchesHSD() throws {
        // Cross-implementation test: verify our serialization produces
        // the exact same bytes as hsd's NameState.write().
        var ns = NameState()
        ns.name = Array("alice".utf8)
        ns.height = 1000
        ns.renewal = 2000
        ns.owner = NameState.Outpoint(
            hash: [UInt8](repeating: 0xBB, count: 32),
            index: 5
        )
        ns.value = 100_000_000
        ns.highest = 200_000_000
        ns.data = Array("test resource".utf8)
        ns.transfer = 3000
        ns.renewals = 3
        ns.registered = true

        let serialized = ns.serialize()
        let hex = serialized.map { String(format: "%02x", $0) }.joined()

        // Expected bytes (Bitcoin CompactSize varints, UInt8 bitfield):
        // bitfield = 0x6f (owner|value|highest|transfer|renewals|registered)
        let expectedHex = "05616c6963650d0074657374207265736f75726365e8030000d00700006fbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb05fe00e1f505fe00c2eb0bb80b000003"

        XCTAssertEqual(hex, expectedHex, "Serialization must match expected format")
    }

    func testSerializeDeserializeFull() throws {
        var ns = NameState()
        ns.name = Array("alice".utf8)
        ns.nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        ns.height = 1000
        ns.renewal = 2000
        ns.owner = NameState.Outpoint(
            hash: [UInt8](repeating: 0xBB, count: 32),
            index: 5
        )
        ns.value = 100_000_000
        ns.highest = 200_000_000
        ns.data = Array("test resource".utf8)
        ns.transfer = 3000
        ns.revoked = 0
        ns.renewals = 3
        ns.registered = true
        ns.expired = false

        let serialized = ns.serialize()
        let decoded = try NameState.deserialize(from: serialized)

        XCTAssertEqual(decoded.name, ns.name)
        XCTAssertEqual(decoded.height, 1000)
        XCTAssertEqual(decoded.renewal, 2000)
        XCTAssertEqual(decoded.owner?.hash, ns.owner?.hash)
        XCTAssertEqual(decoded.owner?.index, 5)
        XCTAssertEqual(decoded.value, 100_000_000)
        XCTAssertEqual(decoded.highest, 200_000_000)
        XCTAssertEqual(decoded.data, Array("test resource".utf8))
        XCTAssertEqual(decoded.transfer, 3000)
        XCTAssertEqual(decoded.revoked, 0)
        XCTAssertEqual(decoded.renewals, 3)
        XCTAssertTrue(decoded.registered)
        XCTAssertFalse(decoded.expired)
    }

    // MARK: - Truncated data bounds checks

    func testDeserializeThrowsOnTruncatedVarintFD() {
        // Build a minimal valid prefix: name + bitfield with value bit set
        var data = [UInt8]()
        data.append(5) // nameLen
        data.append(contentsOf: Array("hello".utf8)) // name
        data.append(contentsOf: [UInt8](repeating: 0xAA, count: 32)) // nameHash
        data.append(contentsOf: [0, 0, 0, 0]) // height
        data.append(contentsOf: [0, 0, 0, 0]) // renewal
        data.append(contentsOf: [UInt8](repeating: 0, count: 32)) // owner hash
        data.append(contentsOf: [0, 0, 0, 0]) // owner index
        let field: UInt8 = (1 << 1) // value bit set
        data.append(field)
        data.append(0) // zero-length resource data
        data.append(0) // registered = false
        // Now the deserializer expects a varint for value.
        // Append 0xFD (signals 2-byte varint) but only 1 trailing byte.
        data.append(0xFD)
        data.append(0x01) // needs one more byte

        XCTAssertThrowsError(try NameState.deserialize(from: data))
    }

    func testDeserializeThrowsOnTruncatedName() {
        // nameLen says 10 but only 3 bytes of name follow
        var data = [UInt8]()
        data.append(10) // nameLen = 10
        data.append(contentsOf: [0x61, 0x62, 0x63]) // only 3 bytes
        // No more data — should fail

        XCTAssertThrowsError(try NameState.deserialize(from: data))
    }

    // MARK: - Forward-compatible serialization

    func testSerializeFlagsNonzeroParentHashZeroWritesLengthByte() throws {
        var ns = NameState()
        ns.name = Array("test".utf8)
        ns.nameHash = NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))
        ns.flags = 1 // non-zero flags, parentHash stays .zero

        let data = ns.serialize()

        // Last 2 bytes should be [flags=1, parentHashLen=0]
        XCTAssertTrue(data.count >= 2)
        XCTAssertEqual(data[data.count - 2], 1, "flags byte should be 1")
        XCTAssertEqual(data[data.count - 1], 0, "parentHash length should be 0")

        // Round-trip
        let decoded = try NameState.deserialize(from: data)
        XCTAssertEqual(decoded.flags, 1)
        XCTAssertEqual(decoded.parentHash, .zero)
    }
}

// MARK: - Name Params Tests

final class NameParamsTests: XCTestCase {

    func testMainnetOpenPeriod() {
        XCTAssertEqual(NameParams.mainnet.openPeriod, 30)
    }

    func testMainnetTimings() {
        let p = NameParams.mainnet
        XCTAssertEqual(p.biddingPeriod, 2_160)
        XCTAssertEqual(p.revealPeriod, 720)
        XCTAssertEqual(p.registerDeadline, 2_130)
        XCTAssertEqual(p.renewalWindow, 262_800)
        XCTAssertEqual(p.transferLockup, 360)
        // Total auction cycle = 30 + 2160 + 720 + 2130 = 5040 blocks = 7 days
        XCTAssertEqual(p.openPeriod + p.biddingPeriod + p.revealPeriod + p.registerDeadline, 5_040)
    }

    func testRegtestRelaxed() {
        let p = NameParams.regtest
        XCTAssertTrue(p.noRollout)
        XCTAssertTrue(p.biddingPeriod < NameParams.mainnet.biddingPeriod)
    }
}

// MARK: - Blind Bid Tests

final class BlindBidTests: XCTestCase {

    func testBlindDeterministic() throws {
        let nonce = BidNonce(unchecked: [UInt8](repeating: 0x42, count: 32))
        let blind1 = try BlindBid.blind(value: 1_000_000, nonce: nonce)
        let blind2 = try BlindBid.blind(value: 1_000_000, nonce: nonce)
        XCTAssertEqual(blind1, blind2)
    }

    func testBlindDifferentValues() throws {
        let nonce = BidNonce(unchecked: [UInt8](repeating: 0x42, count: 32))
        let blind1 = try BlindBid.blind(value: 1_000_000, nonce: nonce)
        let blind2 = try BlindBid.blind(value: 2_000_000, nonce: nonce)
        XCTAssertNotEqual(blind1, blind2)
    }

    func testBlindDifferentNonces() throws {
        let nonce1 = BidNonce(unchecked: [UInt8](repeating: 0x01, count: 32))
        let nonce2 = BidNonce(unchecked: [UInt8](repeating: 0x02, count: 32))
        let blind1 = try BlindBid.blind(value: 1_000_000, nonce: nonce1)
        let blind2 = try BlindBid.blind(value: 1_000_000, nonce: nonce2)
        XCTAssertNotEqual(blind1, blind2)
    }

    func testBlindVerify() throws {
        let nonce = BidNonce(unchecked: [UInt8](repeating: 0xAB, count: 32))
        let value: UInt64 = 5_000_000
        let blind = try BlindBid.blind(value: value, nonce: nonce)

        XCTAssertTrue(try BlindBid.verify(blind: blind, value: value, nonce: nonce))
        XCTAssertFalse(try BlindBid.verify(blind: blind, value: value + 1, nonce: nonce))
    }

    func testBlindSize() throws {
        let blind = try BlindBid.blind(value: 0, nonce: .zero)
        XCTAssertEqual(blind.count, 32)
    }
}

// MARK: - Covenant Data Tests

final class CovenantDataTests: XCTestCase {

    func testMakeOpen() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let name = Array("alice".utf8)
        let covenant = CovenantData.makeOpen(nameHash: nameHash, name: name)

        XCTAssertEqual(covenant.type, .open)
        XCTAssertEqual(covenant.items.count, 3)
        XCTAssertEqual(covenant.items[0], nameHash.bytes)
        XCTAssertEqual(covenant.items[2], name)
    }

    func testMakeBid() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let name = Array("alice".utf8)
        let blind = [UInt8](repeating: 0xBB, count: 32)
        let covenant = CovenantData.makeBid(nameHash: nameHash, startHeight: 1000, name: name, blind: blind)

        XCTAssertEqual(covenant.type, .bid)
        XCTAssertEqual(covenant.items.count, 4)
        XCTAssertEqual(covenant.items[3], blind)
    }

    func testMakeReveal() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let nonce = BidNonce(unchecked: [UInt8](repeating: 0xCC, count: 32))
        let covenant = CovenantData.makeReveal(nameHash: nameHash, startHeight: 1000, nonce: nonce)

        XCTAssertEqual(covenant.type, .reveal)
        XCTAssertEqual(covenant.items.count, 3)
        XCTAssertEqual(covenant.items[2], nonce.bytes)
    }

    func testExtractNameHash() throws {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xDD, count: 32))
        let covenant = CovenantData.makeOpen(nameHash: nameHash, name: Array("bob".utf8))
        let extracted = try CovenantData.nameHash(from: covenant)
        XCTAssertEqual(extracted, nameHash)
    }

    func testExtractHeight() throws {
        let covenant = CovenantData.makeBid(
            nameHash: .zero,
            startHeight: 12345,
            name: Array("x".utf8),
            blind: [UInt8](repeating: 0, count: 32)
        )
        let height = try CovenantData.height(from: covenant)
        XCTAssertEqual(height, 12345)
    }

    func testMakeTransfer() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let addrHash = [UInt8](repeating: 0xEE, count: 20)
        let covenant = CovenantData.makeTransfer(
            nameHash: nameHash, startHeight: 2000, version: 0, addressHash: addrHash
        )
        XCTAssertEqual(covenant.type, .transfer)
        XCTAssertEqual(covenant.items.count, 4)
        XCTAssertEqual(covenant.items[2], [0])
        XCTAssertEqual(covenant.items[3], addrHash)
    }

    func testMakeFinalize() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let blockHash = [UInt8](repeating: 0xFF, count: 32)
        let covenant = CovenantData.makeFinalize(
            nameHash: nameHash, startHeight: 3000, name: Array("bob".utf8),
            flags: 0, claimed: 1000, renewals: 5, blockHash: blockHash
        )
        XCTAssertEqual(covenant.type, .finalize)
        XCTAssertEqual(covenant.items.count, 7)
    }

    func testMakeRevoke() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let covenant = CovenantData.makeRevoke(nameHash: nameHash, startHeight: 4000)
        XCTAssertEqual(covenant.type, .revoke)
        XCTAssertEqual(covenant.items.count, 2)
    }

    func testExtractRawName() throws {
        let name = Array("alice".utf8)
        let covenant = CovenantData.makeOpen(
            nameHash: .zero,
            name: name
        )
        let extracted = try CovenantData.rawName(from: covenant)
        XCTAssertEqual(extracted, name)
    }

    func testExtractBlindHash() throws {
        let blind = [UInt8](repeating: 0xBB, count: 32)
        let covenant = CovenantData.makeBid(
            nameHash: .zero,
            startHeight: 1000,
            name: Array("bob".utf8),
            blind: blind
        )
        let extracted = try CovenantData.blindHash(from: covenant)
        XCTAssertEqual(extracted, blind)
    }

    func testExtractNonce() throws {
        let nonce = BidNonce(unchecked: [UInt8](repeating: 0xCC, count: 32))
        let covenant = CovenantData.makeReveal(
            nameHash: .zero,
            startHeight: 1000,
            nonce: nonce
        )
        let extracted = try CovenantData.nonce(from: covenant)
        XCTAssertEqual(extracted, nonce)
    }

    func testExtractResource() throws {
        let resource = Array("test resource data".utf8)
        let covenant = CovenantData.makeRegister(
            nameHash: .zero,
            startHeight: 1000,
            resource: resource,
            blockHash: [UInt8](repeating: 0, count: 32)
        )
        let extracted = try CovenantData.resource(from: covenant)
        XCTAssertEqual(extracted, resource)
    }

    func testExtractBlockHash() throws {
        let blockHash = [UInt8](repeating: 0xFF, count: 32)
        let covenant = CovenantData.makeRegister(
            nameHash: .zero,
            startHeight: 1000,
            resource: Array("data".utf8),
            blockHash: blockHash
        )
        let extracted = try CovenantData.blockHash(from: covenant, itemIndex: 3)
        XCTAssertEqual(extracted, blockHash)
    }

    func testExtractAddressVersion() throws {
        let covenant = CovenantData.makeTransfer(
            nameHash: .zero,
            startHeight: 2000,
            version: 31,
            addressHash: [UInt8](repeating: 0xEE, count: 20)
        )
        let version = try CovenantData.addressVersion(from: covenant)
        XCTAssertEqual(version, 31)
    }

    func testExtractAddressHash() throws {
        let addrHash = [UInt8](repeating: 0xEE, count: 20)
        let covenant = CovenantData.makeTransfer(
            nameHash: .zero,
            startHeight: 2000,
            version: 0,
            addressHash: addrHash
        )
        let extracted = try CovenantData.addressHash(from: covenant)
        XCTAssertEqual(extracted, addrHash)
    }

    func testExtractNameHashEmpty() {
        let covenant = Covenant.none
        XCTAssertThrowsError(try CovenantData.nameHash(from: covenant)) { error in
            guard case CovenantsError.malformedCovenant = error else {
                XCTFail("Expected malformedCovenant, got \(error)")
                return
            }
        }
    }

    func testExtractAddressHashTooShort() {
        let covenant = Covenant(type: .transfer, items: [
            [UInt8](repeating: 0, count: 32),
            [0, 0, 0, 0],
            [0],
            [0xFF],  // 1 byte, too short (minimum is 2)
        ])
        XCTAssertThrowsError(try CovenantData.addressHash(from: covenant)) { error in
            guard case CovenantsError.malformedCovenant = error else {
                XCTFail("Expected malformedCovenant, got \(error)")
                return
            }
        }
    }
}

// MARK: - Covenant Verifier Tests

final class CovenantVerifierTests: XCTestCase {

    func testValidTransitions() {
        // NONE can go to NONE, OPEN, BID
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .none, to: .none))
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .none, to: .open))
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .none, to: .bid))

        // BID must go to REVEAL
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .bid, to: .reveal))

        // REVEAL can go to REGISTER or REDEEM
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .reveal, to: .register))
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .reveal, to: .redeem))

        // REGISTER can go to UPDATE, RENEW, TRANSFER, REVOKE
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .register, to: .update))
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .register, to: .renew))
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .register, to: .transfer))
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .register, to: .revoke))

        // TRANSFER can go to FINALIZE
        XCTAssertTrue(CovenantVerifier.isValidTransition(from: .transfer, to: .finalize))
    }

    func testInvalidTransitions() {
        // NONE cannot go to REGISTER
        XCTAssertFalse(CovenantVerifier.isValidTransition(from: .none, to: .register))
        // BID cannot go to NONE
        XCTAssertFalse(CovenantVerifier.isValidTransition(from: .bid, to: .none))
        // REVOKE goes nowhere
        XCTAssertFalse(CovenantVerifier.isValidTransition(from: .revoke, to: .none))
        XCTAssertFalse(CovenantVerifier.isValidTransition(from: .revoke, to: .update))
        // REGISTER cannot go to BID
        XCTAssertFalse(CovenantVerifier.isValidTransition(from: .register, to: .bid))
    }

    func testCheckCovenantSanityNone() throws {
        try CovenantVerifier.checkCovenantSanity(Covenant.none)
    }

    func testCheckCovenantSanityOpen() throws {
        let covenant = CovenantData.makeOpen(
            nameHash: .zero,
            name: Array("alice".utf8)
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityBid() throws {
        let covenant = CovenantData.makeBid(
            nameHash: .zero,
            startHeight: 1000,
            name: Array("alice".utf8),
            blind: [UInt8](repeating: 0, count: 32)
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityReveal() throws {
        let covenant = CovenantData.makeReveal(
            nameHash: .zero,
            startHeight: 1000,
            nonce: .zero
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityInvalid() {
        // OPEN with wrong item count
        let bad = Covenant(type: .open, items: [[0x01]])
        XCTAssertThrowsError(try CovenantVerifier.checkCovenantSanity(bad))
    }

    func testCheckCovenantSanityRegister() throws {
        let covenant = CovenantData.makeRegister(
            nameHash: .zero,
            startHeight: 1000,
            resource: Array("resource data".utf8),
            blockHash: [UInt8](repeating: 0, count: 32)
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityResourceTooLarge() {
        let bigResource = [UInt8](repeating: 0xFF, count: 513)
        let covenant = Covenant(type: .register, items: [
            [UInt8](repeating: 0, count: 32),
            [0, 0, 0, 0],
            bigResource,
            [UInt8](repeating: 0, count: 32),
        ])
        XCTAssertThrowsError(try CovenantVerifier.checkCovenantSanity(covenant)) { error in
            guard case CovenantsError.resourceTooLarge(513) = error else {
                XCTFail("Expected resourceTooLarge, got \(error)")
                return
            }
        }
    }

    func testCheckCovenantSanityUpdate() throws {
        let covenant = CovenantData.makeUpdate(
            nameHash: .zero,
            startHeight: 2000,
            resource: [UInt8](repeating: 0xAB, count: 100)
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityRenew() throws {
        let covenant = CovenantData.makeRenew(
            nameHash: .zero,
            startHeight: 3000,
            blockHash: [UInt8](repeating: 0xCC, count: 32)
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityTransfer() throws {
        let covenant = CovenantData.makeTransfer(
            nameHash: .zero,
            startHeight: 4000,
            version: 0,
            addressHash: [UInt8](repeating: 0xEE, count: 20)
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityFinalize() throws {
        let covenant = CovenantData.makeFinalize(
            nameHash: .zero,
            startHeight: 5000,
            name: Array("alice".utf8),
            flags: 0,
            claimed: 1000,
            renewals: 5,
            blockHash: [UInt8](repeating: 0xFF, count: 32)
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityRevoke() throws {
        let covenant = CovenantData.makeRevoke(
            nameHash: .zero,
            startHeight: 6000
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityRedeem() throws {
        let covenant = CovenantData.makeRedeem(
            nameHash: .zero,
            startHeight: 7000
        )
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCheckCovenantSanityNoneWithItems() {
        let covenant = Covenant(type: .none, items: [[0x01]])
        XCTAssertThrowsError(try CovenantVerifier.checkCovenantSanity(covenant)) { error in
            guard case CovenantsError.malformedCovenant = error else {
                XCTFail("Expected malformedCovenant, got \(error)")
                return
            }
        }
    }

    func testCheckCovenantSanityOpenBadNameHash() {
        let covenant = Covenant(type: .open, items: [
            [0x01],
            [0, 0, 0, 0],
            Array("a".utf8),
        ])
        XCTAssertThrowsError(try CovenantVerifier.checkCovenantSanity(covenant)) { error in
            guard case CovenantsError.malformedCovenant = error else {
                XCTFail("Expected malformedCovenant, got \(error)")
                return
            }
        }
    }

    func testCheckCovenantSanityTransferBadAddressHash() {
        let covenant = Covenant(type: .transfer, items: [
            [UInt8](repeating: 0, count: 32),
            [0, 0, 0, 0],
            [0],
            [0xFF],
        ])
        XCTAssertThrowsError(try CovenantVerifier.checkCovenantSanity(covenant)) { error in
            guard case CovenantsError.malformedCovenant = error else {
                XCTFail("Expected malformedCovenant, got \(error)")
                return
            }
        }
    }

    func testCovenantVerifierRegisterAccepts5Items() throws {
        // REGISTER with 5 items: nameHash, height, resource, blockHash, flags
        let covenant = CovenantData.makeRegister(
            nameHash: .zero,
            startHeight: 1000,
            resource: Array("data".utf8),
            blockHash: [UInt8](repeating: 0, count: 32),
            flags: 1
        )
        XCTAssertEqual(covenant.items.count, 5)
        try CovenantVerifier.checkCovenantSanity(covenant)
    }

    func testCovenantVerifierRegisterRejects6Items() {
        // REGISTER with 6 items should fail sanity check.
        let covenant = Covenant(type: .register, items: [
            [UInt8](repeating: 0, count: 32),  // nameHash
            [0, 0, 0, 0],                       // height
            Array("data".utf8),                  // resource
            [UInt8](repeating: 0, count: 32),   // blockHash
            [0x01],                              // flags
            [0xFF],                              // extra item
        ])
        XCTAssertThrowsError(try CovenantVerifier.checkCovenantSanity(covenant)) { error in
            guard case CovenantsError.malformedCovenant = error else {
                XCTFail("Expected malformedCovenant, got \(error)")
                return
            }
        }
    }
}

// MARK: - Minimum Bid Tests

final class MinimumBidTests: XCTestCase {

    func testIntegerMinimumBidMainnet() {
        let p = NameParams.mainnet
        let height = 0 // first block, reward = baseReward = 500_000_000

        // Premium TLD: reward * 100 / 1
        let premiumBid = p.minimumBid(atHeight: height, name: "abc")
        let reward = BlockReward.getReward(height: height)
        XCTAssertEqual(premiumBid, reward * 100 / 1)

        // Regular TLD: reward * 20 / 1
        let tldBid = p.minimumBid(atHeight: height, name: "fistbump")
        XCTAssertEqual(tldBid, reward * 20 / 1)

        // Sub-TLD: reward * 1 / 5
        let subBid = p.minimumBid(atHeight: height, name: "example.fistbump")
        XCTAssertEqual(subBid, reward * 1 / 5)
    }

    func testIntegerMinimumBidRegtest() {
        let p = NameParams.regtest
        // Regtest numerators are all 0, so minimumBid should always be 0.
        XCTAssertEqual(p.minimumBid(atHeight: 0, name: "abc"), 0)
        XCTAssertEqual(p.minimumBid(atHeight: 0, name: "fistbump"), 0)
        XCTAssertEqual(p.minimumBid(atHeight: 0, name: "example.fistbump"), 0)
        XCTAssertEqual(p.minimumBid(atHeight: 1000, name: "anything"), 0)
    }
}

// MARK: - Delegation Record Edge Cases

final class DelegationEdgeCaseTests: XCTestCase {

    func testContainsDelegationUnknownRecordType() {
        // An unknown record type (e.g., type 15) should be treated conservatively as delegation.
        let data: [UInt8] = [0, 15]
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }

    func testContainsDelegationMalformedDNSName() {
        // CNAME (type 9) with a DNS label whose length byte claims more data than available.
        // Label length byte = 50, but only 2 bytes follow.
        let data: [UInt8] = [0, 9, 50, 0xAA, 0xBB]
        // Should return true (conservative) because the DNS name is malformed.
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }

    func testContainsDelegationTruncatedTLSA() {
        // TLSA (type 11) needs at least 8 bytes of header before cert data.
        // Provide only 4 bytes total after the type byte.
        let data: [UInt8] = [0, 11, 0x01, 0xBB, 0x06, 0x03]
        // Should return true since the record is too short to parse.
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }
}

// MARK: - NameState Boundary Heights

final class NameStateBoundaryTests: XCTestCase {

    func testNameStateBoundaryHeights() {
        var ns = NameState()
        ns.height = 1000
        let p = NameParams.mainnet

        let openEnd = ns.height + p.openPeriod    // 1000 + 30 = 1030
        let bidEnd = openEnd + p.biddingPeriod     // 1030 + 2160 = 3190
        let revealEnd = bidEnd + p.revealPeriod    // 3190 + 720 = 3910

        // openEnd - 1 should still be .opening
        XCTAssertEqual(ns.state(at: openEnd - 1, params: p), .opening)
        // openEnd should be .bidding (first bidding block)
        XCTAssertEqual(ns.state(at: openEnd, params: p), .bidding)
        // bidEnd - 1 should still be .bidding
        XCTAssertEqual(ns.state(at: bidEnd - 1, params: p), .bidding)
        // bidEnd should be .reveal (first reveal block)
        XCTAssertEqual(ns.state(at: bidEnd, params: p), .reveal)
        // revealEnd - 1 should still be .reveal
        XCTAssertEqual(ns.state(at: revealEnd - 1, params: p), .reveal)
        // revealEnd should be .closed
        XCTAssertEqual(ns.state(at: revealEnd, params: p), .closed)
    }
}

// MARK: - Covenant Type Tests

final class CovenantTypeExtTests: XCTestCase {

    func testIsLinked() {
        XCTAssertFalse(CovenantType.none.isLinked)
        XCTAssertFalse(CovenantType.open.isLinked)
        XCTAssertFalse(CovenantType.bid.isLinked)
        XCTAssertTrue(CovenantType.reveal.isLinked)
        XCTAssertTrue(CovenantType.redeem.isLinked)
        XCTAssertTrue(CovenantType.register.isLinked)
        XCTAssertTrue(CovenantType.update.isLinked)
        XCTAssertTrue(CovenantType.renew.isLinked)
        XCTAssertTrue(CovenantType.transfer.isLinked)
        XCTAssertTrue(CovenantType.finalize.isLinked)
        XCTAssertTrue(CovenantType.revoke.isLinked)
    }

    func testIsDustworthy() {
        XCTAssertTrue(CovenantType.none.isDustworthy)
        XCTAssertTrue(CovenantType.bid.isDustworthy)
        XCTAssertFalse(CovenantType.register.isDustworthy)
        XCTAssertFalse(CovenantType.update.isDustworthy)
    }

    func testIsNonspendable() {
        XCTAssertFalse(CovenantType.none.isNonspendable)
        XCTAssertFalse(CovenantType.open.isNonspendable)
        XCTAssertFalse(CovenantType.redeem.isNonspendable)
        XCTAssertTrue(CovenantType.bid.isNonspendable)
        XCTAssertTrue(CovenantType.register.isNonspendable)
        XCTAssertTrue(CovenantType.revoke.isNonspendable)
    }

    func testIsUnspendable() {
        XCTAssertFalse(CovenantType.none.isUnspendable)
        XCTAssertFalse(CovenantType.register.isUnspendable)
        XCTAssertTrue(CovenantType.revoke.isUnspendable)
    }
}
