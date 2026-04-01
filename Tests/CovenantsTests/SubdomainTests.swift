import XCTest
@testable import Covenants
import Base
import ExtCrypto
import Protocol

// MARK: - Subdomain Name Validation

final class SubdomainNameTests: XCTestCase {

    func testSubdomainDetection() {
        XCTAssertTrue(NameRules.isSubdomain("example.fistbump"))
        XCTAssertTrue(NameRules.isSubdomain("shop.mail.fistbump"))
        XCTAssertFalse(NameRules.isSubdomain("fistbump"))
        XCTAssertFalse(NameRules.isSubdomain("hello"))
    }

    func testSubdomainDetectionRawName() {
        XCTAssertTrue(NameRules.isSubdomain(rawName: Array("example.fistbump".utf8)))
        XCTAssertFalse(NameRules.isSubdomain(rawName: Array("fistbump".utf8)))
    }

    func testTLDLabel() {
        XCTAssertEqual(NameRules.tldLabel("shop.mail.fistbump"), "fistbump")
        XCTAssertEqual(NameRules.tldLabel("mail.fistbump"), "fistbump")
        XCTAssertEqual(NameRules.tldLabel("fistbump"), "fistbump")
        XCTAssertEqual(NameRules.tldLabel("example.fistbump"), "fistbump")
    }

    func testParentName() {
        XCTAssertEqual(NameRules.parentName("shop.mail.fistbump"), "mail.fistbump")
        XCTAssertEqual(NameRules.parentName("mail.fistbump"), "fistbump")
        XCTAssertNil(NameRules.parentName("fistbump"))
    }

    func testParentNameRawBytes() {
        let raw = Array("shop.mail.fistbump".utf8)
        let parent = NameRules.parentName(rawName: raw)
        XCTAssertEqual(parent, Array("mail.fistbump".utf8))

        XCTAssertNil(NameRules.parentName(rawName: Array("fistbump".utf8)))
    }

    func testAncestorHashes() {
        let ancestors = NameRules.ancestorHashes("shop.mail.fistbump")
        XCTAssertEqual(ancestors.count, 2)
        XCTAssertEqual(ancestors[0], NameRules.hashName("mail.fistbump"))
        XCTAssertEqual(ancestors[1], NameRules.hashName("fistbump"))
    }

    func testAncestorHashesSingleLevel() {
        let ancestors = NameRules.ancestorHashes("example.fistbump")
        XCTAssertEqual(ancestors.count, 1)
        XCTAssertEqual(ancestors[0], NameRules.hashName("fistbump"))
    }

    func testAncestorHashesTLD() {
        let ancestors = NameRules.ancestorHashes("fistbump")
        XCTAssertTrue(ancestors.isEmpty)
    }

    func testDepth() {
        XCTAssertEqual(NameRules.depth("fistbump"), 0)
        XCTAssertEqual(NameRules.depth("mail.fistbump"), 1)
        XCTAssertEqual(NameRules.depth("shop.mail.fistbump"), 2)
    }

    func testDotEdgeCases() {
        XCTAssertFalse(NameRules.verifyName(".fistbump"))
        XCTAssertFalse(NameRules.verifyName("fistbump."))
        XCTAssertFalse(NameRules.verifyName("hello..fistbump"))
        XCTAssertFalse(NameRules.verifyName(""))
    }

    func testLabelLengthLimits() {
        // Max label length is 63
        let maxLabel = String(repeating: "a", count: 63)
        XCTAssertTrue(NameRules.verifyName(maxLabel))
        XCTAssertTrue(NameRules.verifyName(maxLabel + ".fistbump"))

        // Label of 64 bytes is too long
        let tooLong = String(repeating: "a", count: 64)
        XCTAssertFalse(NameRules.verifyName(tooLong))
        XCTAssertFalse(NameRules.verifyName(tooLong + ".fistbump"))
        XCTAssertFalse(NameRules.verifyName("hello." + tooLong))

        // Total name up to 253 bytes is OK
        let longSub = String(repeating: "a", count: 63) + "." +
                       String(repeating: "b", count: 63) + "." +
                       String(repeating: "c", count: 63) + "." +
                       String(repeating: "d", count: 60) // 63+1+63+1+63+1+60 = 252
        XCTAssertTrue(NameRules.verifyName(longSub))

        // Over 253 total is rejected
        let tooLongTotal = String(repeating: "a", count: 63) + "." +
                           String(repeating: "b", count: 63) + "." +
                           String(repeating: "c", count: 63) + "." +
                           String(repeating: "d", count: 63) // 63+1+63+1+63+1+63 = 255
        XCTAssertFalse(NameRules.verifyName(tooLongTotal))
    }

    func testBlacklistedTLD() {
        // Subdomain with blacklisted TLD
        XCTAssertFalse(NameRules.verifyName("hello.test"))
        XCTAssertFalse(NameRules.verifyName("shop.localhost"))
        // Non-blacklisted
        XCTAssertTrue(NameRules.verifyName("example.fistbump"))
    }
}

// MARK: - Subdomain Covenant Data

final class SubdomainCovenantDataTests: XCTestCase {

    func testMakeSubdomainOpen() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let name = Array("example.fistbump".utf8)
        let parentHash = NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))
        let cov = CovenantData.makeSubdomainOpen(nameHash: nameHash, name: name, parentHash: parentHash)

        XCTAssertEqual(cov.type, .open)
        XCTAssertEqual(cov.items.count, 4)
        XCTAssertEqual(cov.items[0], nameHash.bytes)
        XCTAssertEqual(cov.items[2], name)
        XCTAssertEqual(cov.items[3], parentHash.bytes)
    }

    func testMakeSubdomainBid() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let name = Array("example.fistbump".utf8)
        let blind = [UInt8](repeating: 0xCC, count: 32)
        let parentHash = NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))
        let cov = CovenantData.makeSubdomainBid(
            nameHash: nameHash, startHeight: 100,
            name: name, blind: blind, parentHash: parentHash
        )

        XCTAssertEqual(cov.type, .bid)
        XCTAssertEqual(cov.items.count, 5)
        XCTAssertEqual(cov.items[4], parentHash.bytes)
    }

    func testExtractParentHashFromOpen() {
        let parentHash = NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))
        let cov = CovenantData.makeSubdomainOpen(
            nameHash: NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32)),
            name: Array("example.fistbump".utf8),
            parentHash: parentHash
        )
        XCTAssertEqual(CovenantData.parentHash(fromOpen: cov), parentHash)
    }

    func testExtractParentHashFromTLDOpen() {
        let cov = CovenantData.makeOpen(
            nameHash: NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32)),
            name: Array("fistbump".utf8)
        )
        XCTAssertNil(CovenantData.parentHash(fromOpen: cov))
    }

    func testMakeUpdateWithFlags() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let cov = CovenantData.makeUpdate(
            nameHash: nameHash, startHeight: 200,
            resource: [], flags: 1
        )
        XCTAssertEqual(cov.items.count, 4)
        XCTAssertEqual(cov.items[3], [1])
        XCTAssertEqual(CovenantData.flags(from: cov), 1)
    }

    func testExtractFlagsFromRegularUpdate() {
        let cov = CovenantData.makeUpdate(
            nameHash: .zero,
            startHeight: 200, resource: []
        )
        XCTAssertNil(CovenantData.flags(from: cov))
    }
}

// MARK: - NameState Flags & Serialization

final class SubdomainNameStateTests: XCTestCase {

    func testAuctionSubdomainsFlag() {
        var ns = NameState()
        XCTAssertFalse(ns.auctionSubdomains)
        ns.auctionSubdomains = true
        XCTAssertTrue(ns.auctionSubdomains)
        XCTAssertEqual(ns.flags & 1, 1)
        ns.auctionSubdomains = false
        XCTAssertFalse(ns.auctionSubdomains)
        XCTAssertEqual(ns.flags & 1, 0)
    }

    func testSerializeWithFlags() throws {
        var ns = NameState(nameHash: NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32)), name: Array("fistbump".utf8))
        ns.height = 100
        ns.renewal = 100
        ns.auctionSubdomains = true

        let data = ns.serialize()
        let decoded = try NameState.deserialize(from: data)
        XCTAssertTrue(decoded.auctionSubdomains)
        XCTAssertEqual(decoded.flags, 1)
    }

    func testSerializeWithParentHash() throws {
        var ns = NameState(nameHash: NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32)), name: Array("example.fistbump".utf8))
        ns.height = 100
        ns.renewal = 100
        ns.parentHash = NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))

        let data = ns.serialize()
        let decoded = try NameState.deserialize(from: data)
        XCTAssertEqual(decoded.parentHash, NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32)))
    }

    func testMaybeExpirePreservesFlags() {
        var ns = NameState(nameHash: NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32)), name: Array("fistbump".utf8))
        ns.height = 100
        ns.renewal = 100
        ns.auctionSubdomains = true
        ns.parentHash = NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))
        ns.data = Array("test".utf8)
        ns.owner = NameState.Outpoint(hash: [UInt8](repeating: 0xCC, count: 32), index: 0)

        // Force expiration (high enough height with no renewals)
        let expired = ns.maybeExpire(at: 500_000, params: .mainnet)
        XCTAssertTrue(expired)

        // Flags, parentHash, and data should be preserved
        XCTAssertTrue(ns.auctionSubdomains)
        XCTAssertEqual(ns.parentHash, NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32)))
        XCTAssertEqual(ns.data, Array("test".utf8))
        XCTAssertTrue(ns.expired)
        XCTAssertNil(ns.owner)
    }
}

// MARK: - Delegation Record Detection

final class DelegationDetectionTests: XCTestCase {

    func testEmptyResourceNoDelegation() {
        XCTAssertFalse(NameRules.containsDelegationRecords([]))
    }

    func testVersionOnlyNoDelegation() {
        // Just version byte, no records
        XCTAssertFalse(NameRules.containsDelegationRecords([0]))
    }

    func testARecordNoDelegation() {
        // version(0) + type(7=A) + 4 bytes IPv4
        let data: [UInt8] = [0, 7, 192, 168, 1, 1]
        XCTAssertFalse(NameRules.containsDelegationRecords(data))
    }

    func testAAAARecordNoDelegation() {
        // version(0) + type(8=AAAA) + 16 bytes IPv6
        var data: [UInt8] = [0, 8]
        data.append(contentsOf: [UInt8](repeating: 0, count: 16))
        XCTAssertFalse(NameRules.containsDelegationRecords(data))
    }

    func testNSRecordDetected() {
        // version(0) + type(1=NS) — NS is delegation
        let data: [UInt8] = [0, 1]
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }

    func testDSRecordDetected() {
        // version(0) + type(0=DS) — DS is delegation
        let data: [UInt8] = [0, 0]
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }

    func testSynth4RecordDetected() {
        // version(0) + type(4=SYNTH4) — delegation
        let data: [UInt8] = [0, 4]
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }

    func testMixedRecordsWithDelegation() {
        // version(0) + A record (type 7, 4 bytes) + NS record (type 1)
        let data: [UInt8] = [0, 7, 10, 0, 0, 1, 1]
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }

    func testTLSARecordNoDelegation() {
        // version(0) + type(11=TLSA) + port(2) + proto(1) + usage(1) + selector(1) + matchingType(1) + certLen(2) + cert
        let data: [UInt8] = [0, 11, 0x01, 0xBB, 6, 3, 1, 1, 0, 4, 0xAA, 0xBB, 0xCC, 0xDD]
        XCTAssertFalse(NameRules.containsDelegationRecords(data))
    }

    func testTXTRecordNoDelegation() {
        // version(0) + type(6=TXT) + count(1) + len(5) + "hello"
        let data: [UInt8] = [0, 6, 1, 5] + Array("hello".utf8)
        XCTAssertFalse(NameRules.containsDelegationRecords(data))
    }

    func testSUBRecordDetected() {
        // version(0) + type(13=SUB) — SUB conflicts with subdomain auctions
        let data: [UInt8] = [0, 13]
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }

    func testMixedRecordsWithSUB() {
        // version(0) + A record (type 7, 4 bytes) + SUB record (type 13)
        let data: [UInt8] = [0, 7, 10, 0, 0, 1, 13]
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }
}

// MARK: - Covenant Verifier Subdomain Support

final class SubdomainVerifierTests: XCTestCase {

    func testOpenSanitySubdomain() throws {
        // 4-item OPEN is valid (subdomain with parentHash)
        let cov = CovenantData.makeSubdomainOpen(
            nameHash: NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32)),
            name: Array("example.fistbump".utf8),
            parentHash: NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))
        )
        try CovenantVerifier.checkCovenantSanity(cov)
    }

    func testBidSanitySubdomain() throws {
        // 5-item BID is valid (subdomain with parentHash)
        let cov = CovenantData.makeSubdomainBid(
            nameHash: NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32)),
            startHeight: 100,
            name: Array("example.fistbump".utf8),
            blind: [UInt8](repeating: 0xCC, count: 32),
            parentHash: NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))
        )
        try CovenantVerifier.checkCovenantSanity(cov)
    }

    func testUpdateSanityWithFlags() throws {
        let cov = CovenantData.makeUpdate(
            nameHash: NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32)),
            startHeight: 200,
            resource: [],
            flags: 1
        )
        try CovenantVerifier.checkCovenantSanity(cov)
    }

    func testUpdateSanityBadFlags() {
        // Flags must be 1 byte — 2 bytes should fail
        let cov = Covenant(type: .update, items: [
            [UInt8](repeating: 0, count: 32),
            [0, 0, 0, 0],
            [],
            [0, 1], // 2 bytes — invalid
        ])
        XCTAssertThrowsError(try CovenantVerifier.checkCovenantSanity(cov))
    }

    func testContainsDelegationAllowsWalletRecord() {
        // WALLET record (type 14) with length 5 + 5 bytes address data.
        // WALLET is not a delegation record, so should return false.
        let data: [UInt8] = [0, 14, 5, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
        XCTAssertFalse(NameRules.containsDelegationRecords(data))
    }

    func testContainsDelegationBlocksMixedWithUnknown() {
        // A record (type 7, 4 bytes IPv4) followed by an unknown record type (type 15).
        let data: [UInt8] = [0, 7, 10, 0, 0, 1, 15]
        // The unknown type should trigger conservative true.
        XCTAssertTrue(NameRules.containsDelegationRecords(data))
    }
}
