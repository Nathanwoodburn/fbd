import XCTest
@testable import Covenants
@testable import ExtCrypto
import Base
import Consensus
import Protocol

final class PremiumNameTests: XCTestCase {

    // MARK: - Premium Name Detection

    func testIsPremiumShortNames() {
        XCTAssertTrue(NameRules.isPremium("a"))       // 1 char
        XCTAssertTrue(NameRules.isPremium("abc"))     // 3 chars
        XCTAssertTrue(NameRules.isPremium("eskimo"))  // 6 chars (boundary)
        XCTAssertFalse(NameRules.isPremium("12345678")) // 8 chars (over limit)
    }

    func testIsPremiumLongNames() {
        XCTAssertFalse(NameRules.isPremium("1234567")) // 7 chars
        XCTAssertFalse(NameRules.isPremium("shakestation")) // 12 chars
        XCTAssertFalse(NameRules.isPremium("thisisaverylongname")) // 19 chars
    }

    func testIsPremiumRawName() {
        XCTAssertTrue(NameRules.isPremium(rawName: Array("test".utf8)))       // 4 bytes
        XCTAssertTrue(NameRules.isPremium(rawName: Array("eskimo".utf8)))     // 6 bytes (boundary)
        XCTAssertFalse(NameRules.isPremium(rawName: Array("1234567".utf8)))   // 7 bytes
        XCTAssertFalse(NameRules.isPremium(rawName: []))                      // 0 bytes
    }

    func testPremiumMaxLength() {
        XCTAssertEqual(NameRules.premiumNameMaxLength, 6)
    }

    // MARK: - Premium Covenant Builders

    func testMakePremiumOpen() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let name = Array("test".utf8)
        let proof = [UInt8](repeating: 0xBB, count: 100)

        let covenant = CovenantData.makePremiumOpen(nameHash: nameHash, name: name, dnssecProof: proof)
        XCTAssertEqual(covenant.type, .open)
        XCTAssertEqual(covenant.items.count, 4)
        XCTAssertEqual(covenant.items[0], nameHash.bytes)
        XCTAssertEqual(covenant.items[2], name)
        XCTAssertEqual(covenant.items[3], proof)
    }

    func testMakePremiumBid() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let name = Array("test".utf8)
        let blind = [UInt8](repeating: 0xCC, count: 32)
        let proof = [UInt8](repeating: 0xBB, count: 100)

        let covenant = CovenantData.makePremiumBid(
            nameHash: nameHash, startHeight: 1000,
            name: name, blind: blind, dnssecProof: proof
        )
        XCTAssertEqual(covenant.type, .bid)
        XCTAssertEqual(covenant.items.count, 5)
        XCTAssertEqual(covenant.items[0], nameHash.bytes)
        XCTAssertEqual(covenant.items[2], name)
        XCTAssertEqual(covenant.items[3], blind)
        XCTAssertEqual(covenant.items[4], proof)
    }

    func testRegularOpenUnchanged() {
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let name = Array("longname99".utf8)

        let covenant = CovenantData.makeOpen(nameHash: nameHash, name: name)
        XCTAssertEqual(covenant.type, .open)
        XCTAssertEqual(covenant.items.count, 3)
    }

    // MARK: - Covenant Verifier: Variable Item Counts

    func testOpenSanityRegular() throws {
        let covenant = Covenant(type: .open, items: [
            [UInt8](repeating: 0xAA, count: 32), // nameHash
            [0x00, 0x00, 0x00, 0x00],             // height
            Array("longname99".utf8),              // name
        ])
        XCTAssertNoThrow(try CovenantVerifier.checkCovenantSanity(covenant))
    }

    func testOpenSanityPremium() throws {
        let covenant = Covenant(type: .open, items: [
            [UInt8](repeating: 0xAA, count: 32), // nameHash
            [0x00, 0x00, 0x00, 0x00],             // height
            Array("test".utf8),                    // name
            [UInt8](repeating: 0xBB, count: 50),   // DNSSEC proof
        ])
        XCTAssertNoThrow(try CovenantVerifier.checkCovenantSanity(covenant))
    }

    func testOpenSanityBadItemCount() {
        let covenant = Covenant(type: .open, items: [
            [UInt8](repeating: 0xAA, count: 32),
            [0x00, 0x00, 0x00, 0x00],
            Array("test".utf8),
            [0xFF],
            [0xFF], // 5 items — invalid (max is 4)
        ])
        XCTAssertThrowsError(try CovenantVerifier.checkCovenantSanity(covenant))
    }

    func testBidSanityRegular() throws {
        let covenant = Covenant(type: .bid, items: [
            [UInt8](repeating: 0xAA, count: 32), // nameHash
            [0x00, 0x00, 0x00, 0x00],             // height
            Array("longname99".utf8),              // name
            [UInt8](repeating: 0xCC, count: 32),   // blind
        ])
        XCTAssertNoThrow(try CovenantVerifier.checkCovenantSanity(covenant))
    }

    func testBidSanityPremium() throws {
        let covenant = Covenant(type: .bid, items: [
            [UInt8](repeating: 0xAA, count: 32), // nameHash
            [0x00, 0x00, 0x00, 0x00],             // height
            Array("test".utf8),                    // name
            [UInt8](repeating: 0xCC, count: 32),   // blind
            [UInt8](repeating: 0xBB, count: 50),   // DNSSEC proof
        ])
        XCTAssertNoThrow(try CovenantVerifier.checkCovenantSanity(covenant))
    }

    // MARK: - Error Cases

    func testDNSSECErrorCases() {
        // Verify new error cases exist and are equatable
        let err1 = CovenantsError.dnssecProofRequired
        let err2 = CovenantsError.dnssecProofRequired
        XCTAssertEqual(err1, err2)

        let err3 = CovenantsError.devFundPaymentInsufficient()
        XCTAssertNotEqual(err1, err3)
    }

    // MARK: - NameParams DNSSEC Fields

    func testMainnetRequiresDNSSEC() {
        let params = NameParams.mainnet
        XCTAssertTrue(params.requireDNSSEC)
        XCTAssertEqual(params.dnssecGracePeriod, 3_600)
    }

    func testRegtestDisablesDNSSEC() {
        let params = NameParams.regtest
        XCTAssertFalse(params.requireDNSSEC)
        XCTAssertEqual(params.dnssecGracePeriod, 86_400)
    }

    // MARK: - ConsensusParams Dev Fund Fields

    func testDevFundAddressPresent() {
        let params = ConsensusParams.mainnet
        XCTAssertEqual(params.devFundAddress.count, 20)
        XCTAssertEqual(params.devFundVersion, 0)
    }

    func testRegtestDevFundAddress() {
        let params = ConsensusParams.regtest
        XCTAssertEqual(params.devFundAddress.count, 20)
        XCTAssertEqual(params.devFundVersion, 0)
    }
}
