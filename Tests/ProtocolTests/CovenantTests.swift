import XCTest
@testable import Protocol
import Base

final class CovenantTests: XCTestCase {

    func testCovenantNoneRoundTrip() throws {
        let cov = Covenant.none
        var writer = BufferWriter()
        cov.write(to: &writer)

        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .none)
        XCTAssertTrue(decoded.items.isEmpty)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testCovenantNoneSerialization() {
        let cov = Covenant.none
        var writer = BufferWriter()
        cov.write(to: &writer)
        // type=0x00, itemCount=0x00
        XCTAssertEqual(writer.data, [0x00, 0x00])
    }

    func testCovenantWithItemsRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0xAB, count: 32)
        let height: [UInt8] = [0x00, 0x01, 0x00, 0x00] // uint32 256 LE
        let cov = Covenant(type: .open, items: [nameHash, height])

        var writer = BufferWriter()
        cov.write(to: &writer)
        XCTAssertEqual(cov.serializedSize, writer.count)

        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .open)
        XCTAssertEqual(decoded.items.count, 2)
        XCTAssertEqual(decoded.items[0], nameHash)
        XCTAssertEqual(decoded.items[1], height)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testCovenantTypeProperties() {
        XCTAssertFalse(CovenantType.none.isName)
        XCTAssertTrue(CovenantType.open.isName)
        // isLinked: REVEAL through REVOKE (types 4-11)
        XCTAssertFalse(CovenantType.bid.isLinked)
        XCTAssertFalse(CovenantType.none.isLinked)
        XCTAssertFalse(CovenantType.open.isLinked)
        XCTAssertTrue(CovenantType.reveal.isLinked)
        XCTAssertTrue(CovenantType.register.isLinked)
    }

    func testUnknownCovenantTypeThrows() {
        var reader = BufferReader([0xFF, 0x00])
        XCTAssertThrowsError(try Covenant.read(from: &reader))
    }

    // MARK: - All Covenant Type Round-Trips

    func testBidRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0xAA, count: 32)
        let height: [UInt8] = [0x10, 0x00, 0x00, 0x00]
        let blindHash = [UInt8](repeating: 0xBB, count: 32)
        let cov = Covenant(type: .bid, items: [nameHash, height, blindHash])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .bid)
    }

    func testRevealRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0xCC, count: 32)
        let height: [UInt8] = [0x20, 0x00, 0x00, 0x00]
        let nonce = [UInt8](repeating: 0xDD, count: 32)
        let cov = Covenant(type: .reveal, items: [nameHash, height, nonce])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .reveal)
    }

    func testRedeemRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0xEE, count: 32)
        let height: [UInt8] = [0x30, 0x00, 0x00, 0x00]
        let cov = Covenant(type: .redeem, items: [nameHash, height])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .redeem)
    }

    func testRegisterRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0xAA, count: 32)
        let height: [UInt8] = [0x40, 0x00, 0x00, 0x00]
        let data: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05]
        let hash = [UInt8](repeating: 0xBB, count: 32)
        let cov = Covenant(type: .register, items: [nameHash, height, data, hash])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .register)
        XCTAssertEqual(decoded.items.count, 4)
    }

    func testUpdateRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0xCC, count: 32)
        let height: [UInt8] = [0x50, 0x00, 0x00, 0x00]
        let data: [UInt8] = [0x0A, 0x0B, 0x0C]
        let cov = Covenant(type: .update, items: [nameHash, height, data])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .update)
    }

    func testRenewRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0xDD, count: 32)
        let height: [UInt8] = [0x60, 0x00, 0x00, 0x00]
        let blockHash = [UInt8](repeating: 0xEE, count: 32)
        let cov = Covenant(type: .renew, items: [nameHash, height, blockHash])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .renew)
    }

    func testTransferRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0x11, count: 32)
        let height: [UInt8] = [0x70, 0x00, 0x00, 0x00]
        let address = [UInt8](repeating: 0x22, count: 20)
        let cov = Covenant(type: .transfer, items: [nameHash, height, address])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .transfer)
    }

    func testFinalizeRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0x33, count: 32)
        let height: [UInt8] = [0x80, 0x00, 0x00, 0x00]
        let name = Array("myname".utf8)
        let flags: [UInt8] = [0x00]
        let address = [UInt8](repeating: 0x44, count: 20)
        let hash = [UInt8](repeating: 0x55, count: 32)
        let cov = Covenant(type: .finalize, items: [nameHash, height, name, flags, address, hash])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .finalize)
        XCTAssertEqual(decoded.items.count, 6)
    }

    func testRevokeRoundTrip() throws {
        let nameHash = [UInt8](repeating: 0x66, count: 32)
        let height: [UInt8] = [0x90, 0x00, 0x00, 0x00]
        let cov = Covenant(type: .revoke, items: [nameHash, height])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.type, .revoke)
    }

    // MARK: - Large / Edge Case Items

    func testLargeCovenantItem() throws {
        // Item > 255 bytes (tests CompactSize encoding for items > single byte)
        let largeItem = [UInt8](repeating: 0xAB, count: 300)
        let cov = Covenant(type: .register, items: [
            [UInt8](repeating: 0, count: 32),
            [UInt8](repeating: 0, count: 4),
            largeItem
        ])

        var writer = BufferWriter()
        cov.write(to: &writer)
        var reader = BufferReader(writer.data)
        let decoded = try Covenant.read(from: &reader)
        XCTAssertEqual(decoded, cov)
        XCTAssertEqual(decoded.items[2].count, 300)
    }

    func testSerializedSizeMatchesWrittenSize() throws {
        for type in [CovenantType.open, .bid, .reveal, .register, .update] {
            let cov = Covenant(type: type, items: [
                [UInt8](repeating: 0xAA, count: 32),
                [UInt8](repeating: 0, count: 4)
            ])
            var writer = BufferWriter()
            cov.write(to: &writer)
            XCTAssertEqual(cov.serializedSize, writer.count, "Size mismatch for \(type)")
        }
    }

    // MARK: - isName Property

    func testIsNameForAllTypes() {
        XCTAssertFalse(CovenantType.none.isName)
        XCTAssertTrue(CovenantType.open.isName)
        XCTAssertTrue(CovenantType.bid.isName)
        XCTAssertTrue(CovenantType.reveal.isName)
        XCTAssertTrue(CovenantType.redeem.isName)
        XCTAssertTrue(CovenantType.register.isName)
        XCTAssertTrue(CovenantType.update.isName)
        XCTAssertTrue(CovenantType.renew.isName)
        XCTAssertTrue(CovenantType.transfer.isName)
        XCTAssertTrue(CovenantType.finalize.isName)
        XCTAssertTrue(CovenantType.revoke.isName)
    }

    // MARK: - isLinked Property

    func testIsLinkedForAllTypes() {
        // Not linked: NONE, OPEN, BID
        XCTAssertFalse(CovenantType.none.isLinked)
        XCTAssertFalse(CovenantType.open.isLinked)
        XCTAssertFalse(CovenantType.bid.isLinked)

        // Linked: REVEAL through REVOKE
        XCTAssertTrue(CovenantType.reveal.isLinked)
        XCTAssertTrue(CovenantType.redeem.isLinked)
        XCTAssertTrue(CovenantType.register.isLinked)
        XCTAssertTrue(CovenantType.update.isLinked)
        XCTAssertTrue(CovenantType.renew.isLinked)
        XCTAssertTrue(CovenantType.transfer.isLinked)
        XCTAssertTrue(CovenantType.finalize.isLinked)
        XCTAssertTrue(CovenantType.revoke.isLinked)
    }

    // MARK: - Equality

    func testCovenantEquality() {
        let cov1 = Covenant(type: .open, items: [[1, 2, 3]])
        let cov2 = Covenant(type: .open, items: [[1, 2, 3]])
        let cov3 = Covenant(type: .open, items: [[4, 5, 6]])
        XCTAssertEqual(cov1, cov2)
        XCTAssertNotEqual(cov1, cov3)
    }

    func testCovenantTypeEquality() {
        let cov1 = Covenant(type: .bid, items: [[1]])
        let cov2 = Covenant(type: .reveal, items: [[1]])
        XCTAssertNotEqual(cov1, cov2)
    }
}
