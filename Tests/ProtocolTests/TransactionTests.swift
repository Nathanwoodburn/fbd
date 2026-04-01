import XCTest
@testable import Protocol
import Base

final class TransactionTests: XCTestCase {

    // MARK: - Outpoint

    func testOutpointRoundTrip() throws {
        let hash = try Hash256([UInt8](repeating: 0xDE, count: 32))
        let outpoint = Outpoint(hash: hash, index: 42)

        var writer = BufferWriter()
        outpoint.write(to: &writer)
        XCTAssertEqual(writer.count, 36)

        var reader = BufferReader(writer.data)
        let decoded = try Outpoint.read(from: &reader)
        XCTAssertEqual(decoded, outpoint)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testOutpointNull() {
        let null = Outpoint.null
        XCTAssertTrue(null.isNull)
        XCTAssertEqual(null.hash, .zero)
        XCTAssertEqual(null.index, 0xFFFF_FFFF)
    }

    // MARK: - Input

    func testInputRoundTrip() throws {
        let hash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let input = Input(prevout: Outpoint(hash: hash, index: 0), sequence: 0xFFFFFFFE)

        var writer = BufferWriter()
        input.write(to: &writer)
        XCTAssertEqual(writer.count, 40)

        var reader = BufferReader(writer.data)
        let decoded = try Input.read(from: &reader)
        XCTAssertEqual(decoded, input)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testInputCoinbase() {
        let input = Input(prevout: .null)
        XCTAssertTrue(input.isCoinbase)
    }

    // MARK: - Address

    func testAddressRoundTrip() throws {
        let hash = [UInt8](repeating: 0xBB, count: 20)
        let addr = try Address(version: 0, hash: hash)

        var writer = BufferWriter()
        addr.write(to: &writer)
        XCTAssertEqual(writer.count, 22) // 1 + 1 + 20

        var reader = BufferReader(writer.data)
        let decoded = try Address.read(from: &reader)
        XCTAssertEqual(decoded, addr)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testAddressInvalidVersionThrows() {
        XCTAssertThrowsError(try Address(version: 32, hash: [UInt8](repeating: 0, count: 20)))
    }

    func testAddressInvalidHashLengthThrows() {
        XCTAssertThrowsError(try Address(version: 0, hash: [0x01])) // too short
        XCTAssertThrowsError(try Address(version: 0, hash: [UInt8](repeating: 0, count: 41))) // too long
    }

    // MARK: - Output

    func testOutputRoundTrip() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0xCC, count: 20))
        let output = Output(value: 1_000_000, address: addr, covenant: .none)

        var writer = BufferWriter()
        output.write(to: &writer)
        XCTAssertEqual(output.serializedSize, writer.count)

        var reader = BufferReader(writer.data)
        let decoded = try Output.read(from: &reader)
        XCTAssertEqual(decoded, output)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - Witness

    func testWitnessEmptyRoundTrip() throws {
        let witness = Witness.empty

        var writer = BufferWriter()
        witness.write(to: &writer)
        XCTAssertEqual(writer.data, [0x00]) // zero items

        var reader = BufferReader(writer.data)
        let decoded = try Witness.read(from: &reader)
        XCTAssertEqual(decoded, witness)
    }

    func testWitnessWithItemsRoundTrip() throws {
        let sig = [UInt8](repeating: 0x30, count: 72)
        let pubkey = [UInt8](repeating: 0x02, count: 33)
        let witness = Witness(items: [sig, pubkey])

        var writer = BufferWriter()
        witness.write(to: &writer)
        XCTAssertEqual(witness.serializedSize, writer.count)

        var reader = BufferReader(writer.data)
        let decoded = try Witness.read(from: &reader)
        XCTAssertEqual(decoded, witness)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - Transaction

    func testSimpleTransactionRoundTrip() throws {
        let prevHash = try Hash256([UInt8](repeating: 0x11, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x22, count: 20))

        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 500_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [[0x01, 0x02, 0x03]])]
        )

        var writer = BufferWriter()
        tx.write(to: &writer)
        XCTAssertEqual(tx.serializedSize, writer.count)

        var reader = BufferReader(writer.data)
        let decoded = try Transaction.read(from: &reader)
        XCTAssertEqual(decoded, tx)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testCoinbaseTransaction() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x33, count: 20))
        let tx = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: 2_000_000_000, address: addr)],
            witnesses: [Witness(items: [[0x00, 0x00, 0x00]])]
        )
        XCTAssertTrue(tx.isCoinbase)
    }

    func testTransactionWeight() throws {
        let prevHash = try Hash256([UInt8](repeating: 0x44, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x55, count: 20))
        let sig = [UInt8](repeating: 0x30, count: 72)
        let pubkey = [UInt8](repeating: 0x02, count: 33)

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 100_000, address: addr)],
            witnesses: [Witness(items: [sig, pubkey])]
        )

        // base = 4 + 1 + 40 + 1 + (8 + 22 + 2) + 4 = 82
        XCTAssertEqual(tx.baseSize, 82)
        // witness = 1 + (1+72) + (1+33) = 108
        XCTAssertEqual(tx.witnessSize, 108)
        // weight = 82*4 + 108 = 436
        XCTAssertEqual(tx.weight, 436)
        // vsize = ceil(436/4) = 109
        XCTAssertEqual(tx.virtualSize, 109)
    }

    func testTransactionDefaultWitnesses() throws {
        let prevHash = try Hash256([UInt8](repeating: 0x66, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x77, count: 20))

        let tx = Transaction(
            inputs: [
                Input(prevout: Outpoint(hash: prevHash, index: 0)),
                Input(prevout: Outpoint(hash: prevHash, index: 1)),
            ],
            outputs: [Output(value: 200_000, address: addr)]
        )

        // Witnesses default to empty, one per input
        XCTAssertEqual(tx.witnesses.count, 2)
        XCTAssertEqual(tx.witnesses[0], .empty)
        XCTAssertEqual(tx.witnesses[1], .empty)
    }
}
