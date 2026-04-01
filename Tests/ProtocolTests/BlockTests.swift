import XCTest
import ExtCrypto
import Consensus
@testable import Protocol
import Base

final class BlockTests: XCTestCase {

    // MARK: - Block Header

    func testBlockHeaderSize() {
        let header = BlockHeader()
        XCTAssertEqual(header.serializedSize, 236)
    }

    func testBlockHeaderRoundTrip() throws {
        let prevBlock = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let merkleRoot = try Hash256([UInt8](repeating: 0xBB, count: 32))
        let witnessRoot = try Hash256([UInt8](repeating: 0xCC, count: 32))
        let treeRoot = try Hash256([UInt8](repeating: 0xDD, count: 32))
        let reservedRoot = try Hash256([UInt8](repeating: 0xEE, count: 32))
        let extraNonce = [UInt8](1...24)
        let mask = [UInt8](repeating: 0xFF, count: 32)

        let header = BlockHeader(
            nonce: 12345,
            time: 1700000000,
            prevBlock: prevBlock,
            treeRoot: treeRoot,
            extraNonce: extraNonce,
            reservedRoot: reservedRoot,
            witnessRoot: witnessRoot,
            merkleRoot: merkleRoot,
            version: 0,
            bits: 0x1d00ffff,
            mask: mask
        )

        var writer = BufferWriter()
        header.write(to: &writer)
        XCTAssertEqual(writer.count, 236)

        var reader = BufferReader(writer.data)
        let decoded = try BlockHeader.read(from: &reader)
        XCTAssertEqual(decoded, header)
        XCTAssertEqual(decoded.nonce, 12345)
        XCTAssertEqual(decoded.time, 1700000000)
        XCTAssertEqual(decoded.prevBlock, prevBlock)
        XCTAssertEqual(decoded.merkleRoot, merkleRoot)
        XCTAssertEqual(decoded.bits, 0x1d00ffff)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testBlockHeaderFieldOrder() throws {
        // Verify the preheader starts with nonce (LE) then time (LE)
        let header = BlockHeader(nonce: 0x01020304, time: 0x0807060504030201)
        var writer = BufferWriter()
        header.write(to: &writer)

        // First 4 bytes: nonce LE
        XCTAssertEqual(Array(writer.data[0..<4]), [0x04, 0x03, 0x02, 0x01])
        // Next 8 bytes: time LE
        XCTAssertEqual(Array(writer.data[4..<12]), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    }

    // MARK: - Block

    func testEmptyBlockRoundTrip() throws {
        let header = BlockHeader(nonce: 1, time: 1000, bits: 0x20ffffff)
        let block = Block(header: header, transactions: [], balloonProof: regtestProof(for: header))

        var writer = BufferWriter()
        block.write(to: &writer)
        XCTAssertEqual(block.serializedSize, writer.count)

        var reader = BufferReader(writer.data)
        let decoded = try Block.read(from: &reader)
        XCTAssertEqual(decoded, block)
        XCTAssertEqual(decoded.transactions.count, 0)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testBlockWithCoinbaseRoundTrip() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x11, count: 20))
        let coinbase = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: 2_000_000_000, address: addr)],
            witnesses: [Witness(items: [[0x01]])]
        )

        let header = BlockHeader(nonce: 99, time: 2000, bits: 0x20ffffff)
        let block = Block(header: header, transactions: [coinbase], balloonProof: regtestProof(for: header))

        var writer = BufferWriter()
        block.write(to: &writer)

        var reader = BufferReader(writer.data)
        let decoded = try Block.read(from: &reader)
        XCTAssertEqual(decoded, block)
        XCTAssertEqual(decoded.transactions.count, 1)
        XCTAssertTrue(decoded.transactions[0].isCoinbase)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - InvItem

    func testInvItemRoundTrip() throws {
        let hash = try Hash256([UInt8](repeating: 0x42, count: 32))
        let item = InvItem(type: .tx, hash: hash)

        var writer = BufferWriter()
        item.write(to: &writer)
        XCTAssertEqual(writer.count, 36)

        var reader = BufferReader(writer.data)
        let decoded = try InvItem.read(from: &reader)
        XCTAssertEqual(decoded, item)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testInvItemUnknownTypeThrows() {
        var writer = BufferWriter()
        writer.writeUInt32LE(999)
        writer.writeBytes([UInt8](repeating: 0, count: 32))

        var reader = BufferReader(writer.data)
        XCTAssertThrowsError(try InvItem.read(from: &reader))
    }

    // MARK: - NetAddress

    func testNetAddressRoundTrip() throws {
        let ip: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1]
        let key = [UInt8](repeating: 0x02, count: 33)
        let addr = NetAddress(time: 1000, services: 1, ip: ip, port: 32867, key: key)

        var writer = BufferWriter()
        addr.write(to: &writer)
        XCTAssertEqual(writer.count, 88)

        var reader = BufferReader(writer.data)
        let decoded = try NetAddress.read(from: &reader)
        XCTAssertEqual(decoded, addr)
        XCTAssertEqual(decoded.port, 32867)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testNetAddressPortLittleEndian() throws {
        let addr = NetAddress(
            services: 0,
            ip: [UInt8](repeating: 0, count: 16),
            port: 0x2F26 // 12070 decimal
        )

        var writer = BufferWriter()
        addr.write(to: &writer)
        // Port at offset 57 (8 time + 4 services + 4 servicesHi + 1 format + 16 ip + 20 reserved + 2 port)
        // Port is little-endian in FBD
        XCTAssertEqual(writer.data[53], 0x26) // low byte first
        XCTAssertEqual(writer.data[54], 0x2F) // high byte second
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
