import XCTest
import ExtCrypto
@testable import Net
import Base
import Protocol
import Consensus

final class CompactBlockTests: XCTestCase {

    /// Helper: create a dummy transaction with a unique hash.
    private func makeTx(seed: UInt8) -> Transaction {
        let input = Input(
            prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: seed, count: 32)), index: UInt32(seed))
        )
        let output = Output(value: UInt64(seed) * 1000, address: .null)
        return Transaction(inputs: [input], outputs: [output])
    }

    private func makeCoinbaseTx() -> Transaction {
        let input = Input(prevout: .null)
        let output = Output(value: 500_000_000, address: .null)
        return Transaction(inputs: [input], outputs: [output])
    }

    func testFromBlockRoundTrip() throws {
        let coinbase = makeCoinbaseTx()
        let tx1 = makeTx(seed: 1)
        let tx2 = makeTx(seed: 2)
        let header = BlockHeader(nonce: 42, time: 1000, bits: 0x207fffff)
        let block = Block(header: header, transactions: [coinbase, tx1, tx2], balloonProof: regtestProof(for: header))

        let compact = try CompactBlockData.fromBlock(block, slots: 4)

        // Header should match
        XCTAssertEqual(compact.header, block.header)

        // Coinbase should be prefilled at index 0
        XCTAssertEqual(compact.prefilledTxs.count, 1)
        XCTAssertEqual(compact.prefilledTxs[0].index, 0)
        XCTAssertEqual(compact.prefilledTxs[0].tx, coinbase)

        // Should have 2 short IDs (for tx1 and tx2)
        XCTAssertEqual(compact.shortIds.count, 2)

        // Reconstruct with mempool containing both txs
        let tx1Hash = tx1.txHash()
        let tx2Hash = tx2.txHash()
        let mempoolTxs: [Hash256: Transaction] = [tx1Hash: tx1, tx2Hash: tx2]
        let blockHash = try ProofOfWork.powHash(for: header, slots: 4)
        let result = CompactBlockReconstructor.reconstruct(data: compact, mempoolTxs: mempoolTxs, blockHash: blockHash)

        if case .success(let reconstructed) = result {
            XCTAssertEqual(reconstructed.transactions.count, 3)
            XCTAssertEqual(reconstructed.header, header)
            XCTAssertEqual(reconstructed.transactions[0], coinbase)
            XCTAssertEqual(reconstructed.transactions[1], tx1)
            XCTAssertEqual(reconstructed.transactions[2], tx2)
        } else {
            XCTFail("Expected successful reconstruction")
        }
    }

    func testReconstructMissingTxs() throws {
        let coinbase = makeCoinbaseTx()
        let tx1 = makeTx(seed: 1)
        let header = BlockHeader(nonce: 99, time: 2000, bits: 0x207fffff)
        let block = Block(header: header, transactions: [coinbase, tx1], balloonProof: regtestProof(for: header))

        let compact = try CompactBlockData.fromBlock(block, slots: 4)

        // Reconstruct with empty mempool — should be missing
        let blockHash = try ProofOfWork.powHash(for: header, slots: 4)
        let result = CompactBlockReconstructor.reconstruct(data: compact, mempoolTxs: [:], blockHash: blockHash)

        if case .missing(_, let indices) = result {
            XCTAssertEqual(indices, [1])
        } else {
            XCTFail("Expected missing result")
        }
    }

    func testFillMissing() throws {
        let coinbase = makeCoinbaseTx()
        let tx1 = makeTx(seed: 1)
        let header = BlockHeader(nonce: 0, time: 3000, bits: 0x207fffff)

        // Simulate partial reconstruction
        var txs: [Transaction?] = [coinbase, nil]
        let missingIndices: [UInt32] = [1]

        let filled = CompactBlockReconstructor.fillMissing(
            txs: &txs,
            missingIndices: missingIndices,
            responseTxs: [tx1],
            header: header,
            balloonProof: regtestProof(for: header)
        )

        XCTAssertNotNil(filled)
        XCTAssertEqual(filled?.transactions.count, 2)
        XCTAssertEqual(filled?.transactions[1], tx1)
    }

    func testFillMissingCountMismatch() throws {
        let coinbase = makeCoinbaseTx()
        let header = BlockHeader(bits: 0x207fffff)

        var txs: [Transaction?] = [coinbase, nil]
        let missingIndices: [UInt32] = [1]

        // Wrong count — should fail
        let filled = CompactBlockReconstructor.fillMissing(
            txs: &txs,
            missingIndices: missingIndices,
            responseTxs: [],
            header: header,
            balloonProof: regtestProof(for: header)
        )

        XCTAssertNil(filled)
    }

    func testShortTxIdDeterminism() {
        let hash = Hash256(unchecked: [UInt8](repeating: 0xAB, count: 32))
        let key0: UInt64 = 0x0123456789ABCDEF
        let key1: UInt64 = 0xFEDCBA9876543210

        let sid1 = ShortTxId.compute(txHash: hash, key0: key0, key1: key1)
        let sid2 = ShortTxId.compute(txHash: hash, key0: key0, key1: key1)

        XCTAssertEqual(sid1, sid2)
        XCTAssertEqual(sid1.bytes.count, 6)
    }

    func testPrefilledCoinbase() throws {
        let coinbase = makeCoinbaseTx()
        let header = BlockHeader(nonce: 1, time: 4000, bits: 0x207fffff)
        let block = Block(header: header, transactions: [coinbase], balloonProof: regtestProof(for: header))

        let compact = try CompactBlockData.fromBlock(block, slots: 4)

        XCTAssertEqual(compact.prefilledTxs.count, 1)
        XCTAssertEqual(compact.prefilledTxs[0].index, 0)
        XCTAssertEqual(compact.prefilledTxs[0].tx, coinbase)
        XCTAssertTrue(compact.shortIds.isEmpty)
    }

    // MARK: - GetBlockTxnPacket Tests

    func testGetBlockTxnDifferentialIndexOverflowThrows() {
        // Manually craft raw bytes for a GetBlockTxnPacket whose differential
        // indices overflow UInt32 when decoded.
        var raw = [UInt8]()

        // hash: 32 zero bytes
        raw.append(contentsOf: [UInt8](repeating: 0, count: 32))

        // count: 2 (compact size fits in one byte)
        raw.append(2)

        // first diff: UInt32.max encoded as compact size (0xFE prefix + 4 LE bytes)
        raw.append(0xFE)
        raw.append(0xFF)
        raw.append(0xFF)
        raw.append(0xFF)
        raw.append(0xFF)

        // second diff: 0 (compact size single byte)
        // absolute index = UInt32.max + 0 + 1 = overflow
        raw.append(0)

        XCTAssertThrowsError(try GetBlockTxnPacket.decode(from: raw)) { error in
            guard case NetError.malformedPacket(let msg) = error else {
                XCTFail("Expected NetError.malformedPacket, got \(error)")
                return
            }
            XCTAssertTrue(msg.contains("overflow"), "Error message should mention overflow: \(msg)")
        }
    }

    func testGetBlockTxnRoundTrip() throws {
        let hash = Hash256(unchecked: [UInt8](repeating: 0xAB, count: 32))
        let original = GetBlockTxnPacket(hash: hash, indices: [0, 5, 100])

        let encoded = original.encode()
        let decoded = try GetBlockTxnPacket.decode(from: encoded)

        XCTAssertEqual(decoded.hash, original.hash)
        XCTAssertEqual(decoded.indices, original.indices)
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
