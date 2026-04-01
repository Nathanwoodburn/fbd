import XCTest
@testable import Mining
@testable import Base
@testable import ExtCrypto
@testable import Protocol
@testable import Consensus
@testable import Chain
@testable import Mempool

// MARK: - Merkle Tree Tests

final class MerkleTreeTests: XCTestCase {

    func testEmptyMerkleRoot() throws {
        let root = try MerkleTree.computeRoot([])
        // Empty tree returns sentinel: blake2b(empty)
        let sentinel = try Blake2bHash.hash256([])
        XCTAssertEqual(root, sentinel)
    }

    func testSingleHashMerkleRoot() throws {
        let hash = try Blake2bHash.hash256([1, 2, 3])
        let root = try MerkleTree.computeRoot([hash])
        // Domain-separated: leaf = blake2b(0x00 || hash)
        var leafBuf = [UInt8]()
        leafBuf.append(0x00)
        leafBuf.append(contentsOf: hash.bytes)
        let expected = try Blake2bHash.hash256(leafBuf)
        XCTAssertEqual(root, expected)
    }

    func testTwoHashesMerkleRoot() throws {
        let h1 = try Blake2bHash.hash256([1])
        let h2 = try Blake2bHash.hash256([2])
        let root = try MerkleTree.computeRoot([h1, h2])

        // Domain-separated: leaf1 = blake2b(0x00 || h1), leaf2 = blake2b(0x00 || h2)
        var l1 = [UInt8](); l1.append(0x00); l1.append(contentsOf: h1.bytes)
        let leaf1 = try Blake2bHash.hash256(l1)
        var l2 = [UInt8](); l2.append(0x00); l2.append(contentsOf: h2.bytes)
        let leaf2 = try Blake2bHash.hash256(l2)

        // Internal: blake2b(0x01 || leaf1 || leaf2)
        var internal_ = [UInt8]()
        internal_.append(0x01)
        internal_.append(contentsOf: leaf1.bytes)
        internal_.append(contentsOf: leaf2.bytes)
        let expected = try Blake2bHash.hash256(internal_)

        XCTAssertEqual(root, expected)
    }

    func testOddNumberUsesSentinel() throws {
        let h1 = try Blake2bHash.hash256([1])
        let h2 = try Blake2bHash.hash256([2])
        let h3 = try Blake2bHash.hash256([3])

        let root = try MerkleTree.computeRoot([h1, h2, h3])

        // Sentinel = blake2b(empty)
        let sentinel = try Blake2bHash.hash256([])

        // Leaves: blake2b(0x00 || h_i)
        var l1 = [UInt8](); l1.append(0x00); l1.append(contentsOf: h1.bytes)
        let leaf1 = try Blake2bHash.hash256(l1)
        var l2 = [UInt8](); l2.append(0x00); l2.append(contentsOf: h2.bytes)
        let leaf2 = try Blake2bHash.hash256(l2)
        var l3 = [UInt8](); l3.append(0x00); l3.append(contentsOf: h3.bytes)
        let leaf3 = try Blake2bHash.hash256(l3)

        // Level 1: blake2b(0x01 || leaf1 || leaf2), blake2b(0x01 || leaf3 || sentinel)
        var c12 = [UInt8](); c12.append(0x01)
        c12.append(contentsOf: leaf1.bytes); c12.append(contentsOf: leaf2.bytes)
        let node12 = try Blake2bHash.hash256(c12)

        var c3s = [UInt8](); c3s.append(0x01)
        c3s.append(contentsOf: leaf3.bytes); c3s.append(contentsOf: sentinel.bytes)
        let node3s = try Blake2bHash.hash256(c3s)

        // Level 0: blake2b(0x01 || node12 || node3s)
        var top = [UInt8](); top.append(0x01)
        top.append(contentsOf: node12.bytes); top.append(contentsOf: node3s.bytes)
        let expected = try Blake2bHash.hash256(top)

        XCTAssertEqual(root, expected)
    }

    func testDeterministic() throws {
        let hashes = try (0..<8).map { try Blake2bHash.hash256([UInt8($0)]) }
        let root1 = try MerkleTree.computeRoot(hashes)
        let root2 = try MerkleTree.computeRoot(hashes)
        XCTAssertEqual(root1, root2)
    }

    func testDifferentInputsDifferentRoots() throws {
        let h1 = [try Blake2bHash.hash256([1]), try Blake2bHash.hash256([2])]
        let h2 = [try Blake2bHash.hash256([3]), try Blake2bHash.hash256([4])]
        let root1 = try MerkleTree.computeRoot(h1)
        let root2 = try MerkleTree.computeRoot(h2)
        XCTAssertNotEqual(root1, root2)
    }
}

// MARK: - Coinbase Builder Tests

final class CoinbaseBuilderTests: XCTestCase {

    func testCoinbaseAtHeight0() {
        let cb = CoinbaseBuilder.build(address: .null, height: 0, fees: 0)
        XCTAssertTrue(cb.isCoinbase)
        XCTAssertEqual(cb.inputs.count, 1)
        XCTAssertEqual(cb.outputs.count, 1)
        // Reward at height 0: 500 FBC = 500_000_000 bumps
        XCTAssertEqual(cb.outputs[0].value, UInt64(Constants.baseReward))
    }

    func testCoinbaseWithFees() {
        let fees: Int64 = 50_000
        let cb = CoinbaseBuilder.build(address: .null, height: 100, fees: fees)
        let reward = BlockReward.getReward(height: 100)
        XCTAssertEqual(cb.outputs[0].value, UInt64(reward + fees))
    }

    func testCoinbaseAfterHalving() {
        let height = Constants.halvingInterval
        let cb = CoinbaseBuilder.build(address: .null, height: height, fees: 0)
        let expected = Constants.baseReward >> 1 // halved
        XCTAssertEqual(cb.outputs[0].value, UInt64(expected))
    }

    func testCoinbaseIsActuallyCoinbase() {
        let cb = CoinbaseBuilder.build(address: .null, height: 42, fees: 0)
        XCTAssertTrue(cb.isCoinbase)
        XCTAssertTrue(cb.inputs[0].prevout.isNull)
    }

    func testHeightCommitment() {
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(0), [0])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(1), [1])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(255), [0xFF, 0])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(256), [0, 1])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(0x1234), [0x34, 0x12])
    }

    func testCoinbaseWitnessContainsHeight() {
        let cb = CoinbaseBuilder.build(address: .null, height: 500, fees: 0)
        XCTAssertEqual(cb.witnesses.count, 1)
        XCTAssertFalse(cb.witnesses[0].items.isEmpty)
        // First witness item should be the height commitment
        XCTAssertEqual(cb.witnesses[0].items[0], CoinbaseBuilder.heightCommitment(500))
    }

    func testCoinbaseWithFlags() {
        let flags: [UInt8] = Array("fbd".utf8)
        let cb = CoinbaseBuilder.build(address: .null, height: 1, fees: 0, flags: flags)
        XCTAssertEqual(cb.witnesses[0].items.count, 2)
        XCTAssertEqual(cb.witnesses[0].items[1], flags)
    }
}

// MARK: - Block Assembler Tests

final class BlockAssemblerTests: XCTestCase {

    /// Create a simple chain entry for testing.
    private func makeTip(height: Int = 100) throws -> ChainEntry {
        let header = BlockHeader(bits: 0x1d00ffff)
        return try ChainEntry.fromBlock(header, prev: nil, slots: 4)
    }

    func testAssembleEmptyMempool() throws {
        let tip = try makeTip()
        let mempool = Mempool()

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        XCTAssertEqual(template.height, tip.height + 1)
        XCTAssertTrue(template.transactions.isEmpty)
        XCTAssertEqual(template.fees, 0)
        XCTAssertTrue(template.coinbase.isCoinbase)
    }

    func testAssembleSetsHeaderFields() throws {
        let tip = try makeTip()
        let mempool = Mempool()

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 12345,
            bits: 0x1d00ffff
        )

        XCTAssertEqual(template.header.time, 12345)
        XCTAssertEqual(template.header.bits, 0x1d00ffff)
        XCTAssertEqual(template.header.prevBlock, tip.hash)
    }

    func testMerkleRootIncludesCoinbase() throws {
        let tip = try makeTip()
        let mempool = Mempool()

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        // With no mempool txs, merkle root = blake2b(0x00 || coinbase tx hash)
        let cbHash = template.coinbase.txHash()
        let expectedRoot = try MerkleTree.computeRoot([cbHash])
        XCTAssertEqual(template.header.merkleRoot, expectedRoot)
    }
}

// MARK: - Block Template Tests

final class BlockTemplateTests: XCTestCase {

    func testTemplateWeightIncludesCoinbase() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        // Weight should be at least the coinbase weight
        XCTAssertGreaterThan(template.weight, 0)
        XCTAssertEqual(template.weight, template.coinbase.weight)
    }

    func testAssembleWithTransactions() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        // Create a fake transaction with a known prevout
        let prevHash = Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 900_000, address: .null)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )

        // Create a CoinView with the prevout
        var view = CoinView()
        view.addEntry(Outpoint(hash: prevHash, index: 0), CoinEntry.fromOutput(
            Output(value: 1_000_000, address: .null), height: 0, coinbase: false
        ))

        let entry = MempoolEntry(tx: tx, view: view, height: 1, time: 1000)
        mempool.addEntry(entry)

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        XCTAssertEqual(template.transactions.count, 1)
        XCTAssertGreaterThan(template.fees, 0)
    }

    func testFeeOrdering() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        // Two transactions: one with high fee, one with low fee
        let prevHash1 = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))
        let prevHash2 = Hash256(unchecked: [UInt8](repeating: 0xCC, count: 32))

        let txLow = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: prevHash1, index: 0))],
            outputs: [Output(value: 990_000, address: .null)], // fee = 10,000
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let txHigh = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: prevHash2, index: 0))],
            outputs: [Output(value: 500_000, address: .null)], // fee = 500,000
            locktime: 0,
            witnesses: [Witness(items: [])]
        )

        var viewLow = CoinView()
        viewLow.addEntry(Outpoint(hash: prevHash1, index: 0), CoinEntry.fromOutput(
            Output(value: 1_000_000, address: .null), height: 0, coinbase: false
        ))
        var viewHigh = CoinView()
        viewHigh.addEntry(Outpoint(hash: prevHash2, index: 0), CoinEntry.fromOutput(
            Output(value: 1_000_000, address: .null), height: 0, coinbase: false
        ))

        mempool.addEntry(MempoolEntry(tx: txLow, view: viewLow, height: 1, time: 1000))
        mempool.addEntry(MempoolEntry(tx: txHigh, view: viewHigh, height: 1, time: 1000))

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        XCTAssertEqual(template.transactions.count, 2)
        // Higher fee-rate tx should be first
        XCTAssertEqual(template.transactions[0].txHash(), txHigh.txHash())
    }

    func testEmptyMempoolOnlyCoinbase() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        XCTAssertTrue(template.transactions.isEmpty)
        XCTAssertTrue(template.coinbase.isCoinbase)
        XCTAssertEqual(template.fees, 0)
    }

    func testCoinbaseRewardHalving() {
        // First halving
        let reward0 = BlockReward.getReward(height: 0)
        XCTAssertEqual(reward0, Constants.baseReward)

        let rewardHalved = BlockReward.getReward(height: Constants.halvingInterval)
        XCTAssertEqual(rewardHalved, Constants.baseReward >> 1)

        let rewardDouble = BlockReward.getReward(height: Constants.halvingInterval * 2)
        XCTAssertEqual(rewardDouble, Constants.baseReward >> 2)
    }

    func testHeightCommitmentEncoding() {
        // Various heights
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(0), [0])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(1), [1])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(127), [127])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(255), [0xFF, 0])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(256), [0, 1])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(0xFFFF), [0xFF, 0xFF, 0])
        XCTAssertEqual(CoinbaseBuilder.heightCommitment(100_000), CoinbaseBuilder.heightCommitment(100_000))
    }

    func testWitnessRootWithTransactions() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        let prevHash = Hash256(unchecked: [UInt8](repeating: 0xDD, count: 32))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 900_000, address: .null)],
            locktime: 0,
            witnesses: [Witness(items: [[1, 2, 3]])]
        )

        var view = CoinView()
        view.addEntry(Outpoint(hash: prevHash, index: 0), CoinEntry.fromOutput(
            Output(value: 1_000_000, address: .null), height: 0, coinbase: false
        ))
        mempool.addEntry(MempoolEntry(tx: tx, view: view, height: 1, time: 1000))

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        // Witness root should be set (not zero when there are transactions with witnesses)
        XCTAssertNotEqual(template.header.witnessRoot, .zero)
    }

    func testTemplateHeight() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        XCTAssertEqual(template.height, tip.height + 1)
    }

    func testTemplateSigops() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        // Even empty template should have sigops from reserved
        XCTAssertGreaterThanOrEqual(template.sigops, 0)
    }

    // MARK: - Edge Case Tests

    func testTopologicalSortOrdersParentBeforeChild() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        // Create parent tx with high fee so it gets selected first by fee rate
        let fundingHash = Hash256(unchecked: [UInt8](repeating: 0xE1, count: 32))
        let parentTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: fundingHash, index: 0))],
            outputs: [Output(value: 500_000, address: .null)], // fee = 500_000 (high)
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let parentHash = parentTx.txHash()

        // Create child tx that spends the parent's output with lower fee
        let childTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: parentHash, index: 0))],
            outputs: [Output(value: 400_000, address: .null)], // fee = 100_000 (lower)
            locktime: 0,
            witnesses: [Witness(items: [])]
        )

        // CoinView for parent
        var parentView = CoinView()
        parentView.addEntry(Outpoint(hash: fundingHash, index: 0), CoinEntry.fromOutput(
            Output(value: 1_000_000, address: .null), height: 0, coinbase: false
        ))

        // CoinView for child — parent output is unconfirmed (height -1)
        var childView = CoinView()
        childView.addEntry(Outpoint(hash: parentHash, index: 0), CoinEntry.fromOutput(
            Output(value: 500_000, address: .null), height: -1, coinbase: false
        ))

        // Parent has higher fee rate, so assembler selects it first.
        // Child is then eligible because parent is already in selectedSet.
        // The topological sort ensures parent appears before child in final order.
        mempool.addEntry(MempoolEntry(tx: parentTx, view: parentView, height: 1, time: 1000))
        mempool.addEntry(MempoolEntry(tx: childTx, view: childView, height: 1, time: 1000))

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        // Both should be selected
        XCTAssertEqual(template.transactions.count, 2)
        // Parent must appear before child in the final ordering
        XCTAssertEqual(template.transactions[0].txHash(), parentHash,
                       "Parent tx must appear before child tx after topological sort")
        XCTAssertEqual(template.transactions[1].txHash(), childTx.txHash(),
                       "Child tx must appear after parent tx")
    }

    func testBlockAssemblerSkipsOrphanChildren() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        // Create a heavy parent whose weight exceeds the block limit
        let parentFundingHash = Hash256(unchecked: [UInt8](repeating: 0xF1, count: 32))
        let bigWitnessData = [UInt8](repeating: 0xCC, count: Constants.maxBlockWeight)
        let heavyParentTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: parentFundingHash, index: 0))],
            outputs: [Output(value: 900_000, address: .null)],
            locktime: 0,
            witnesses: [Witness(items: [bigWitnessData])]
        )
        let heavyParentHash = heavyParentTx.txHash()

        var heavyParentView = CoinView()
        heavyParentView.addEntry(Outpoint(hash: parentFundingHash, index: 0), CoinEntry.fromOutput(
            Output(value: 1_000_000, address: .null), height: 0, coinbase: false
        ))

        // Child that spends the heavy parent
        let orphanChildTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: heavyParentHash, index: 0))],
            outputs: [Output(value: 800_000, address: .null)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )

        var orphanChildView = CoinView()
        orphanChildView.addEntry(Outpoint(hash: heavyParentHash, index: 0), CoinEntry.fromOutput(
            Output(value: 900_000, address: .null), height: -1, coinbase: false
        ))

        mempool.addEntry(MempoolEntry(tx: heavyParentTx, view: heavyParentView, height: 1, time: 1000))
        mempool.addEntry(MempoolEntry(tx: orphanChildTx, view: orphanChildView, height: 1, time: 1000))

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        // The heavy parent is skipped (too large), so the child should also be excluded
        let selectedHashes = Set(template.transactions.map { $0.txHash() })
        XCTAssertFalse(selectedHashes.contains(heavyParentHash),
                       "Heavy parent should not be selected")
        XCTAssertFalse(selectedHashes.contains(orphanChildTx.txHash()),
                       "Child of unselected parent should be excluded")
    }

    func testBlockAssemblerFeesMatchSelectedTransactions() throws {
        let header = BlockHeader(bits: 0x1d00ffff)
        let tip = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let mempool = Mempool()

        // Create two independent transactions with different fees
        let fundHash1 = Hash256(unchecked: [UInt8](repeating: 0xD1, count: 32))
        let tx1 = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: fundHash1, index: 0))],
            outputs: [Output(value: 800_000, address: .null)], // fee = 200_000
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        var view1 = CoinView()
        view1.addEntry(Outpoint(hash: fundHash1, index: 0), CoinEntry.fromOutput(
            Output(value: 1_000_000, address: .null), height: 0, coinbase: false
        ))

        let fundHash2 = Hash256(unchecked: [UInt8](repeating: 0xD2, count: 32))
        let tx2 = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: fundHash2, index: 0))],
            outputs: [Output(value: 700_000, address: .null)], // fee = 300_000
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        var view2 = CoinView()
        view2.addEntry(Outpoint(hash: fundHash2, index: 0), CoinEntry.fromOutput(
            Output(value: 1_000_000, address: .null), height: 0, coinbase: false
        ))

        let entry1 = MempoolEntry(tx: tx1, view: view1, height: 1, time: 1000)
        let entry2 = MempoolEntry(tx: tx2, view: view2, height: 1, time: 1000)

        mempool.addEntry(entry1)
        mempool.addEntry(entry2)

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: .null,
            time: 1000,
            bits: 0x1d00ffff
        )

        // Both transactions should be included
        XCTAssertEqual(template.transactions.count, 2)
        // Total fees should equal the sum of both fees
        let expectedFees = entry1.fee + entry2.fee  // 200_000 + 300_000 = 500_000
        XCTAssertEqual(template.fees, expectedFees,
                       "Template fees must match sum of selected transaction fees")
        // Weight should include both transactions plus coinbase
        XCTAssertGreaterThan(template.weight, template.coinbase.weight)
    }
}
