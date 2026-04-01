import XCTest
@testable import Chain
import Base
import ExtCrypto
import Protocol
import Consensus

// MARK: - ChainEntry Tests

final class ChainEntryTests: XCTestCase {

    func testFromBlockGenesis() throws {
        let header = BlockHeader(
            nonce: 0,
            time: 1580745078,
            prevBlock: .zero,
            treeRoot: .zero,
            version: 0,
            bits: 0x207fffff
        )
        let entry = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        XCTAssertEqual(entry.height, 0)
        XCTAssertTrue(entry.isGenesis)
        XCTAssertEqual(entry.prevBlock, .zero)
        XCTAssertEqual(entry.bits, 0x207fffff)
        XCTAssertFalse(entry.chainwork.isZero)
    }

    func testFromBlockWithPrev() throws {
        let genesisHeader = BlockHeader(
            time: 1580745078,
            bits: 0x207fffff
        )
        let genesis = try ChainEntry.fromBlock(genesisHeader, prev: nil, slots: 4)

        let header2 = BlockHeader(
            time: 1580745678,
            prevBlock: genesis.hash,
            bits: 0x207fffff
        )
        let entry = try ChainEntry.fromBlock(header2, prev: genesis, slots: 4)
        XCTAssertEqual(entry.height, 1)
        XCTAssertFalse(entry.isGenesis)
        XCTAssertEqual(entry.prevBlock, genesis.hash)
        XCTAssertTrue(entry.chainwork > genesis.chainwork)
    }

    func testHasBit() throws {
        let header = BlockHeader(version: 0b0000_0101, bits: 0x207fffff)
        let entry = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        XCTAssertTrue(entry.hasBit(0))
        XCTAssertFalse(entry.hasBit(1))
        XCTAssertTrue(entry.hasBit(2))
        XCTAssertFalse(entry.hasBit(3))
    }

    func testToHeader() throws {
        let header = BlockHeader(
            nonce: 42,
            time: 1000,
            prevBlock: .zero,
            treeRoot: .zero,
            version: 1,
            bits: 0x207fffff
        )
        let entry = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let reconstructed = entry.toHeader()
        XCTAssertEqual(reconstructed.nonce, 42)
        XCTAssertEqual(reconstructed.time, 1000)
        XCTAssertEqual(reconstructed.version, 1)
        XCTAssertEqual(reconstructed.bits, 0x207fffff)
    }
}

// MARK: - ChainState Tests

final class ChainStateTests: XCTestCase {

    func testInitialState() {
        let state = ChainState()
        XCTAssertEqual(state.tip, .zero)
        XCTAssertEqual(state.tx, 0)
        XCTAssertEqual(state.coin, 0)
        XCTAssertEqual(state.value, 0)
        XCTAssertEqual(state.burned, 0)
    }

    func testConnect() {
        var state = ChainState()
        state.connect(txCount: 5)
        XCTAssertEqual(state.tx, 5)
        state.connect(txCount: 3)
        XCTAssertEqual(state.tx, 8)
    }

    func testDisconnect() {
        var state = ChainState()
        state.connect(txCount: 10)
        state.disconnect(txCount: 3)
        XCTAssertEqual(state.tx, 7)
    }

    func testAddSpend() {
        var state = ChainState()
        state.add(value: 1_000_000)
        XCTAssertEqual(state.coin, 1)
        XCTAssertEqual(state.value, 1_000_000)

        state.add(value: 2_000_000)
        XCTAssertEqual(state.coin, 2)
        XCTAssertEqual(state.value, 3_000_000)

        state.spend(value: 1_000_000)
        XCTAssertEqual(state.coin, 1)
        XCTAssertEqual(state.value, 2_000_000)
    }

    func testBurnUnburn() {
        var state = ChainState()
        state.burn(value: 500_000)
        XCTAssertEqual(state.coin, 1)
        XCTAssertEqual(state.burned, 500_000)

        state.unburn(value: 500_000)
        XCTAssertEqual(state.coin, 0)
        XCTAssertEqual(state.burned, 0)
    }

    func testCommit() {
        var state = ChainState()
        let hash = Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32))
        state.commit(hash)
        XCTAssertEqual(state.tip, hash)
    }

    func testSerializeDeserialize() throws {
        var state = ChainState()
        state.commit(Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32)))
        state.tx = 100
        state.coin = 50
        state.value = 999_999
        state.burned = 123

        let data = state.serialize()
        XCTAssertEqual(data.count, 64)

        let decoded = try ChainState.deserialize(from: data)
        XCTAssertEqual(decoded.tip, state.tip)
        XCTAssertEqual(decoded.tx, 100)
        XCTAssertEqual(decoded.coin, 50)
        XCTAssertEqual(decoded.value, 999_999)
        XCTAssertEqual(decoded.burned, 123)
    }

    func testChainStateSaturatingSpend() {
        // Start with coin=0, value=0. Spending should saturate to 0, not crash.
        var state = ChainState()
        XCTAssertEqual(state.coin, 0)
        XCTAssertEqual(state.value, 0)
        state.spend(value: 100)
        XCTAssertEqual(state.coin, 0)
        XCTAssertEqual(state.value, 0)
    }

    func testChainStateDisconnectSaturating() {
        // Start with tx=0. Disconnecting should saturate to 0, not crash.
        var state = ChainState()
        XCTAssertEqual(state.tx, 0)
        state.disconnect(txCount: 5)
        XCTAssertEqual(state.tx, 0)
    }
}

// MARK: - CoinEntry Tests

final class CoinEntryTests: XCTestCase {

    private func makeOutput(value: UInt64 = 1_000_000) -> Output {
        Output(value: value, address: .null)
    }

    func testFromOutput() {
        let output = makeOutput()
        let entry = CoinEntry.fromOutput(output, height: 100, coinbase: false)
        XCTAssertEqual(entry.height, 100)
        XCTAssertFalse(entry.coinbase)
        XCTAssertEqual(entry.output.value, 1_000_000)
        XCTAssertFalse(entry.spent)
    }

    func testCoinbaseEntry() {
        let output = makeOutput()
        let entry = CoinEntry.fromOutput(output, height: 0, coinbase: true)
        XCTAssertTrue(entry.coinbase)
    }

    func testUnconfirmedEntry() {
        let output = makeOutput()
        let entry = CoinEntry.fromOutput(output, height: -1, coinbase: false)
        XCTAssertEqual(entry.height, -1)
    }

    func testSerializeDeserialize() throws {
        let output = makeOutput(value: 5_000_000)
        let entry = CoinEntry.fromOutput(output, height: 12345, coinbase: true, version: 2)
        let data = entry.serialize()
        let decoded = try CoinEntry.deserialize(from: data)
        XCTAssertEqual(decoded.version, 2)
        XCTAssertEqual(decoded.height, 12345)
        XCTAssertTrue(decoded.coinbase)
        XCTAssertEqual(decoded.output.value, 5_000_000)
    }

    func testSerializeUnconfirmed() throws {
        let output = makeOutput()
        let entry = CoinEntry.fromOutput(output, height: -1, coinbase: false)
        let data = entry.serialize()
        let decoded = try CoinEntry.deserialize(from: data)
        XCTAssertEqual(decoded.height, -1)
        XCTAssertFalse(decoded.coinbase)
    }
}

// MARK: - CoinView Tests

final class CoinViewTests: XCTestCase {

    private func makeAddress() -> Address {
        .null
    }

    private func makeCoinbaseTx(outputValues: [UInt64] = [1_000_000]) -> Transaction {
        let input = Input(prevout: .null)
        let outputs = outputValues.map { Output(value: $0, address: makeAddress()) }
        return Transaction(inputs: [input], outputs: outputs)
    }

    func testAddTXAndGet() {
        var view = CoinView()
        let tx = makeCoinbaseTx()
        let txHash = tx.txHash()
        view.addTX(tx, height: 100)

        let entry = view.getEntry(Outpoint(hash: txHash, index: 0))
        XCTAssertNotNil(entry)
        XCTAssertEqual(entry?.output.value, 1_000_000)
        XCTAssertEqual(entry?.height, 100)
    }

    func testGetMissing() {
        let view = CoinView()
        let entry = view.getEntry(Outpoint(hash: .zero, index: 0))
        XCTAssertNil(entry)
    }

    func testSpendEntry() {
        var view = CoinView()
        let tx = makeCoinbaseTx()
        let txHash = tx.txHash()
        view.addTX(tx, height: 100)

        let outpoint = Outpoint(hash: txHash, index: 0)
        let spent = view.spendEntry(outpoint)
        XCTAssertNotNil(spent)
        XCTAssertEqual(spent?.output.value, 1_000_000)
        XCTAssertFalse(view.isUnspent(outpoint))
        XCTAssertEqual(view.undo.count, 1)
    }

    func testSpendMissing() {
        var view = CoinView()
        let result = view.spendEntry(Outpoint(hash: .zero, index: 0))
        XCTAssertNil(result)
    }

    func testGetInputValue() {
        var view = CoinView()
        let fundingTx = makeCoinbaseTx(outputValues: [5_000_000, 3_000_000])
        let fundingHash = fundingTx.txHash()
        view.addTX(fundingTx, height: 100)

        let input1 = Input(prevout: Outpoint(hash: fundingHash, index: 0))
        let input2 = Input(prevout: Outpoint(hash: fundingHash, index: 1))
        let spendingTx = Transaction(
            inputs: [input1, input2],
            outputs: [Output(value: 7_000_000, address: makeAddress())]
        )

        let inputValue = view.getInputValue(spendingTx)
        XCTAssertEqual(inputValue, 8_000_000)

        let fee = view.getFee(spendingTx)
        XCTAssertEqual(fee, 1_000_000)
    }

    func testHasCoins() {
        var view = CoinView()
        let tx = makeCoinbaseTx()
        let txHash = tx.txHash()
        XCTAssertFalse(view.hasCoins(for: txHash))
        view.addTX(tx, height: 100)
        XCTAssertTrue(view.hasCoins(for: txHash))
    }

    func testPopUndo() {
        var view = CoinView()
        let tx = makeCoinbaseTx(outputValues: [1_000, 2_000])
        let txHash = tx.txHash()
        view.addTX(tx, height: 100)

        view.spendEntry(Outpoint(hash: txHash, index: 0))
        view.spendEntry(Outpoint(hash: txHash, index: 1))

        let undo2 = view.popUndo()
        XCTAssertEqual(undo2?.output.value, 2_000)
        let undo1 = view.popUndo()
        XCTAssertEqual(undo1?.output.value, 1_000)
        XCTAssertNil(view.popUndo())
    }

    func testCoinViewInputValueOverflow() {
        var view = CoinView()
        let halfMax = UInt64.max / 2 + 1
        // Create two coins whose values sum to more than UInt64.max
        let hash1 = Hash256(unchecked: [UInt8](repeating: 0xA1, count: 32))
        let hash2 = Hash256(unchecked: [UInt8](repeating: 0xA2, count: 32))
        view.addEntry(
            Outpoint(hash: hash1, index: 0),
            CoinEntry.fromOutput(Output(value: halfMax, address: .null), height: 1, coinbase: false)
        )
        view.addEntry(
            Outpoint(hash: hash2, index: 0),
            CoinEntry.fromOutput(Output(value: halfMax, address: .null), height: 1, coinbase: false)
        )

        let tx = Transaction(
            inputs: [
                Input(prevout: Outpoint(hash: hash1, index: 0)),
                Input(prevout: Outpoint(hash: hash2, index: 0)),
            ],
            outputs: [Output(value: 1, address: .null)]
        )
        // getInputValue should detect the overflow and return nil
        XCTAssertNil(view.getInputValue(tx))
    }

    func testCoinViewFeeOverflow() {
        var view = CoinView()
        let halfMax = UInt64.max / 2 + 1
        let hash1 = Hash256(unchecked: [UInt8](repeating: 0xB1, count: 32))
        let hash2 = Hash256(unchecked: [UInt8](repeating: 0xB2, count: 32))
        view.addEntry(
            Outpoint(hash: hash1, index: 0),
            CoinEntry.fromOutput(Output(value: halfMax, address: .null), height: 1, coinbase: false)
        )
        view.addEntry(
            Outpoint(hash: hash2, index: 0),
            CoinEntry.fromOutput(Output(value: halfMax, address: .null), height: 1, coinbase: false)
        )

        let tx = Transaction(
            inputs: [
                Input(prevout: Outpoint(hash: hash1, index: 0)),
                Input(prevout: Outpoint(hash: hash2, index: 0)),
            ],
            outputs: [Output(value: 1, address: .null)]
        )
        // getFee depends on getInputValue, which overflows -> nil
        XCTAssertNil(view.getFee(tx))
    }
}

// MARK: - MedianTime Tests

final class MedianTimeTests: XCTestCase {

    func testMedianOf11() {
        let timestamps: [UInt64] = [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
        let mtp = MedianTime.compute(timestamps)
        XCTAssertEqual(mtp, 6)
    }

    func testMedianOfFewer() {
        let timestamps: [UInt64] = [5, 3, 1]
        let mtp = MedianTime.compute(timestamps)
        XCTAssertEqual(mtp, 3)
    }

    func testMedianOfOne() {
        XCTAssertEqual(MedianTime.compute([100]), 100)
    }

    func testMedianEmpty() {
        XCTAssertEqual(MedianTime.compute([]), 0)
    }

    func testMedianWithDuplicates() {
        let timestamps = [UInt64](repeating: 5, count: 11)
        XCTAssertEqual(MedianTime.compute(timestamps), 5)
    }

    func testMedianClipsToSpan() {
        let timestamps: [UInt64] = [20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8]
        let mtp = MedianTime.compute(timestamps)
        XCTAssertEqual(mtp, 15)
    }
}

// MARK: - Chain Core Tests

final class ChainCoreTests: XCTestCase {

    /// Mine a valid regtest header by iterating nonces until PoW passes.
    private func mineRegtestHeader(
        time: UInt64,
        prevBlock: Hash256,
        bits: UInt32 = 0x207fffff
    ) throws -> BlockHeader {
        let target = Target256.fromCompact(bits)
        for nonce in UInt32(0)...UInt32.max {
            let header = BlockHeader(
                nonce: nonce,
                time: time,
                prevBlock: prevBlock,
                bits: bits
            )
            let hash = try ProofOfWork.powHash(for: header, slots: 4)
            let hashNum = Target256(bigEndian: hash.bytes)
            if hashNum <= target {
                return header
            }
        }
        fatalError("Failed to mine block")
    }

    /// Build a chain of N blocks, returning the last entry.
    @discardableResult
    private func buildChain(_ chain: Chain, count: Int) throws -> ChainEntry {
        var prev = chain.tip
        for _ in 1...count {
            let header = try mineRegtestHeader(
                time: prev.time + 1,
                prevBlock: prev.hash
            )
            prev = try chain.add(header: header, proof: regtestProof(for: header))
        }
        return prev
    }

    func testChainInitWithGenesis() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        XCTAssertEqual(chain.height, 0)
        XCTAssertTrue(chain.tip.isGenesis)
        XCTAssertEqual(chain.tip.prevBlock, .zero)
    }

    func testAddValidHeader() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesis = chain.tip

        let header = try mineRegtestHeader(
            time: genesis.time + 1,
            prevBlock: genesis.hash
        )

        let entry = try chain.add(header: header, proof: regtestProof(for: header))
        XCTAssertEqual(entry.height, 1)
        XCTAssertEqual(entry.prevBlock, genesis.hash)
        XCTAssertEqual(chain.height, 1)
    }

    func testAddDuplicateHeaderThrows() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesis = chain.tip

        let header = try mineRegtestHeader(
            time: genesis.time + 1,
            prevBlock: genesis.hash
        )

        _ = try chain.add(header: header, proof: regtestProof(for: header))

        XCTAssertThrowsError(try chain.add(header: header, proof: regtestProof(for: header))) { error in
            guard case HeaderError.duplicateHeader = error else {
                XCTFail("Expected duplicateHeader, got \(error)")
                return
            }
        }
    }

    func testAddOrphanHeaderThrows() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        // Header pointing to a non-existent parent — this should fail with orphanHeader
        // before PoW check, so we don't need a valid PoW
        let header = BlockHeader(
            nonce: 0,
            time: 1580746000,
            prevBlock: Hash256(unchecked: [UInt8](repeating: 0xFF, count: 32)),
            bits: 0x207fffff
        )

        XCTAssertThrowsError(try chain.add(header: header, proof: regtestProof(for: header))) { error in
            guard case HeaderError.orphanHeader = error else {
                XCTFail("Expected orphanHeader, got \(error)")
                return
            }
        }
    }

    func testGetEntryByHash() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesis = chain.tip

        let entry = chain.getEntry(hash: genesis.hash)
        XCTAssertNotNil(entry)
        XCTAssertEqual(entry?.height, 0)
    }

    func testGetEntryByHashMissing() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let missing = Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32))
        XCTAssertNil(chain.getEntry(hash: missing))
    }

    func testGetEntryByHeight() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let entry = chain.getEntryByHeight(0)
        XCTAssertNotNil(entry)
        XCTAssertTrue(entry!.isGenesis)

        XCTAssertNil(chain.getEntryByHeight(1))
        XCTAssertNil(chain.getEntryByHeight(-1))
    }

    func testGetNextBitsRegtest() throws {
        // Regtest has noRetargeting=true, so getNextBits always returns powBits
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let bits = chain.getNextBits()
        XCTAssertEqual(bits, 0x207fffff)
    }

    func testMedianTimePastGenesis() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let mtp = chain.medianTimePast()
        // Genesis MTP = genesis time (only one block)
        XCTAssertEqual(mtp, chain.tip.time)
    }

    func testMedianTimePastWithMultipleEntries() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        // Add 5 blocks with increasing timestamps
        try buildChain(chain, count: 5)

        let mtp = chain.medianTimePast()
        // With 6 blocks (0-5), MTP = median of last 6 timestamps
        // Median of 6 values: middle element (index 3 of sorted 6) = entry at height 3
        let expectedMedian = chain.getEntryByHeight(3)!.time
        XCTAssertEqual(mtp, expectedMedian)
    }

    func testGetPreviousTimestamps() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        // Add 3 blocks
        try buildChain(chain, count: 3)

        let timestamps = chain.getPreviousTimestamps(chain.tip, count: 11)
        // Should get 4 timestamps (genesis + 3 blocks), limited by actual chain length
        XCTAssertEqual(timestamps.count, 4)
        // First should be the tip's time, going backwards
        XCTAssertEqual(timestamps[0], chain.tip.time)
    }

    func testGetLocator() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        // Add 5 blocks
        try buildChain(chain, count: 5)

        let locator = chain.getLocator()
        // First hash should be the tip
        XCTAssertEqual(locator.first, chain.tip.hash)
        // Last hash should be genesis
        XCTAssertEqual(locator.last, chain.getEntryByHeight(0)?.hash)
        // Should have 6 hashes (heights 5, 4, 3, 2, 1, 0 — all within first 10 before exponential)
        XCTAssertEqual(locator.count, 6)
    }

    func testGetLocatorExponentialBackoff() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        // Add 20 blocks
        try buildChain(chain, count: 20)

        let locator = chain.getLocator()
        // Should have fewer hashes than blocks due to exponential backoff
        XCTAssertTrue(locator.count < 21)
        XCTAssertTrue(locator.count > 10, "Should have at least 10 hashes for 20 blocks")
        XCTAssertEqual(locator.first, chain.tip.hash)
        XCTAssertEqual(locator.last, chain.getEntryByHeight(0)?.hash)
    }

    func testHasHash() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        XCTAssertTrue(chain.has(hash: chain.tip.hash))
        XCTAssertFalse(chain.has(hash: Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))))
    }

    func testBuildMultipleBlockChain() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        try buildChain(chain, count: 10)

        XCTAssertEqual(chain.height, 10)
        XCTAssertTrue(chain.tip.chainwork > Target256.zero)

        // Verify all entries are accessible
        for h in 0...10 {
            let entry = chain.getEntryByHeight(h)
            XCTAssertNotNil(entry, "Entry at height \(h) should exist")
            XCTAssertEqual(entry?.height, h)
        }
    }
}

// MARK: - TxIndex Tests

final class TxIndexTests: XCTestCase {

    private var tmpDir: String!

    override func setUp() {
        super.setUp()
        tmpDir = NSTemporaryDirectory() + "fbd-test-txindex-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: tmpDir)
        super.tearDown()
    }

    func testTxIndexPutGetRemove() throws {
        let chain = try Chain(network: .regtest, txIndexPath: tmpDir + "/txindex")
        chain.clockOverride = chain.tip.time
        XCTAssertTrue(chain.hasTxIndex)

        let hash = Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32))
        chain.putTxIndex(txHash: hash, height: 500, txIndex: 3)

        let loc = chain.getTxLocation(txHash: hash)
        XCTAssertNotNil(loc)
        XCTAssertEqual(loc?.height, 500)
        XCTAssertEqual(loc?.txIndex, 3)

        chain.removeTxIndex(txHash: hash)
        XCTAssertNil(chain.getTxLocation(txHash: hash))
    }

    func testTxIndexMissingHash() throws {
        let chain = try Chain(network: .regtest, txIndexPath: tmpDir + "/txindex")
        chain.clockOverride = chain.tip.time
        let hash = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))
        XCTAssertNil(chain.getTxLocation(txHash: hash))
    }

    func testTxIndexDisabled() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        XCTAssertFalse(chain.hasTxIndex)

        let hash = Hash256(unchecked: [UInt8](repeating: 0xCC, count: 32))
        // Operations are no-ops without --index-tx
        chain.putTxIndex(txHash: hash, height: 100, txIndex: 0)
        XCTAssertNil(chain.getTxLocation(txHash: hash))
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
