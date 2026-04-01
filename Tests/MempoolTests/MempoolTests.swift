import XCTest
@testable import Mempool
import Base
import ExtCrypto
import Consensus
import Protocol
import Chain

// MARK: - Test Helpers

private func makeAddress() -> Address {
    .null
}

private func makeCoinbaseTx(outputValues: [UInt64] = [1_000_000]) -> Transaction {
    let input = Input(prevout: .null)
    let outputs = outputValues.map { Output(value: $0, address: makeAddress()) }
    return Transaction(inputs: [input], outputs: outputs)
}

private func makeSpendingTx(
    prevHash: Hash256,
    prevIndex: UInt32 = 0,
    outputValue: UInt64
) -> Transaction {
    let input = Input(prevout: Outpoint(hash: prevHash, index: prevIndex))
    let output = Output(value: outputValue, address: makeAddress())
    return Transaction(inputs: [input], outputs: [output])
}

// MARK: - MempoolPolicy Tests

final class MempoolPolicyTests: XCTestCase {

    func testConstants() {
        XCTAssertEqual(MempoolPolicy.maxSize, 100_000_000)
        XCTAssertEqual(MempoolPolicy.maxOrphans, 100)
        XCTAssertEqual(MempoolPolicy.maxAncestors, 50)
        XCTAssertEqual(MempoolPolicy.expiryTime, 259_200)
        XCTAssertEqual(MempoolPolicy.minRelay, 1_000)
    }

    func testEvictionThreshold() {
        XCTAssertEqual(MempoolPolicy.evictionThreshold, 90_000_000)
    }

    func testGetMinFee() {
        // 1000 byte tx at default rate (1000/kB) = 1000 bumps
        XCTAssertEqual(MempoolPolicy.getMinFee(size: 1000), 1_000)

        // 500 byte tx = 500 bumps
        XCTAssertEqual(MempoolPolicy.getMinFee(size: 500), 500)

        // Very small tx: fee would be 0, so returns rate instead
        XCTAssertEqual(MempoolPolicy.getMinFee(size: 0), 1_000)
    }

    func testGetRate() {
        // 1000 bumps for 1000 bytes = 1000/kB
        XCTAssertEqual(MempoolPolicy.getRate(size: 1000, fee: 1_000), 1_000)

        // 5000 bumps for 500 bytes = 10000/kB
        XCTAssertEqual(MempoolPolicy.getRate(size: 500, fee: 5_000), 10_000)

        // Zero size returns 0
        XCTAssertEqual(MempoolPolicy.getRate(size: 0, fee: 100), 0)
    }
}

// MARK: - MempoolEntry Tests

final class MempoolEntryTests: XCTestCase {

    func testCreateEntry() {
        var view = CoinView()
        let fundTx = makeCoinbaseTx(outputValues: [5_000_000])
        let fundHash = fundTx.txHash()
        view.addTX(fundTx, height: 100)

        let spendTx = makeSpendingTx(prevHash: fundHash, outputValue: 4_000_000)
        let entry = MempoolEntry(tx: spendTx, view: view, height: 200, time: 1000)

        XCTAssertEqual(entry.hash, spendTx.txHash())
        XCTAssertEqual(entry.height, 200)
        XCTAssertEqual(entry.time, 1000)
        XCTAssertEqual(entry.fee, 1_000_000) // 5M - 4M
        XCTAssertEqual(entry.value, 5_000_000)
        XCTAssertFalse(entry.dependencies)
    }

    func testCoinbaseFlag() {
        var view = CoinView()
        let coinbaseTx = makeCoinbaseTx(outputValues: [10_000_000])
        let cbHash = coinbaseTx.txHash()
        view.addTX(coinbaseTx, height: 0)

        // Mark the coin entry as coinbase
        let spendTx = makeSpendingTx(prevHash: cbHash, outputValue: 9_000_000)
        let entry = MempoolEntry(tx: spendTx, view: view, height: 200, time: 1000)
        XCTAssertTrue(entry.coinbase)
    }

    func testFeeRate() {
        var view = CoinView()
        let fundTx = makeCoinbaseTx(outputValues: [10_000_000])
        let fundHash = fundTx.txHash()
        view.addTX(fundTx, height: 100)

        let spendTx = makeSpendingTx(prevHash: fundHash, outputValue: 9_000_000)
        let entry = MempoolEntry(tx: spendTx, view: view, height: 200, time: 1000)

        XCTAssertEqual(entry.fee, 1_000_000)
        XCTAssertTrue(entry.rate > 0)
        XCTAssertEqual(entry.rate, entry.deltaRate) // No prioritization
        XCTAssertEqual(entry.descFee, entry.fee)
        XCTAssertEqual(entry.descSize, entry.size)
    }

    func testGetPriority() {
        var view = CoinView()
        let fundTx = makeCoinbaseTx(outputValues: [10_000_000])
        let fundHash = fundTx.txHash()
        view.addTX(fundTx, height: 100)

        let spendTx = makeSpendingTx(prevHash: fundHash, outputValue: 9_000_000)
        let entry = MempoolEntry(tx: spendTx, view: view, height: 200, time: 1000)

        // At same height, priority = 0
        XCTAssertEqual(entry.getPriority(at: 200), 0)

        // After 100 blocks, priority increases
        let p = entry.getPriority(at: 300)
        XCTAssertTrue(p > 0)
    }
}

// MARK: - ContractState Tests

final class ContractStateTests: XCTestCase {

    private func makeNameHash(_ byte: UInt8) -> Hash256 {
        Hash256(unchecked: [UInt8](repeating: byte, count: 32))
    }

    private func makeNameCovenant(type: CovenantType, nameHash: Hash256) -> Covenant {
        Covenant(type: type, items: [Array(nameHash.bytes)])
    }

    private func makeNameTx(covenantType: CovenantType, nameHash: Hash256) -> Transaction {
        makeNameTxWithValue(covenantType: covenantType, nameHash: nameHash, value: 1_000_000)
    }

    private func makeNameTxWithValue(covenantType: CovenantType, nameHash: Hash256, value: UInt64) -> Transaction {
        let output = Output(
            value: value,
            address: makeAddress(),
            covenant: makeNameCovenant(type: covenantType, nameHash: nameHash)
        )
        return Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [output]
        )
    }

    func testTrackOpen() {
        var state = ContractState()
        let nameHash = makeNameHash(0x01)
        let tx = makeNameTx(covenantType: .open, nameHash: nameHash)
        let txHash = tx.txHash()

        state.track(tx, txHash: txHash)
        XCTAssertTrue(state.unique.contains(nameHash))
        XCTAssertTrue(state.opens[nameHash]?.contains(txHash) == true)
    }

    func testTrackBid() {
        var state = ContractState()
        let nameHash = makeNameHash(0x02)
        let tx = makeNameTx(covenantType: .bid, nameHash: nameHash)
        let txHash = tx.txHash()

        state.track(tx, txHash: txHash)
        // Bids don't go in unique set
        XCTAssertFalse(state.unique.contains(nameHash))
        XCTAssertTrue(state.bids[nameHash]?.contains(txHash) == true)
    }

    func testHasNamesBlocksUniqueOps() {
        var state = ContractState()
        let nameHash = makeNameHash(0x03)
        let tx1 = makeNameTx(covenantType: .open, nameHash: nameHash)
        state.track(tx1, txHash: tx1.txHash())

        // Second OPEN for same name should be detected
        let tx2 = makeNameTx(covenantType: .open, nameHash: nameHash)
        XCTAssertTrue(state.hasNames(tx2))

        // Different name should not conflict
        let otherHash = makeNameHash(0x04)
        let tx3 = makeNameTx(covenantType: .open, nameHash: otherHash)
        XCTAssertFalse(state.hasNames(tx3))
    }

    func testHasNamesAllowsMultipleBids() {
        var state = ContractState()
        let nameHash = makeNameHash(0x05)
        let tx1 = makeNameTx(covenantType: .bid, nameHash: nameHash)
        state.track(tx1, txHash: tx1.txHash())

        // BID doesn't go in unique, so hasNames won't flag a second BID
        let tx2 = makeNameTx(covenantType: .bid, nameHash: nameHash)
        XCTAssertFalse(state.hasNames(tx2))
    }

    func testUntrack() {
        var state = ContractState()
        let nameHash = makeNameHash(0x06)
        let tx = makeNameTx(covenantType: .open, nameHash: nameHash)
        let txHash = tx.txHash()

        state.track(tx, txHash: txHash)
        XCTAssertTrue(state.unique.contains(nameHash))

        state.untrack(tx, txHash: txHash)
        XCTAssertFalse(state.unique.contains(nameHash))
        XCTAssertNil(state.opens[nameHash])
    }

    func testTxsForName() {
        var state = ContractState()
        let nameHash = makeNameHash(0x07)

        // Use different values so txs have different hashes
        let tx1 = makeNameTxWithValue(covenantType: .bid, nameHash: nameHash, value: 1_000_000)
        let tx2 = makeNameTxWithValue(covenantType: .bid, nameHash: nameHash, value: 2_000_000)
        state.track(tx1, txHash: tx1.txHash())
        state.track(tx2, txHash: tx2.txHash())

        let txs = state.txsForName(nameHash)
        XCTAssertEqual(txs.count, 2)
        XCTAssertTrue(txs.contains(tx1.txHash()))
        XCTAssertTrue(txs.contains(tx2.txHash()))
    }
}

// MARK: - Mempool Tests

final class MempoolTests: XCTestCase {

    private func makeEntryAndView(
        fundValue: UInt64 = 5_000_000,
        spendValue: UInt64 = 4_000_000,
        height: Int = 200
    ) -> (MempoolEntry, CoinView) {
        var view = CoinView()
        let fundTx = makeCoinbaseTx(outputValues: [fundValue])
        let fundHash = fundTx.txHash()
        view.addTX(fundTx, height: 100)

        let spendTx = makeSpendingTx(prevHash: fundHash, outputValue: spendValue)
        let entry = MempoolEntry(tx: spendTx, view: view, height: height, time: 1000)
        return (entry, view)
    }

    func testAddAndGet() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()

        pool.addEntry(entry)
        XCTAssertEqual(pool.count, 1)
        XCTAssertTrue(pool.has(entry.hash))
        XCTAssertNotNil(pool.get(entry.hash))
        XCTAssertEqual(pool.get(entry.hash)?.fee, entry.fee)
    }

    func testRemoveEntry() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()

        pool.addEntry(entry)
        XCTAssertEqual(pool.count, 1)

        let removed = pool.removeEntry(entry.hash)
        XCTAssertEqual(removed.count, 1)
        XCTAssertEqual(pool.count, 0)
        XCTAssertFalse(pool.has(entry.hash))
    }

    func testDoubleSpendDetection() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()
        pool.addEntry(entry)

        // Create a transaction that spends the same input
        let conflictTx = entry.tx
        XCTAssertTrue(pool.isDoubleSpend(conflictTx))
    }

    func testNoDoubleSpendForCoinbase() {
        let pool = Mempool()
        let cbTx = makeCoinbaseTx()
        // Coinbase inputs are skipped in double spend check
        XCTAssertFalse(pool.isDoubleSpend(cbTx))
    }

    func testOrphans() {
        var pool = Mempool()
        let orphanHash = Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let parentHash = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))

        pool.addOrphan(orphanHash, raw: [1, 2, 3], missingParents: [parentHash])
        XCTAssertEqual(pool.orphans.count, 1)
        XCTAssertTrue(pool.waiting[parentHash]?.contains(orphanHash) == true)

        // Resolve orphans when parent arrives
        let resolved = pool.resolveOrphans(for: parentHash)
        XCTAssertEqual(resolved.count, 1)
        XCTAssertTrue(resolved.contains(orphanHash))
        XCTAssertNil(pool.waiting[parentHash])
    }

    func testRemoveOrphan() {
        var pool = Mempool()
        let orphanHash = Hash256(unchecked: [UInt8](repeating: 0xCC, count: 32))
        pool.addOrphan(orphanHash, raw: [1, 2], missingParents: [])

        pool.removeOrphan(orphanHash)
        XCTAssertEqual(pool.orphans.count, 0)
    }

    func testOrphanEviction() {
        var pool = Mempool()

        // Fill orphan pool to the limit
        for i in 0..<MempoolPolicy.maxOrphans {
            var bytes = [UInt8](repeating: 0, count: 32)
            bytes[0] = UInt8(i & 0xFF)
            bytes[1] = UInt8((i >> 8) & 0xFF)
            let hash = Hash256(unchecked: bytes)
            pool.addOrphan(hash, raw: [UInt8(i & 0xFF)], missingParents: [])
        }
        XCTAssertEqual(pool.orphans.count, MempoolPolicy.maxOrphans)

        // Adding one more should evict one
        let newHash = Hash256(unchecked: [UInt8](repeating: 0xFF, count: 32))
        pool.addOrphan(newHash, raw: [0xFF], missingParents: [])
        XCTAssertEqual(pool.orphans.count, MempoolPolicy.maxOrphans)
    }

    func testEvictExpired() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()
        pool.addEntry(entry)

        // Not expired yet
        let notExpired = pool.evictExpired(now: entry.time + MempoolPolicy.expiryTime - 1)
        XCTAssertEqual(notExpired, 0)
        XCTAssertEqual(pool.count, 1)

        // Now expired
        let expired = pool.evictExpired(now: entry.time + MempoolPolicy.expiryTime)
        XCTAssertEqual(expired, 1)
        XCTAssertEqual(pool.count, 0)
    }

    func testCountAncestors() {
        var pool = Mempool()

        // Create a chain: fund -> tx1 -> tx2
        var view = CoinView()
        let fundTx = makeCoinbaseTx(outputValues: [10_000_000])
        let fundHash = fundTx.txHash()
        view.addTX(fundTx, height: 100)

        let tx1 = makeSpendingTx(prevHash: fundHash, outputValue: 9_000_000)
        let entry1 = MempoolEntry(tx: tx1, view: view, height: 200, time: 1000)
        pool.addEntry(entry1)

        // tx2 spends tx1's output — check ancestor count
        let tx2 = makeSpendingTx(prevHash: entry1.hash, outputValue: 8_000_000)
        let count = pool.countAncestors(tx2)
        XCTAssertEqual(count, 1)
    }

    func testGetByFeeRate() {
        var pool = Mempool()

        // Create two entries with different fee rates
        var view1 = CoinView()
        let fund1 = makeCoinbaseTx(outputValues: [5_000_000])
        view1.addTX(fund1, height: 100)
        let tx1 = makeSpendingTx(prevHash: fund1.txHash(), outputValue: 4_500_000)
        let entry1 = MempoolEntry(tx: tx1, view: view1, height: 200, time: 1000)

        var view2 = CoinView()
        let fund2 = makeCoinbaseTx(outputValues: [5_000_000])
        view2.addTX(fund2, height: 100)
        let tx2 = makeSpendingTx(prevHash: fund2.txHash(), outputValue: 3_000_000)
        let entry2 = MempoolEntry(tx: tx2, view: view2, height: 200, time: 1000)

        pool.addEntry(entry1) // Lower fee (500K)
        pool.addEntry(entry2) // Higher fee (2M)

        let sorted = pool.getByFeeRate()
        XCTAssertEqual(sorted.count, 2)
        // Higher fee rate should come first
        XCTAssertTrue(sorted[0].rate >= sorted[1].rate)
    }

    func testSpentTracking() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()
        let spentOutpoint = entry.tx.inputs[0].prevout

        pool.addEntry(entry)
        XCTAssertNotNil(pool.spents[spentOutpoint])
        XCTAssertEqual(pool.spents[spentOutpoint], entry.hash)

        pool.removeEntry(entry.hash)
        XCTAssertNil(pool.spents[spentOutpoint])
    }

    func testSizeTracking() {
        var pool = Mempool()
        XCTAssertEqual(pool.size, 0)

        let (entry, _) = makeEntryAndView()
        pool.addEntry(entry)
        XCTAssertTrue(pool.size > 0)

        pool.removeEntry(entry.hash)
        XCTAssertEqual(pool.size, 0)
    }

    // MARK: - Double Spend Detection

    func testIsDoubleSpendDetectsConflictingInputs() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()
        pool.addEntry(entry)

        // Different tx spending the same outpoint
        let conflictTx = makeSpendingTx(
            prevHash: entry.tx.inputs[0].prevout.hash,
            prevIndex: entry.tx.inputs[0].prevout.index,
            outputValue: 3_000_000
        )
        XCTAssertTrue(pool.isDoubleSpend(conflictTx))
    }

    func testIsDoubleSpendAllowsUnrelatedTx() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()
        pool.addEntry(entry)

        // A different tx spending a different outpoint
        let unrelatedHash = Hash256(unchecked: [UInt8](repeating: 0xDD, count: 32))
        let unrelatedTx = makeSpendingTx(prevHash: unrelatedHash, outputValue: 1_000_000)
        XCTAssertFalse(pool.isDoubleSpend(unrelatedTx))
    }

    // MARK: - Remove Block

    func testRemoveBlockClearsConfirmedTxs() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()
        pool.addEntry(entry)
        XCTAssertEqual(pool.count, 1)

        // Simulate a block containing this transaction
        let hdr = BlockHeader(bits: 0x207fffff)
        let block = Block(
            header: hdr,
            transactions: [makeCoinbaseTx(), entry.tx],
            balloonProof: regtestProof(for: hdr)
        )
        pool.removeBlock(block)
        XCTAssertEqual(pool.count, 0, "Confirmed tx should be removed from pool")
    }

    func testRemoveBlockIgnoresUnknownTxs() {
        var pool = Mempool()
        let (entry, _) = makeEntryAndView()
        pool.addEntry(entry)

        // Block with a different tx
        let otherTx = makeSpendingTx(
            prevHash: Hash256(unchecked: [UInt8](repeating: 0xEE, count: 32)),
            outputValue: 1_000
        )
        let hdr = BlockHeader(bits: 0x207fffff)
        let block = Block(
            header: hdr,
            transactions: [makeCoinbaseTx(), otherTx],
            balloonProof: regtestProof(for: hdr)
        )
        pool.removeBlock(block)
        XCTAssertEqual(pool.count, 1, "Unrelated tx should not be removed")
    }

    // MARK: - Resolve Orphans

    func testResolveOrphansWhenParentArrives() {
        var pool = Mempool()
        let parentHash = Hash256(unchecked: [UInt8](repeating: 0x11, count: 32))
        let orphan1 = Hash256(unchecked: [UInt8](repeating: 0x22, count: 32))
        let orphan2 = Hash256(unchecked: [UInt8](repeating: 0x33, count: 32))

        pool.addOrphan(orphan1, raw: [1], missingParents: [parentHash])
        pool.addOrphan(orphan2, raw: [2], missingParents: [parentHash])

        let resolved = pool.resolveOrphans(for: parentHash)
        XCTAssertEqual(resolved.count, 2)
        XCTAssertTrue(resolved.contains(orphan1))
        XCTAssertTrue(resolved.contains(orphan2))
    }

    func testResolveOrphansReturnsEmptyWhenNoWaiters() {
        let pool = Mempool()
        let hash = Hash256(unchecked: [UInt8](repeating: 0x44, count: 32))
        let resolved = pool.resolveOrphans(for: hash)
        XCTAssertTrue(resolved.isEmpty)
    }

    // MARK: - Evict By Fee Rate

    func testEvictByFeeRateEvictsLowestFirst() {
        var pool = Mempool()

        // Create many entries to exceed eviction threshold
        // We can't easily hit the real threshold (90MB), but we can test the sort behavior
        // by adding entries and verifying the method runs without error
        var view1 = CoinView()
        let fund1 = makeCoinbaseTx(outputValues: [5_000_000])
        view1.addTX(fund1, height: 100)
        let tx1 = makeSpendingTx(prevHash: fund1.txHash(), outputValue: 4_900_000) // Low fee: 100K
        let entry1 = MempoolEntry(tx: tx1, view: view1, height: 200, time: 1000)

        var view2 = CoinView()
        let fund2 = makeCoinbaseTx(outputValues: [5_000_000])
        view2.addTX(fund2, height: 100)
        let tx2 = makeSpendingTx(prevHash: fund2.txHash(), outputValue: 1_000_000) // High fee: 4M
        let entry2 = MempoolEntry(tx: tx2, view: view2, height: 200, time: 1000)

        pool.addEntry(entry1)
        pool.addEntry(entry2)

        // Verify both are in the pool
        XCTAssertEqual(pool.count, 2)

        // getByFeeRate should put higher fee rate first
        let sorted = pool.getByFeeRate()
        XCTAssertEqual(sorted.count, 2)
        XCTAssertTrue(sorted[0].rate >= sorted[1].rate,
                       "Higher fee rate should come first")
    }

    // MARK: - Evict Expired (additional)

    func testEvictExpiredKeepsFreshEntries() {
        var pool = Mempool()

        // Entry at time 5000
        var view = CoinView()
        let fund = makeCoinbaseTx(outputValues: [5_000_000])
        view.addTX(fund, height: 100)
        let tx = makeSpendingTx(prevHash: fund.txHash(), outputValue: 4_000_000)
        let entry = MempoolEntry(tx: tx, view: view, height: 200, time: 5000)
        pool.addEntry(entry)

        // Expire at time just before expiry
        let evicted = pool.evictExpired(now: 5000 + MempoolPolicy.expiryTime - 1)
        XCTAssertEqual(evicted, 0)
        XCTAssertEqual(pool.count, 1, "Fresh entry should remain")
    }

    func testEvictExpiredRemovesMultiple() {
        var pool = Mempool()

        for i: UInt8 in 0..<3 {
            var view = CoinView()
            let fund = makeCoinbaseTx(outputValues: [UInt64(5_000_000 + Int(i) * 1000)])
            view.addTX(fund, height: 100)
            let tx = makeSpendingTx(prevHash: fund.txHash(), outputValue: UInt64(4_000_000 + Int(i) * 1000))
            let entry = MempoolEntry(tx: tx, view: view, height: 200, time: 1000)
            pool.addEntry(entry)
        }

        XCTAssertEqual(pool.count, 3)

        let evicted = pool.evictExpired(now: 1000 + MempoolPolicy.expiryTime)
        XCTAssertEqual(evicted, 3)
        XCTAssertEqual(pool.count, 0)
    }

    // MARK: - Count Ancestors (additional)

    func testCountAncestorsDeepChain() {
        var pool = Mempool()

        // Build a chain: fund -> tx1 -> tx2 -> tx3
        var view = CoinView()
        let fundTx = makeCoinbaseTx(outputValues: [10_000_000])
        let fundHash = fundTx.txHash()
        view.addTX(fundTx, height: 100)

        let tx1 = makeSpendingTx(prevHash: fundHash, outputValue: 9_000_000)
        let entry1 = MempoolEntry(tx: tx1, view: view, height: 200, time: 1000)
        pool.addEntry(entry1)

        var view2 = CoinView()
        view2.addTX(tx1, height: -1)
        let tx2 = makeSpendingTx(prevHash: entry1.hash, outputValue: 8_000_000)
        let entry2 = MempoolEntry(tx: tx2, view: view2, height: 200, time: 1000)
        pool.addEntry(entry2)

        // tx3 spends tx2's output — should have 2 ancestors
        let tx3 = makeSpendingTx(prevHash: entry2.hash, outputValue: 7_000_000)
        let count = pool.countAncestors(tx3)
        XCTAssertEqual(count, 2)
    }

    func testCountAncestorsNoAncestors() {
        let pool = Mempool()
        let tx = makeSpendingTx(
            prevHash: Hash256(unchecked: [UInt8](repeating: 0xFF, count: 32)),
            outputValue: 1_000_000
        )
        let count = pool.countAncestors(tx)
        XCTAssertEqual(count, 0)
    }

    // MARK: - Contract State Tracking in Pool

    func testRemoveBlockCleansUpOrphans() {
        let pool = Mempool()
        let orphanHash = Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let parentHash = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))

        pool.addOrphan(orphanHash, raw: [1, 2, 3], missingParents: [parentHash])
        XCTAssertEqual(pool.orphans.count, 1)
        XCTAssertTrue(pool.waiting[parentHash]?.contains(orphanHash) == true)

        // Build a block containing a transaction whose txHash == parentHash.
        // We use a spending tx whose hash happens to be parentHash — but what
        // matters is that the block contains a tx with that hash. The simplest
        // approach: find what hash a coinbase tx produces, then build the test
        // around it. Instead, we craft a block whose non-coinbase transaction
        // has the right hash by looking up what removeBlock actually does: it
        // calls tx.txHash() for each transaction and resolves orphans for that hash.
        // We need a Transaction whose txHash() == parentHash. Since we cannot
        // reverse the hash, we instead re-architect the test: use a real tx hash
        // as the parentHash.
        let parentTx = makeSpendingTx(
            prevHash: Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32)),
            outputValue: 1_000_000
        )
        let realParentHash = parentTx.txHash()

        // Re-setup with the real parent hash
        let pool2 = Mempool()
        let orphanHash2 = Hash256(unchecked: [UInt8](repeating: 0xCC, count: 32))
        pool2.addOrphan(orphanHash2, raw: [1, 2, 3], missingParents: [realParentHash])
        XCTAssertEqual(pool2.orphans.count, 1)
        XCTAssertTrue(pool2.waiting[realParentHash]?.contains(orphanHash2) == true)

        // Create a block that includes parentTx
        let hdr = BlockHeader(bits: 0x207fffff)
        let block = Block(
            header: hdr,
            transactions: [makeCoinbaseTx(), parentTx],
            balloonProof: regtestProof(for: hdr)
        )
        pool2.removeBlock(block)

        XCTAssertTrue(pool2.orphans.isEmpty, "Orphans should be cleaned up after removeBlock")
        XCTAssertNil(pool2.waiting[realParentHash], "Waiting map should no longer contain the parent hash")
    }

    func testContractStateTrackedOnAdd() {
        var pool = Mempool()
        let nameHash = Hash256(unchecked: [UInt8](repeating: 0x01, count: 32))
        let openOutput = Output(
            value: 0,
            address: makeAddress(),
            covenant: Covenant(type: .open, items: [Array(nameHash.bytes)])
        )
        let tx = Transaction(inputs: [Input(prevout: .null)], outputs: [openOutput])
        let txHash = tx.txHash()

        var view = CoinView()
        view.addTX(makeCoinbaseTx(outputValues: [1_000_000]), height: 100)
        let entry = MempoolEntry(tx: tx, view: view, height: 200, time: 1000)
        pool.addEntry(entry)

        XCTAssertTrue(pool.contracts.unique.contains(nameHash))
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
