import XCTest
@testable import Chain
import Base
import Protocol
import Consensus
import Storage
import ExtCrypto

final class CoinDatabaseTests: XCTestCase {

    private var tempDir: String!

    override func setUp() {
        tempDir = NSTemporaryDirectory() + "coindb_test_\(UUID().uuidString)"
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: tempDir)
    }

    private var dbPath: String { tempDir + "/coins" }

    // MARK: - Helpers

    private func makeOutput(value: UInt64 = 1_000_000) -> Output {
        Output(value: value, address: .null)
    }

    private func makeCoinEntry(
        value: UInt64 = 1_000_000,
        height: Int = 100,
        coinbase: Bool = false
    ) -> CoinEntry {
        CoinEntry.fromOutput(makeOutput(value: value), height: height, coinbase: coinbase)
    }

    private func makeCoinbaseTx(outputValues: [UInt64] = [2_000_000_000]) -> Transaction {
        let input = Input(prevout: .null)
        let outputs = outputValues.map { Output(value: $0, address: .null) }
        return Transaction(inputs: [input], outputs: outputs)
    }

    private func makeSpendingTx(
        from txHash: Hash256,
        index: UInt32 = 0,
        outputValues: [UInt64] = [500_000]
    ) -> Transaction {
        let input = Input(prevout: Outpoint(hash: txHash, index: index))
        let outputs = outputValues.map { Output(value: $0, address: .null) }
        return Transaction(inputs: [input], outputs: outputs)
    }

    // MARK: - LevelDBStore Tests

    func testLevelDBStoreBasicOperations() throws {
        let store = try LevelDBStore(path: dbPath)
        let db = store.openDatabase(name: "test")

        // Put and get
        let key: [UInt8] = [1, 2, 3]
        let value: [UInt8] = [4, 5, 6, 7, 8]
        try store.put(db: db, key: key, value: value)

        let result = try store.get(db: db, key: key)
        XCTAssertEqual(result, value)

        // Missing key
        let missing = try store.get(db: db, key: [9, 9, 9])
        XCTAssertNil(missing)

        // Delete
        try store.delete(db: db, key: key)
        let afterDelete = try store.get(db: db, key: key)
        XCTAssertNil(afterDelete)

        store.close()
    }

    func testLevelDBStoreBatchWrite() throws {
        let store = try LevelDBStore(path: dbPath)
        let db = store.openDatabase(name: "test")

        let ops: [(db: UInt8, op: LevelDBStore.BatchOp)] = [
            (db, .put(key: [1], value: [10])),
            (db, .put(key: [2], value: [20])),
            (db, .put(key: [3], value: [30])),
        ]
        try store.writeBatch(ops)

        XCTAssertEqual(try store.get(db: db, key: [1]), [10])
        XCTAssertEqual(try store.get(db: db, key: [2]), [20])
        XCTAssertEqual(try store.get(db: db, key: [3]), [30])

        // Batch with delete
        let ops2: [(db: UInt8, op: LevelDBStore.BatchOp)] = [
            (db, .delete(key: [2])),
            (db, .put(key: [4], value: [40])),
        ]
        try store.writeBatch(ops2)

        XCTAssertNil(try store.get(db: db, key: [2]))
        XCTAssertEqual(try store.get(db: db, key: [4]), [40])

        store.close()
    }

    // MARK: - CoinDatabase Tests

    func testStoreAndRetrieveCoin() throws {
        let db = try CoinDatabase(path: dbPath, network: .regtest)

        // Create a coin view with a coinbase output
        let coinbaseTx = makeCoinbaseTx()
        let txHash = coinbaseTx.txHash()

        var view = CoinView()
        view.addTX(coinbaseTx, height: 1)

        let blockHash = Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32))
        try db.saveView(view, height: 1, hash: blockHash)

        // Retrieve the coin
        let coin = db.getCoin(Outpoint(hash: txHash, index: 0))
        XCTAssertNotNil(coin)
        XCTAssertEqual(coin?.output.value, 2_000_000_000)
        XCTAssertEqual(coin?.height, 1)
        XCTAssertTrue(coin?.coinbase == true)

        // Non-existent coin
        let missing = db.getCoin(Outpoint(hash: .zero, index: 99))
        XCTAssertNil(missing)

        db.close()
    }

    func testSpendCoin() throws {
        let db = try CoinDatabase(path: dbPath, network: .regtest)

        // Block 1: coinbase creates a coin
        let coinbaseTx = makeCoinbaseTx(outputValues: [2_000_000_000])
        let cbHash = coinbaseTx.txHash()

        var view1 = CoinView()
        view1.addTX(coinbaseTx, height: 1)
        let hash1 = Hash256(unchecked: [UInt8](repeating: 0x01, count: 32))
        try db.saveView(view1, height: 1, hash: hash1)

        // Verify coin exists
        XCTAssertNotNil(db.getCoin(Outpoint(hash: cbHash, index: 0)))

        // Block 2: spend the coinbase output (regtest maturity = 2, so height 3+ needed)
        // But for just testing the spend mechanism, use height 3
        let spendTx = makeSpendingTx(from: cbHash, outputValues: [1_999_000_000])
        let coinbaseTx2 = makeCoinbaseTx(outputValues: [2_001_000_000])

        var view2 = CoinView()
        // Load the coin being spent
        let coin = db.getCoin(Outpoint(hash: cbHash, index: 0))!
        view2.addEntry(Outpoint(hash: cbHash, index: 0), coin)
        // Spend it
        XCTAssertTrue(view2.spendInputs(spendTx))
        // Add new outputs
        view2.addTX(coinbaseTx2, height: 3)
        view2.addTX(spendTx, height: 3)

        let hash2 = Hash256(unchecked: [UInt8](repeating: 0x03, count: 32))
        try db.saveView(view2, height: 3, hash: hash2)

        // Original coin should be gone
        XCTAssertNil(db.getCoin(Outpoint(hash: cbHash, index: 0)))

        // New coins should exist
        XCTAssertNotNil(db.getCoin(Outpoint(hash: coinbaseTx2.txHash(), index: 0)))
        XCTAssertNotNil(db.getCoin(Outpoint(hash: spendTx.txHash(), index: 0)))

        db.close()
    }

    func testUndoPersistence() throws {
        let db = try CoinDatabase(path: dbPath, network: .regtest)

        // Create a coin and then spend it (generating undo data)
        let coinbaseTx = makeCoinbaseTx(outputValues: [2_000_000_000])
        let cbHash = coinbaseTx.txHash()

        var view1 = CoinView()
        view1.addTX(coinbaseTx, height: 1)
        try db.saveView(view1, height: 1, hash: Hash256(unchecked: [UInt8](repeating: 0x01, count: 32)))

        // Spend the coin in a new view
        let spendTx = makeSpendingTx(from: cbHash, outputValues: [1_999_000_000])

        var view2 = CoinView()
        let coin = db.getCoin(Outpoint(hash: cbHash, index: 0))!
        view2.addEntry(Outpoint(hash: cbHash, index: 0), coin)
        XCTAssertTrue(view2.spendInputs(spendTx))
        view2.addTX(makeCoinbaseTx(outputValues: [2_001_000_000]), height: 3)
        view2.addTX(spendTx, height: 3)

        try db.saveView(view2, height: 3, hash: Hash256(unchecked: [UInt8](repeating: 0x03, count: 32)))

        // Undo data should exist for height 3
        let undo = try db.getUndo(height: 3)
        XCTAssertNotNil(undo)
        XCTAssertEqual(undo?.count, 1)
        XCTAssertEqual(undo?.first?.output.value, 2_000_000_000)
        XCTAssertEqual(undo?.first?.height, 1)
        XCTAssertTrue(undo?.first?.coinbase == true)

        // Undo data at height 1 exists but is empty (only coinbase outputs, no spends)
        let undoH1 = try db.getUndo(height: 1)
        XCTAssertNotNil(undoH1)
        XCTAssertEqual(undoH1?.count, 0)

        db.close()
    }

    func testChainStatePersistence() throws {
        let blockHash = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))

        // Write some data and close
        do {
            let db = try CoinDatabase(path: dbPath, network: .regtest)
            let coinbaseTx = makeCoinbaseTx(outputValues: [2_000_000_000])

            var view = CoinView()
            view.addTX(coinbaseTx, height: 1)
            try db.saveView(view, height: 1, hash: blockHash)

            let state = db.getState()
            XCTAssertEqual(state.tip, blockHash)
            XCTAssertTrue(state.coin > 0)
            XCTAssertTrue(state.value > 0)

            db.close()
        }

        // Reopen and verify state persisted
        do {
            let db = try CoinDatabase(path: dbPath, network: .regtest)
            let state = db.getState()
            XCTAssertEqual(state.tip, blockHash)
            XCTAssertTrue(state.coin > 0)
            XCTAssertTrue(state.value > 0)
            db.close()
        }
    }

    func testLevelDBCrashSafety() throws {
        // Write coins, close without explicit flush, reopen
        let coinbaseTx = makeCoinbaseTx(outputValues: [2_000_000_000])
        let txHash = coinbaseTx.txHash()

        do {
            let db = try CoinDatabase(path: dbPath, network: .regtest)
            var view = CoinView()
            view.addTX(coinbaseTx, height: 1)
            try db.saveView(view, height: 1, hash: Hash256(unchecked: [UInt8](repeating: 0xCC, count: 32)))
            db.close()
        }

        // Reopen and verify data persists
        do {
            let db = try CoinDatabase(path: dbPath, network: .regtest)
            let coin = db.getCoin(Outpoint(hash: txHash, index: 0))
            XCTAssertNotNil(coin)
            XCTAssertEqual(coin?.output.value, 2_000_000_000)
            db.close()
        }
    }

    func testMultipleCoinsInSingleBlock() throws {
        let db = try CoinDatabase(path: dbPath, network: .regtest)

        // Coinbase with multiple outputs
        let coinbaseTx = makeCoinbaseTx(outputValues: [1_000_000_000, 500_000_000, 500_000_000])
        let cbHash = coinbaseTx.txHash()

        var view = CoinView()
        view.addTX(coinbaseTx, height: 1)
        try db.saveView(view, height: 1, hash: Hash256(unchecked: [UInt8](repeating: 0xDD, count: 32)))

        // All three outputs should be retrievable
        for i: UInt32 in 0..<3 {
            let coin = db.getCoin(Outpoint(hash: cbHash, index: i))
            XCTAssertNotNil(coin, "Coin at index \(i) should exist")
        }

        XCTAssertEqual(db.getCoin(Outpoint(hash: cbHash, index: 0))?.output.value, 1_000_000_000)
        XCTAssertEqual(db.getCoin(Outpoint(hash: cbHash, index: 1))?.output.value, 500_000_000)
        XCTAssertEqual(db.getCoin(Outpoint(hash: cbHash, index: 2))?.output.value, 500_000_000)

        db.close()
    }

    func testDisconnectBlockSkipsIntraBlockSpendRestoration() throws {
        let db = try CoinDatabase(path: dbPath, network: .regtest)

        // Block 0: set up a prior coin that tx1 will spend
        let priorTx = makeCoinbaseTx(outputValues: [1_000_000])
        let priorHash = priorTx.txHash()
        var view0 = CoinView()
        view0.addTX(priorTx, height: 0)
        try db.saveView(view0, height: 0, hash: Hash256(unchecked: [UInt8](repeating: 0x00, count: 32)))

        XCTAssertNotNil(db.getCoin(Outpoint(hash: priorHash, index: 0)))

        // Block 1 transactions:
        //   coinbaseTx: creates output A:0
        //   tx1: spends priorTx:0, creates tx1:0
        //   tx2: spends tx1:0 (intra-block spend)
        let coinbaseTx1 = makeCoinbaseTx(outputValues: [2_000_000_000])
        let tx1 = makeSpendingTx(from: priorHash, index: 0, outputValues: [900_000])
        let tx1Hash = tx1.txHash()
        let tx2 = makeSpendingTx(from: tx1Hash, index: 0, outputValues: [800_000])

        // Build a CoinView for block 1
        var view1 = CoinView()
        view1.addTX(coinbaseTx1, height: 1)

        // Load the prior coin being spent by tx1
        let priorCoin = db.getCoin(Outpoint(hash: priorHash, index: 0))!
        view1.addEntry(Outpoint(hash: priorHash, index: 0), priorCoin)
        XCTAssertTrue(view1.spendInputs(tx1))
        view1.addTX(tx1, height: 1)

        // Spend tx1:0 within the same block (intra-block spend)
        XCTAssertTrue(view1.spendInputs(tx2))
        view1.addTX(tx2, height: 1)

        let blockHash1 = Hash256(unchecked: [UInt8](repeating: 0x01, count: 32))
        try db.saveView(view1, height: 1, hash: blockHash1)

        // tx1:0 should NOT exist — it was created and spent within the same block
        XCTAssertNil(db.getCoin(Outpoint(hash: tx1Hash, index: 0)),
            "Intra-block spend should not be persisted to the coin DB")
        // tx2:0 should exist (created but not spent)
        XCTAssertNotNil(db.getCoin(Outpoint(hash: tx2.txHash(), index: 0)))
        // priorTx:0 should be gone (spent by tx1)
        XCTAssertNil(db.getCoin(Outpoint(hash: priorHash, index: 0)))

        // Build the Block structure for disconnectBlock
        let header = BlockHeader()
        let proof = regtestProof(for: header)
        let block = Block(header: header, transactions: [coinbaseTx1, tx1, tx2], balloonProof: proof)

        let prevHash = Hash256(unchecked: [UInt8](repeating: 0x00, count: 32))
        try db.disconnectBlock(block, height: 1, prevHash: prevHash)

        // After disconnect:
        // tx1:0 was an intra-block spend — it must NOT be restored
        XCTAssertNil(db.getCoin(Outpoint(hash: tx1Hash, index: 0)),
            "Intra-block spend should not be restored during disconnect")
        // tx2:0 was created in this block — it should be removed
        XCTAssertNil(db.getCoin(Outpoint(hash: tx2.txHash(), index: 0)),
            "Output created in disconnected block should be removed")
        // coinbaseTx1:0 was created in this block — it should be removed
        XCTAssertNil(db.getCoin(Outpoint(hash: coinbaseTx1.txHash(), index: 0)),
            "Coinbase output from disconnected block should be removed")
        // priorTx:0 was spent by tx1 — it should be restored from undo data
        XCTAssertNotNil(db.getCoin(Outpoint(hash: priorHash, index: 0)),
            "Coin spent by this block should be restored after disconnect")
        XCTAssertEqual(db.getCoin(Outpoint(hash: priorHash, index: 0))?.output.value, 1_000_000)

        // Verify the undo data was cleaned up (no underflow)
        let undoAfter = try db.getUndo(height: 1)
        XCTAssertNil(undoAfter, "Undo data should be deleted after disconnect")

        db.close()
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
