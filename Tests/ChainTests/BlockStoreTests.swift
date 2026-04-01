import XCTest
import ExtCrypto
@testable import Chain
import Base
import Protocol
import Consensus

final class BlockStoreTests: XCTestCase {

    private var tempDir: String!

    override func setUp() {
        super.setUp()
        tempDir = NSTemporaryDirectory() + "blockstore_test_\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: tempDir)
        super.tearDown()
    }

    /// Helper to create a minimal block with a given header and one coinbase tx.
    private func makeBlock(
        prevBlock: Hash256 = .zero,
        time: UInt64 = 0,
        nonce: UInt32 = 0,
        merkleRoot: Hash256 = .zero,
        witnessRoot: Hash256 = .zero
    ) -> Block {
        let coinbaseInput = Input(
            prevout: Outpoint(hash: .zero, index: 0xFFFFFFFF),
            sequence: 0xFFFFFFFF
        )
        let coinbaseOutput = Output(value: 500 * 1_000_000, address: .null)
        let coinbaseTx = Transaction(
            version: 0,
            inputs: [coinbaseInput],
            outputs: [coinbaseOutput],
            locktime: 0,
            witnesses: [.empty]
        )

        let header = BlockHeader(
            nonce: nonce,
            time: time,
            prevBlock: prevBlock,
            witnessRoot: witnessRoot,
            merkleRoot: merkleRoot,
            bits: 0x207fffff
        )

        return Block(header: header, transactions: [coinbaseTx], balloonProof: regtestProof(for: header))
    }

    // MARK: - Basic operations

    func testCreateNewStore() throws {
        let store = try BlockStore(blocksDir: tempDir, network: .regtest)
        XCTAssertEqual(store.storedCount, 0)
        XCTAssertFalse(store.hasBlock(height: 0))
        try store.close()
    }

    func testStoreAndLoadBlock() throws {
        let store = try BlockStore(blocksDir: tempDir, network: .regtest)

        let block = makeBlock(time: 1000, nonce: 42)
        try store.storeBlock(block, height: 0)

        XCTAssertEqual(store.storedCount, 1)
        XCTAssertTrue(store.hasBlock(height: 0))
        XCTAssertFalse(store.hasBlock(height: 1))

        let loaded = try store.loadBlock(height: 0)
        XCTAssertNotNil(loaded)
        XCTAssertEqual(loaded, block)
        try store.close()
    }

    func testStoreMultipleBlocks() throws {
        let store = try BlockStore(blocksDir: tempDir, network: .regtest)

        let block0 = makeBlock(time: 1000, nonce: 0)
        let block1 = makeBlock(time: 1600, nonce: 1)
        let block2 = makeBlock(time: 2200, nonce: 2)

        try store.storeBlock(block0, height: 0)
        try store.storeBlock(block1, height: 1)
        try store.storeBlock(block2, height: 2)

        XCTAssertEqual(store.storedCount, 3)

        // Load each block and verify
        for (i, expected) in [block0, block1, block2].enumerated() {
            let loaded = try store.loadBlock(height: i)
            XCTAssertEqual(loaded, expected, "Block at height \(i) should match")
        }

        try store.close()
    }

    // MARK: - Sequential ordering

    func testHeightMismatchThrows() throws {
        let store = try BlockStore(blocksDir: tempDir, network: .regtest)

        let block = makeBlock(time: 1000)

        // Can't skip height 0
        XCTAssertThrowsError(try store.storeBlock(block, height: 1)) { error in
            if case BlockStoreError.heightMismatch(let expected, let got) = error {
                XCTAssertEqual(expected, 0)
                XCTAssertEqual(got, 1)
            } else {
                XCTFail("Expected heightMismatch, got \(error)")
            }
        }

        try store.close()
    }

    // MARK: - Out of range loads

    func testLoadOutOfRange() throws {
        let store = try BlockStore(blocksDir: tempDir, network: .regtest)

        // No blocks stored
        let result = try store.loadBlock(height: 0)
        XCTAssertNil(result)

        let negResult = try store.loadBlock(height: -1)
        XCTAssertNil(negResult)

        try store.close()
    }

    // MARK: - Reload from disk

    func testReloadFromDisk() throws {
        let block0 = makeBlock(time: 1000, nonce: 0)
        let block1 = makeBlock(time: 1600, nonce: 1)

        // Write blocks, close
        let store1 = try BlockStore(blocksDir: tempDir, network: .regtest)
        try store1.storeBlock(block0, height: 0)
        try store1.storeBlock(block1, height: 1)
        try store1.flush()
        try store1.close()

        // Reopen and verify
        let store2 = try BlockStore(blocksDir: tempDir, network: .regtest)
        XCTAssertEqual(store2.storedCount, 2)

        let loaded0 = try store2.loadBlock(height: 0)
        XCTAssertEqual(loaded0, block0)

        let loaded1 = try store2.loadBlock(height: 1)
        XCTAssertEqual(loaded1, block1)

        try store2.close()
    }

    // MARK: - Continue appending after reload

    func testAppendAfterReload() throws {
        let block0 = makeBlock(time: 1000, nonce: 0)
        let block1 = makeBlock(time: 1600, nonce: 1)

        // Write first block, close
        let store1 = try BlockStore(blocksDir: tempDir, network: .regtest)
        try store1.storeBlock(block0, height: 0)
        try store1.flush()
        try store1.close()

        // Reopen and append second block
        let store2 = try BlockStore(blocksDir: tempDir, network: .regtest)
        XCTAssertEqual(store2.storedCount, 1)

        try store2.storeBlock(block1, height: 1)
        XCTAssertEqual(store2.storedCount, 2)

        let loaded0 = try store2.loadBlock(height: 0)
        XCTAssertEqual(loaded0, block0)

        let loaded1 = try store2.loadBlock(height: 1)
        XCTAssertEqual(loaded1, block1)

        try store2.close()
    }

    // MARK: - Network mismatch

    func testNetworkMismatch() throws {
        // Create a regtest store
        let store = try BlockStore(blocksDir: tempDir, network: .regtest)
        try store.close()

        // Try to open as mainnet
        XCTAssertThrowsError(
            try BlockStore(blocksDir: tempDir, network: .main)
        ) { error in
            if case BlockStoreError.networkMismatch = error {} else {
                XCTFail("Expected networkMismatch, got \(error)")
            }
        }
    }

    // MARK: - File rotation

    func testFileRotation() throws {
        // Use a tiny maxFileSize to force rotation
        let store = try BlockStore(blocksDir: tempDir, network: .regtest, maxFileSize: 1024)

        var blocks: [Block] = []
        // Store blocks until we rotate (each block is ~300+ bytes framed)
        for i in 0..<10 {
            let block = makeBlock(time: UInt64(1000 + i * 600), nonce: UInt32(i))
            try store.storeBlock(block, height: i)
            blocks.append(block)
        }

        XCTAssertEqual(store.storedCount, 10)

        // Verify both data files exist
        let fm = FileManager.default
        XCTAssertTrue(fm.fileExists(atPath: tempDir + "/blk00000.dat"))
        XCTAssertTrue(fm.fileExists(atPath: tempDir + "/blk00001.dat"))

        // Load all blocks and verify correctness
        for (i, expected) in blocks.enumerated() {
            let loaded = try store.loadBlock(height: i)
            XCTAssertEqual(loaded, expected, "Block at height \(i) should match after rotation")
        }

        try store.close()
    }

    // MARK: - Block frame format

    func testBlockFrameFormat() throws {
        let store = try BlockStore(blocksDir: tempDir, network: .regtest)

        let block = makeBlock(time: 1000, nonce: 42)
        try store.storeBlock(block, height: 0)
        try store.flush()

        // Read raw bytes from blk00000.dat
        let dataPath = tempDir + "/blk00000.dat"
        let rawData = try Data(contentsOf: URL(fileURLWithPath: dataPath))

        // First 4 bytes: network magic (LE)
        var reader = BufferReader([UInt8](rawData))
        let magic = try reader.readUInt32LE()
        XCTAssertEqual(magic, NetworkType.regtest.magic, "Frame should start with network magic")

        // Next 4 bytes: block data length (LE)
        let length = try reader.readUInt32LE()

        // Serialize block independently to check
        var blockWriter = BufferWriter(capacity: block.serializedSize)
        block.write(to: &blockWriter)
        XCTAssertEqual(Int(length), blockWriter.data.count, "Frame length should match serialized block size")

        // Total file size should be 8 (frame header) + block data
        XCTAssertEqual(rawData.count, 8 + blockWriter.data.count)

        try store.close()
    }

    // MARK: - Reload after rotation

    func testReloadAfterRotation() throws {
        let block0 = makeBlock(time: 1000, nonce: 0)
        let block1 = makeBlock(time: 1600, nonce: 1)
        let block2 = makeBlock(time: 2200, nonce: 2)
        let block3 = makeBlock(time: 2800, nonce: 3)

        // Write across 2+ files with tiny max size, then close
        let store1 = try BlockStore(blocksDir: tempDir, network: .regtest, maxFileSize: 512)
        try store1.storeBlock(block0, height: 0)
        try store1.storeBlock(block1, height: 1)
        try store1.storeBlock(block2, height: 2)
        try store1.flush()
        try store1.close()

        // Reopen and verify resume works
        let store2 = try BlockStore(blocksDir: tempDir, network: .regtest, maxFileSize: 512)
        XCTAssertEqual(store2.storedCount, 3)

        // Can still read blocks from older files
        XCTAssertEqual(try store2.loadBlock(height: 0), block0)
        XCTAssertEqual(try store2.loadBlock(height: 1), block1)
        XCTAssertEqual(try store2.loadBlock(height: 2), block2)

        // Can append more blocks after reload
        try store2.storeBlock(block3, height: 3)
        XCTAssertEqual(store2.storedCount, 4)
        XCTAssertEqual(try store2.loadBlock(height: 3), block3)

        try store2.close()
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
