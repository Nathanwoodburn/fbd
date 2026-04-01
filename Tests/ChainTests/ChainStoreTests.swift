import XCTest
import ExtCrypto
@testable import Chain
import Base
import Protocol
import Consensus

final class ChainEntrySerializationTests: XCTestCase {

    func testRoundTrip() throws {
        let entry = try Genesis.entry(for: .regtest)

        // Build a second entry to test non-genesis fields
        let header = BlockHeader(
            nonce: 42,
            time: entry.time + 600,
            prevBlock: entry.hash,
            treeRoot: Hash256(unchecked: [UInt8](repeating: 0xAB, count: 32)),
            extraNonce: [UInt8](repeating: 0xCD, count: 24),
            reservedRoot: Hash256(unchecked: [UInt8](repeating: 0xEF, count: 32)),
            witnessRoot: Hash256(unchecked: [UInt8](repeating: 0x11, count: 32)),
            merkleRoot: Hash256(unchecked: [UInt8](repeating: 0x22, count: 32)),
            version: 7,
            bits: 0x207fffff,
            mask: [UInt8](repeating: 0x33, count: 32)
        )
        let child = try ChainEntry.fromBlock(header, prev: entry, slots: 4)

        var writer = BufferWriter(capacity: child.serializedSize)
        child.write(to: &writer)
        XCTAssertEqual(writer.data.count, ChainEntry.recordSize)

        var reader = BufferReader( writer.data)
        let decoded = try ChainEntry.read(from: &reader)

        XCTAssertEqual(decoded, child)
        XCTAssertEqual(decoded.hash, child.hash)
        XCTAssertEqual(decoded.height, child.height)
        XCTAssertEqual(decoded.chainwork, child.chainwork)
        XCTAssertEqual(decoded.extraNonce, child.extraNonce)
        XCTAssertEqual(decoded.mask, child.mask)
    }

    func testRecordSizeIs308() {
        XCTAssertEqual(ChainEntry.recordSize, 308)
    }

    func testGenesisRoundTrip() throws {
        let genesis = try Genesis.entry(for: .regtest)
        let data = genesis.serializedData()
        XCTAssertEqual(data.count, 308)

        var reader = BufferReader( data)
        let decoded = try ChainEntry.read(from: &reader)
        XCTAssertEqual(decoded, genesis)
    }
}

final class ChainStoreTests: XCTestCase {

    private var tempDir: String!

    override func setUp() {
        super.setUp()
        tempDir = NSTemporaryDirectory() + "chainstore_test_\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: tempDir)
        super.tearDown()
    }

    private var storePath: String { tempDir + "/headers.bin" }

    // MARK: - Basic operations

    func testCreateNewStore() throws {
        let store = try ChainStore(path: storePath, network: .regtest)
        XCTAssertEqual(store.entryCount, 0)

        let entries = try store.loadEntries()
        XCTAssertTrue(entries.isEmpty)
        try store.close()
    }

    func testAppendAndLoad() throws {
        let genesis = try Genesis.entry(for: .regtest)

        // Create a few entries by hand (just need valid serialization, not PoW)
        let entry1 = ChainEntry(
            hash: Hash256(unchecked: [UInt8](repeating: 0x01, count: 32)),
            version: 0, prevBlock: genesis.hash,
            merkleRoot: .zero, witnessRoot: .zero, treeRoot: .zero, reservedRoot: .zero,
            time: genesis.time + 1, bits: 0x207fffff, nonce: 1,
            extraNonce: [UInt8](repeating: 0, count: 24),
            mask: [UInt8](repeating: 0, count: 32),
            height: 1, chainwork: genesis.chainwork + genesis.proof
        )
        let entry2 = ChainEntry(
            hash: Hash256(unchecked: [UInt8](repeating: 0x02, count: 32)),
            version: 0, prevBlock: entry1.hash,
            merkleRoot: .zero, witnessRoot: .zero, treeRoot: .zero, reservedRoot: .zero,
            time: genesis.time + 2, bits: 0x207fffff, nonce: 2,
            extraNonce: [UInt8](repeating: 0, count: 24),
            mask: [UInt8](repeating: 0, count: 32),
            height: 2, chainwork: entry1.chainwork + entry1.proof
        )

        let store = try ChainStore(path: storePath, network: .regtest)
        try store.appendEntries([entry1, entry2])
        XCTAssertEqual(store.entryCount, 2)

        let loaded = try store.loadEntries()
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(loaded[0], entry1)
        XCTAssertEqual(loaded[1], entry2)
        try store.close()
    }

    // MARK: - Reload from disk

    func testReloadFromDisk() throws {
        let genesis = try Genesis.entry(for: .regtest)
        let entry = ChainEntry(
            hash: Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32)),
            version: 0, prevBlock: genesis.hash,
            merkleRoot: .zero, witnessRoot: .zero, treeRoot: .zero, reservedRoot: .zero,
            time: genesis.time + 1, bits: 0x207fffff, nonce: 99,
            extraNonce: [UInt8](repeating: 0, count: 24),
            mask: [UInt8](repeating: 0, count: 32),
            height: 1, chainwork: genesis.chainwork + genesis.proof
        )

        // Write entries, close
        let store1 = try ChainStore(path: storePath, network: .regtest)
        try store1.appendEntries([entry])
        try store1.close()

        // Reopen and verify
        let store2 = try ChainStore(path: storePath, network: .regtest)
        XCTAssertEqual(store2.entryCount, 1)
        let loaded = try store2.loadEntries()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded[0], entry)
        try store2.close()
    }

    // MARK: - Network mismatch

    func testNetworkMismatch() throws {
        // Create a regtest store
        let store = try ChainStore(path: storePath, network: .regtest)
        try store.close()

        // Try to open as mainnet
        XCTAssertThrowsError(try ChainStore(path: storePath, network: .main)) { error in
            if case ChainStoreError.networkMismatch = error {} else {
                XCTFail("Expected networkMismatch, got \(error)")
            }
        }
    }

    // MARK: - Partial write truncation

    func testPartialWriteTruncated() throws {
        let genesis = try Genesis.entry(for: .regtest)
        let entry = ChainEntry(
            hash: Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32)),
            version: 0, prevBlock: genesis.hash,
            merkleRoot: .zero, witnessRoot: .zero, treeRoot: .zero, reservedRoot: .zero,
            time: genesis.time + 1, bits: 0x207fffff, nonce: 1,
            extraNonce: [UInt8](repeating: 0, count: 24),
            mask: [UInt8](repeating: 0, count: 32),
            height: 1, chainwork: genesis.chainwork + genesis.proof
        )

        // Write one valid entry
        let store1 = try ChainStore(path: storePath, network: .regtest)
        try store1.appendEntries([entry])
        try store1.close()

        // Append garbage bytes to simulate a partial write
        let fh = FileHandle(forWritingAtPath: storePath)!
        fh.seekToEndOfFile()
        fh.write(Data([0xFF, 0xFE, 0xFD]))
        fh.closeFile()

        // Reopen — should truncate the partial entry and recover the valid one
        let store2 = try ChainStore(path: storePath, network: .regtest)
        XCTAssertEqual(store2.entryCount, 1)
        let loaded = try store2.loadEntries()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded[0], entry)
        try store2.close()
    }

    // MARK: - Incremental append

    func testIncrementalAppend() throws {
        let genesis = try Genesis.entry(for: .regtest)
        let entry1 = ChainEntry(
            hash: Hash256(unchecked: [UInt8](repeating: 0x01, count: 32)),
            version: 0, prevBlock: genesis.hash,
            merkleRoot: .zero, witnessRoot: .zero, treeRoot: .zero, reservedRoot: .zero,
            time: genesis.time + 1, bits: 0x207fffff, nonce: 1,
            extraNonce: [UInt8](repeating: 0, count: 24),
            mask: [UInt8](repeating: 0, count: 32),
            height: 1, chainwork: genesis.chainwork + genesis.proof
        )
        let entry2 = ChainEntry(
            hash: Hash256(unchecked: [UInt8](repeating: 0x02, count: 32)),
            version: 0, prevBlock: entry1.hash,
            merkleRoot: .zero, witnessRoot: .zero, treeRoot: .zero, reservedRoot: .zero,
            time: genesis.time + 2, bits: 0x207fffff, nonce: 2,
            extraNonce: [UInt8](repeating: 0, count: 24),
            mask: [UInt8](repeating: 0, count: 32),
            height: 2, chainwork: entry1.chainwork + entry1.proof
        )

        // Append first entry
        let store = try ChainStore(path: storePath, network: .regtest)
        try store.appendEntries([entry1])
        XCTAssertEqual(store.entryCount, 1)

        // Append second entry
        try store.appendEntries([entry2])
        XCTAssertEqual(store.entryCount, 2)

        // Verify both are loaded
        let loaded = try store.loadEntries()
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(loaded[0], entry1)
        XCTAssertEqual(loaded[1], entry2)
        try store.close()
    }

    // MARK: - Chain integration

    func testChainFlush() throws {
        let store = try ChainStore(path: storePath, network: .regtest)
        let chain = try Chain(network: .regtest, store: store)
        chain.clockOverride = chain.tip.time

        // Mine a block on top of genesis
        let genesis = chain.tip
        let target = Target256.fromCompact(0x207fffff)
        var header: BlockHeader!
        for nonce in UInt32(0)...UInt32.max {
            let h = BlockHeader(
                nonce: nonce,
                time: genesis.time + 1,
                prevBlock: genesis.hash,
                bits: 0x207fffff
            )
            let hash = try ProofOfWork.powHash(for: h, slots: 4)
            if Target256(bigEndian: hash.bytes) <= target {
                header = h
                break
            }
        }

        try chain.add(header: header, proof: regtestProof(for: header))
        XCTAssertEqual(chain.height, 1)

        // Flush to disk
        try chain.flush()
        XCTAssertEqual(store.entryCount, 1)

        // Flush again (no-op)
        try chain.flush()
        XCTAssertEqual(store.entryCount, 1)

        try store.close()
    }

    func testChainReloadFromStore() throws {
        // Create chain, mine a block, flush
        let store1 = try ChainStore(path: storePath, network: .regtest)
        let chain1 = try Chain(network: .regtest, store: store1)
        chain1.clockOverride = chain1.tip.time

        let genesis = chain1.tip
        let target = Target256.fromCompact(0x207fffff)
        var header: BlockHeader!
        for nonce in UInt32(0)...UInt32.max {
            let h = BlockHeader(
                nonce: nonce,
                time: genesis.time + 1,
                prevBlock: genesis.hash,
                bits: 0x207fffff
            )
            let hash = try ProofOfWork.powHash(for: h, slots: 4)
            if Target256(bigEndian: hash.bytes) <= target {
                header = h
                break
            }
        }

        let entry = try chain1.add(header: header, proof: regtestProof(for: header))
        try chain1.flush()
        try store1.close()

        // Reload into new chain
        let store2 = try ChainStore(path: storePath, network: .regtest)
        let chain2 = try Chain(network: .regtest, store: store2)
        chain2.clockOverride = chain2.tip.time

        XCTAssertEqual(chain2.height, 1)
        XCTAssertEqual(chain2.tip.hash, entry.hash)
        XCTAssertTrue(chain2.has(hash: entry.hash))
        XCTAssertTrue(chain2.has(hash: genesis.hash))
        try store2.close()
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
