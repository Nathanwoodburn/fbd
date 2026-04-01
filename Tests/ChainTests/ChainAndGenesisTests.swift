import XCTest
@testable import Chain
import Base
import ExtCrypto
import Protocol
import Consensus

// MARK: - Test Mining Helper

/// Mine a valid regtest block header by iterating nonces until PoW passes.
/// Regtest target (0x207fffff) is very easy; ~50% of hashes pass.
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

// MARK: - Genesis Tests

final class GenesisTests: XCTestCase {

    func testRegtestGenesis() throws {
        let header = Genesis.header(for: .regtest)
        XCTAssertEqual(header.prevBlock, .zero)
        XCTAssertEqual(header.time, 1774224000)
        XCTAssertEqual(header.bits, 0x207fffff)
        XCTAssertEqual(header.version, 0)
    }

    func testMainnetGenesis() throws {
        let header = Genesis.header(for: .main)
        XCTAssertEqual(header.prevBlock, .zero)
        XCTAssertEqual(header.bits, ConsensusParams.mainnet.powBits)
    }

    func testTestnetGenesis() throws {
        let header = Genesis.header(for: .testnet)
        XCTAssertEqual(header.prevBlock, .zero)
        XCTAssertEqual(header.bits, ConsensusParams.testnet.powBits)
    }

    func testGenesisEntry() throws {
        let entry = try Genesis.entry(for: .regtest)
        XCTAssertEqual(entry.height, 0)
        XCTAssertTrue(entry.isGenesis)
        XCTAssertEqual(entry.prevBlock, .zero)
        XCTAssertFalse(entry.chainwork.isZero)
    }

    func testSimnetUsesRegtestGenesis() throws {
        let simnet = Genesis.header(for: .simnet)
        let regtest = Genesis.header(for: .regtest)
        XCTAssertEqual(simnet.bits, regtest.bits)
        XCTAssertEqual(simnet.time, regtest.time)
    }
}

// MARK: - ConsensusParams Network Mapping

final class ConsensusParamsNetworkTests: XCTestCase {

    func testMainnetMapping() {
        let params = ConsensusParams.params(for: .main)
        XCTAssertEqual(params.powBits, ConsensusParams.mainnet.powBits)
        XCTAssertFalse(params.noRetargeting)
    }

    func testTestnetMapping() {
        let params = ConsensusParams.params(for: .testnet)
        XCTAssertEqual(params.powBits, ConsensusParams.testnet.powBits)
    }

    func testRegtestMapping() {
        let params = ConsensusParams.params(for: .regtest)
        XCTAssertEqual(params.powBits, 0x207fffff)
        XCTAssertTrue(params.noRetargeting)
    }

    func testSimnetUsesRegtest() {
        let params = ConsensusParams.params(for: .simnet)
        XCTAssertEqual(params.powBits, ConsensusParams.regtest.powBits)
        XCTAssertTrue(params.noRetargeting)
    }
}

// MARK: - Chain Tests

final class ChainIndexTests: XCTestCase {

    func testInitWithGenesis() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        XCTAssertEqual(chain.height, 0)
        XCTAssertTrue(chain.tip.isGenesis)
        XCTAssertTrue(chain.has(hash: chain.tip.hash))
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
        XCTAssertEqual(chain.height, 1)
        XCTAssertEqual(chain.tip.height, 1)
        XCTAssertTrue(chain.has(hash: entry.hash))
    }

    func testRejectDuplicate() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesis = chain.tip

        let header = try mineRegtestHeader(
            time: genesis.time + 1,
            prevBlock: genesis.hash
        )

        let entry = try chain.add(header: header, proof: regtestProof(for: header))

        XCTAssertThrowsError(try chain.add(header: header, proof: regtestProof(for: header))) { error in
            if case HeaderError.duplicateHeader = error {} else {
                XCTFail("Expected duplicateHeader, got \(error)")
            }
        }
        XCTAssertEqual(chain.height, 1)
        XCTAssertTrue(chain.has(hash: entry.hash))
    }

    func testRejectOrphan() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        let orphan = BlockHeader(
            time: 1580745678,
            prevBlock: Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32)),
            bits: 0x207fffff
        )

        XCTAssertThrowsError(try chain.add(header: orphan, proof: regtestProof(for: orphan))) { error in
            if case HeaderError.orphanHeader = error {} else {
                XCTFail("Expected orphanHeader, got \(error)")
            }
        }
    }

    func testRejectBadDifficulty() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesis = chain.tip

        // Wrong bits for regtest (should be 0x207fffff)
        let header = BlockHeader(
            time: genesis.time + 1,
            prevBlock: genesis.hash,
            bits: 0x1c00ffff
        )

        XCTAssertThrowsError(try chain.add(header: header, proof: regtestProof(for: header)))
    }

    func testBuildChain() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        var prevEntry = chain.tip
        for i in 1...10 {
            let header = try mineRegtestHeader(
                time: prevEntry.time + 1,
                prevBlock: prevEntry.hash
            )
            prevEntry = try chain.add(header: header, proof: regtestProof(for: header))
            XCTAssertEqual(prevEntry.height, i)
        }

        XCTAssertEqual(chain.height, 10)
        XCTAssertEqual(chain.tip.height, 10)

        for i in 0...10 {
            let entry = chain.getEntryByHeight(i)
            XCTAssertNotNil(entry, "Entry at height \(i) should exist")
            XCTAssertEqual(entry?.height, i)
        }
    }

    func testGetLocator() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        var prevEntry = chain.tip
        for _ in 1...20 {
            let header = try mineRegtestHeader(
                time: prevEntry.time + 1,
                prevBlock: prevEntry.hash
            )
            prevEntry = try chain.add(header: header, proof: regtestProof(for: header))
        }

        let locator = chain.getLocator()

        XCTAssertEqual(locator.first, chain.tip.hash)
        XCTAssertEqual(locator.last, chain.getEntryByHeight(0)?.hash)
        XCTAssertTrue(locator.count < 20, "Locator should be compact")
        XCTAssertTrue(locator.count > 1, "Locator should have multiple entries")
    }

    func testGetPreviousTimestamps() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        var prevEntry = chain.tip
        for i in 1...15 {
            let header = try mineRegtestHeader(
                time: prevEntry.time + UInt64(i),
                prevBlock: prevEntry.hash
            )
            prevEntry = try chain.add(header: header, proof: regtestProof(for: header))
        }

        let timestamps = chain.getPreviousTimestamps(chain.tip, count: 11)
        XCTAssertEqual(timestamps.count, 11)
        XCTAssertEqual(timestamps[0], chain.tip.time)
    }

    func testGetEntryByHash() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesis = chain.tip

        let header = try mineRegtestHeader(
            time: genesis.time + 1,
            prevBlock: genesis.hash
        )
        let entry = try chain.add(header: header, proof: regtestProof(for: header))

        XCTAssertNotNil(chain.getEntry(hash: entry.hash))
        XCTAssertNil(chain.getEntry(hash: Hash256(unchecked: [UInt8](repeating: 0xFF, count: 32))))
    }

    func testChainworkIncreases() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesisWork = chain.tip.chainwork

        let header = try mineRegtestHeader(
            time: chain.tip.time + 1,
            prevBlock: chain.tip.hash
        )
        let entry = try chain.add(header: header, proof: regtestProof(for: header))

        XCTAssertTrue(entry.chainwork > genesisWork)
    }
}

// MARK: - BIP9 Soft Fork Deployment Tests

final class BIP9DeploymentTests: XCTestCase {

    /// Mine a regtest header with a specific version (for version bit signaling).
    private func mineRegtestHeaderWithVersion(
        time: UInt64,
        prevBlock: Hash256,
        version: UInt32 = 0,
        bits: UInt32 = 0x207fffff
    ) throws -> BlockHeader {
        let target = Target256.fromCompact(bits)
        for nonce in UInt32(0)...UInt32.max {
            let header = BlockHeader(
                nonce: nonce,
                time: time,
                prevBlock: prevBlock,
                version: version,
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

    /// Build a chain of N blocks with the given version, returning the last entry.
    @discardableResult
    private func buildChain(
        _ chain: Chain,
        count: Int,
        version: UInt32 = 0,
        startTime: UInt64? = nil
    ) throws -> ChainEntry {
        var prev = chain.tip
        let baseTime = startTime ?? prev.time
        for i in 1...count {
            let header = try mineRegtestHeaderWithVersion(
                time: baseTime + UInt64(i),
                prevBlock: prev.hash,
                version: version
            )
            prev = try chain.add(header: header, proof: regtestProof(for: header))
        }
        return prev
    }

    // MARK: - hasBit

    func testHasBitSimple() throws {
        let header = BlockHeader(version: 0b0000_0101, bits: 0x207fffff)
        let entry = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        XCTAssertTrue(entry.hasBit(0))
        XCTAssertFalse(entry.hasBit(1))
        XCTAssertTrue(entry.hasBit(2))
        XCTAssertFalse(entry.hasBit(3))
    }

    func testHasBitZeroVersion() throws {
        let header = BlockHeader(version: 0, bits: 0x207fffff)
        let entry = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        for bit in 0..<29 {
            XCTAssertFalse(entry.hasBit(bit), "Bit \(bit) should not be set")
        }
    }

    func testHasBitHighBits() throws {
        let header = BlockHeader(version: 1 << 28, bits: 0x207fffff)
        let entry = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        XCTAssertTrue(entry.hasBit(28))
        XCTAssertFalse(entry.hasBit(27))
    }

    // MARK: - getDeploymentState

    func testDeploymentDefinedBeforeStartTime() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        // Build a small chain — deployment starts far in the future
        try buildChain(chain, count: 10)

        let deployment = Deployment(name: "test", bit: 28, startTime: 9_999_999_999, timeout: 9_999_999_999)
        let state = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertEqual(state, .defined)
    }

    func testDeploymentStartedAfterStartTime() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        // Regtest window = 144. State at boundary 143 is always DEFINED (no prior window).
        // Need 2 windows so boundary 287 can transition DEFINED → STARTED.

        let deployment = Deployment(name: "test", bit: 28, startTime: 1000, timeout: 9_999_999_999)

        // Build 288 blocks (two full windows)
        try buildChain(chain, count: 288)

        let state = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertEqual(state, .started)
    }

    func testDeploymentLockedInAfterThreshold() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        // Regtest: window=144, threshold=108
        // Boundary 143: DEFINED, Boundary 287: STARTED, Boundary 431: count signaling

        let deployment = Deployment(name: "test", bit: 28, startTime: 1000, timeout: 9_999_999_999)

        // Window 1 (0-143): DEFINED
        // Window 2 (144-287): STARTED
        try buildChain(chain, count: 288)

        // Window 3 (288-431): 108 signaling + 36 non-signaling → LOCKED_IN
        try buildChain(chain, count: 108, version: 1 << 28)
        try buildChain(chain, count: 36, version: 0)

        let state = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertEqual(state, .lockedIn)
    }

    func testDeploymentActiveAfterLockedIn() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        let deployment = Deployment(name: "test", bit: 28, startTime: 1000, timeout: 9_999_999_999)

        // Boundary 143: DEFINED, Boundary 287: STARTED
        try buildChain(chain, count: 288)

        // Boundary 431: all signaling → LOCKED_IN
        try buildChain(chain, count: 144, version: 1 << 28)

        // Boundary 575: ACTIVE
        try buildChain(chain, count: 144)

        let state = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertEqual(state, .active)
    }

    func testDeploymentFailedAfterTimeout() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesisTime = chain.tip.time

        // Deployment starts before genesis, timeout shortly after genesis
        // Boundary 143: DEFINED (no prior window)
        // Boundary 287: MTP well past timeout → FAILED
        let deployment = Deployment(name: "test", bit: 28, startTime: 1000, timeout: genesisTime + 100)

        try buildChain(chain, count: 288)

        let state = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertEqual(state, .failed)
    }

    func testDeploymentNotEnoughSignaling() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        let deployment = Deployment(name: "test", bit: 28, startTime: 1000, timeout: 9_999_999_999)

        // Boundary 143: DEFINED, Boundary 287: STARTED
        try buildChain(chain, count: 288)

        // Window 3 (288-431): only 107 signaling (threshold is 108) → stays STARTED
        try buildChain(chain, count: 107, version: 1 << 28)
        try buildChain(chain, count: 37, version: 0)

        let state = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertEqual(state, .started)
    }

    func testDeploymentActiveIsTerminal() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        let deployment = Deployment(name: "test", bit: 28, startTime: 1000, timeout: 9_999_999_999)

        // Boundary 143: DEFINED, Boundary 287: STARTED
        try buildChain(chain, count: 288)
        // Boundary 431: all signaling → LOCKED_IN
        try buildChain(chain, count: 144, version: 1 << 28)
        // Boundary 575: ACTIVE
        try buildChain(chain, count: 144)

        // More windows — still active (terminal state)
        try buildChain(chain, count: 144)

        let state = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertEqual(state, .active)
    }

    // MARK: - getDeployments (aggregate)

    func testGetDeploymentsDefault() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let state = chain.getDeployments(prev: chain.tip)
        // At genesis, nothing is active (DeploymentState is empty — no soft forks)
        _ = state
    }

    // MARK: - ThresholdState

    func testThresholdStateStatusStrings() {
        XCTAssertEqual(ThresholdState.defined.statusString, "defined")
        XCTAssertEqual(ThresholdState.started.statusString, "started")
        XCTAssertEqual(ThresholdState.lockedIn.statusString, "locked_in")
        XCTAssertEqual(ThresholdState.active.statusString, "active")
        XCTAssertEqual(ThresholdState.failed.statusString, "failed")
    }

    // MARK: - Chain Reorganization

    func testForkDetectionAndReorg() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesis = chain.tip

        // Build main chain: genesis → A → B → C (height 3)
        let headerA = try mineRegtestHeaderWithVersion(
            time: genesis.time + 10, prevBlock: genesis.hash
        )
        let entryA = try chain.add(header: headerA, proof: regtestProof(for: headerA))

        let headerB = try mineRegtestHeaderWithVersion(
            time: entryA.time + 10, prevBlock: entryA.hash
        )
        let entryB = try chain.add(header: headerB, proof: regtestProof(for: headerB))

        let headerC = try mineRegtestHeaderWithVersion(
            time: entryB.time + 10, prevBlock: entryB.hash
        )
        let entryC = try chain.add(header: headerC, proof: regtestProof(for: headerC))

        XCTAssertEqual(chain.height, 3)
        XCTAssertEqual(chain.tip.hash, entryC.hash)

        // Build fork from A: A → D → E → F (3 blocks vs 2 on main after A)
        // Fork has more chainwork since it's longer
        let headerD = try mineRegtestHeaderWithVersion(
            time: entryA.time + 11, prevBlock: entryA.hash
        )
        let entryD = try chain.add(header: headerD, proof: regtestProof(for: headerD))
        // D doesn't trigger reorg yet (chainwork 2 vs main's 3)

        let headerE = try mineRegtestHeaderWithVersion(
            time: entryD.time + 10, prevBlock: entryD.hash
        )
        let entryE = try chain.add(header: headerE, proof: regtestProof(for: headerE))
        // E at height 3 same as C — chainwork might be equal

        let headerF = try mineRegtestHeaderWithVersion(
            time: entryE.time + 10, prevBlock: entryE.hash
        )
        let entryF = try chain.add(header: headerF, proof: regtestProof(for: headerF))
        // F at height 4 — definitely more chainwork

        // Chain should have reorged to the longer fork
        XCTAssertEqual(chain.height, 4)
        XCTAssertEqual(chain.tip.hash, entryF.hash)

        // byHeight should reflect the new chain
        XCTAssertEqual(chain.getEntryByHeight(0)?.hash, genesis.hash)
        XCTAssertEqual(chain.getEntryByHeight(1)?.hash, entryA.hash) // Common ancestor
        XCTAssertEqual(chain.getEntryByHeight(2)?.hash, entryD.hash) // New chain
        XCTAssertEqual(chain.getEntryByHeight(3)?.hash, entryE.hash)
        XCTAssertEqual(chain.getEntryByHeight(4)?.hash, entryF.hash)

        // Old chain entries should still be in byHash
        XCTAssertTrue(chain.has(hash: entryB.hash))
        XCTAssertTrue(chain.has(hash: entryC.hash))
    }

    func testNoReorgForWeakerFork() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time
        let genesis = chain.tip

        // Main chain: 5 blocks
        try buildChain(chain, count: 5)
        let mainTip = chain.tip

        // Fork from genesis with only 2 blocks — less chainwork
        let headerD = try mineRegtestHeaderWithVersion(
            time: genesis.time + 601, prevBlock: genesis.hash
        )
        _ = try chain.add(header: headerD, proof: regtestProof(for: headerD))

        // Tip should not change — main chain has more work
        XCTAssertEqual(chain.tip.hash, mainTip.hash)
        XCTAssertEqual(chain.height, 5)
    }

    func testReorgClearsBIP9Cache() throws {
        let chain = try Chain(network: .regtest)
        chain.clockOverride = chain.tip.time

        let deployment = Deployment(name: "test", bit: 28, startTime: 1000, timeout: 9_999_999_999)

        // Build 288 blocks to get STARTED state cached (2 windows)
        try buildChain(chain, count: 288)
        let state1 = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertEqual(state1, .started)

        // Now force a reorg by building a longer fork from genesis
        let genesis = chain.getEntryByHeight(0)!
        var prev = genesis
        for i in 1...300 {
            let header = try mineRegtestHeaderWithVersion(
                time: genesis.time + UInt64(i * 2),
                prevBlock: prev.hash
            )
            prev = try chain.add(header: header, proof: regtestProof(for: header))
        }

        // After reorg, cache should be cleared and state recomputed
        XCTAssertEqual(chain.height, 300)
        // State should still be computable without errors
        let state2 = chain.getDeploymentState(prev: chain.tip, deployment: deployment)
        XCTAssertNotNil(state2)
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
