import XCTest
import ExtCrypto
@testable import Consensus
import Base
import Protocol

// MARK: - Target256 Tests

final class Target256Tests: XCTestCase {

    func testZero() {
        let z = Target256.zero
        XCTAssertTrue(z.isZero)
        XCTAssertEqual(z.bitLength, 0)
    }

    func testOne() {
        let one = Target256.one
        XCTAssertFalse(one.isZero)
        XCTAssertEqual(one.bitLength, 1)
        XCTAssertTrue(one.bit(0))
        XCTAssertFalse(one.bit(1))
    }

    func testBigEndianRoundTrip() {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[0] = 0x01
        bytes[31] = 0xFF

        let t = Target256(bigEndian: bytes)
        XCTAssertEqual(t.w0, 0xFF)
        XCTAssertEqual(t.w3, 0x01 << 56)
        XCTAssertEqual(t.bigEndianBytes(), bytes)
    }

    func testComparison() {
        let a = Target256(0, 0, 0, 100)
        let b = Target256(0, 0, 0, 200)
        let c = Target256(0, 0, 1, 0)

        XCTAssertTrue(a < b)
        XCTAssertTrue(b < c)
        XCTAssertTrue(a < c)
        XCTAssertFalse(b < a)
        XCTAssertTrue(a <= a)
        XCTAssertTrue(b > a)
    }

    func testAddition() {
        let a = Target256(0, 0, 0, .max)
        let b = Target256.one
        let sum = a + b
        XCTAssertEqual(sum.w0, 0)
        XCTAssertEqual(sum.w1, 1)
    }

    func testSubtraction() {
        let a = Target256(0, 0, 1, 0)
        let b = Target256.one
        let diff = a - b
        XCTAssertEqual(diff.w0, .max)
        XCTAssertEqual(diff.w1, 0)
    }

    func testMultiply() {
        let a = Target256(0, 0, 0, 1_000_000)
        let result = a.multiplied(by: 600)
        XCTAssertEqual(result.w0, 600_000_000)
    }

    func testDivideByScalar() {
        let a = Target256(0, 0, 0, 600_000_000)
        let (q, r) = a.dividedBy(600)
        XCTAssertEqual(q.w0, 1_000_000)
        XCTAssertEqual(r, 0)
    }

    func testDivideByScalarWithRemainder() {
        let a = Target256(0, 0, 0, 7)
        let (q, r) = a.dividedBy(3)
        XCTAssertEqual(q.w0, 2)
        XCTAssertEqual(r, 1)
    }

    func testDivmod() {
        let a = Target256(0, 0, 0, 100)
        let b = Target256(0, 0, 0, 7)
        let (q, rem) = a.divmod(b)
        XCTAssertEqual(q, Target256(0, 0, 0, 14))
        XCTAssertEqual(rem, Target256(0, 0, 0, 2))
    }

    func testDivmodLarger() {
        let a = Target256(0, 0, 1, 0)  // 2^64
        let b = Target256(0, 1, 0, 0)  // 2^128
        let (q, rem) = b.divmod(a)
        XCTAssertEqual(q, a)
        XCTAssertEqual(rem, .zero)
    }

    func testShiftLeft() {
        let a = Target256.one
        let shifted = a.shiftedLeft(by: 64)
        XCTAssertEqual(shifted.w0, 0)
        XCTAssertEqual(shifted.w1, 1)

        let shifted2 = a.shiftedLeft(by: 1)
        XCTAssertEqual(shifted2.w0, 2)
    }

    func testShiftLeftCrossWord() {
        let a = Target256(0, 0, 0, 0x8000_0000_0000_0000)
        let shifted = a.shiftedLeft(by: 1)
        XCTAssertEqual(shifted.w0, 0)
        XCTAssertEqual(shifted.w1, 1)
    }

    func testTwosComplement() {
        let a = Target256.one
        let neg = a.twosComplement()
        XCTAssertEqual(neg, Target256.max)
    }

    func testInversePow2_256() {
        // floor(2^256 / 2) = 2^255
        let two = Target256(0, 0, 0, 2)
        let result = two.inversePow2_256()
        XCTAssertTrue(result.bit(255))
        XCTAssertFalse(result.bit(254))
    }

    func testDescription() {
        let a = Target256(0, 0, 0, 0xFF)
        let desc = a.description
        XCTAssertEqual(desc.count, 64)
        XCTAssertTrue(desc.hasSuffix("00000000000000ff"))
    }

    // MARK: - Compact Target

    func testCompactRoundTrip() {
        let bits: UInt32 = 0x1c00ffff
        let target = Target256.fromCompact(bits)
        XCTAssertFalse(target.isZero)
        let roundTripped = target.toCompact()
        XCTAssertEqual(roundTripped, bits)
    }

    func testCompactZero() {
        let target = Target256.fromCompact(0)
        XCTAssertTrue(target.isZero)
    }

    func testCompactKnownValue() {
        // 0x1d00ffff: mantissa = 0x00ffff, exponent = 0x1d (29)
        // target = 0x00ffff * 256^(29-3) = 0x00ffff * 256^26
        let bits: UInt32 = 0x1d00ffff
        let target = Target256.fromCompact(bits)
        XCTAssertFalse(target.isZero)
        XCTAssertEqual(target.bitLength, 224)
    }

    func testCompactNegativeReturnsZero() {
        let bits: UInt32 = 0x1c800000
        let target = Target256.fromCompact(bits)
        XCTAssertTrue(target.isZero)
    }

    func testCompactSmallExponent() {
        let bits: UInt32 = 0x03123456
        let target = Target256.fromCompact(bits)
        XCTAssertEqual(target.w0, 0x123456)
    }

    func testDivideByScalarLargeValue() {
        // Test division when high words are populated
        let a = Target256(0, 0, 1, 0)  // 2^64
        let (q, r) = a.dividedBy(2)
        XCTAssertEqual(q, Target256(0, 0, 0, 0x8000_0000_0000_0000))
        XCTAssertEqual(r, 0)
    }
}

// MARK: - Block Reward Tests

final class BlockRewardTests: XCTestCase {

    func testGenesisReward() {
        // 500 FBC = 500_000_000 bumps
        XCTAssertEqual(BlockReward.getReward(height: 0), 500_000_000)
    }

    func testFirstHalving() {
        XCTAssertEqual(BlockReward.getReward(height: 1_051_200), 250_000_000)
    }

    func testSecondHalving() {
        XCTAssertEqual(BlockReward.getReward(height: 2_102_400), 125_000_000)
    }

    func testRewardAtMaxHalvings() {
        XCTAssertEqual(BlockReward.getReward(height: 52 * 1_051_200), 0)
    }

    func testRewardBeforeMaxHalvings() {
        // Reward at halving 28 is still positive (5e8 >> 28 = 1)
        XCTAssertTrue(BlockReward.getReward(height: 28 * 1_051_200) > 0)
        // Reward at halving 29 is zero (5e8 >> 29 = 0)
        XCTAssertEqual(BlockReward.getReward(height: 29 * 1_051_200), 0)
    }

    func testTotalMinedFirstEra() {
        let total = BlockReward.totalMined(upTo: 1_051_200)
        XCTAssertEqual(total, 500_000_000 * 1_051_200)
    }

    func testTotalMinedTwoEras() {
        let total = BlockReward.totalMined(upTo: 2_102_400)
        let expected: Int64 = 500_000_000 * 1_051_200 + 250_000_000 * 1_051_200
        XCTAssertEqual(total, expected)
    }
}

// MARK: - Difficulty Retarget Tests

final class DifficultyRetargetTests: XCTestCase {

    func testTargetToWork() {
        let work = DifficultyRetarget.targetToWork(0x1c00ffff)
        XCTAssertFalse(work.isZero)
    }

    func testGetSuitableBlock() {
        let a = DifficultyRetarget.BlockInfo(time: 100, chainwork: .zero)
        let b = DifficultyRetarget.BlockInfo(time: 300, chainwork: .zero)
        let c = DifficultyRetarget.BlockInfo(time: 200, chainwork: .zero)
        let median = DifficultyRetarget.getSuitableBlock(c, b, a)
        XCTAssertEqual(median.time, 200)
    }

    func testRetargetSteadyState() {
        let params = ConsensusParams.mainnet
        let work = Target256(0, 0, 0, 1_000_000)
        let first = DifficultyRetarget.BlockInfo(time: 0, chainwork: .zero)
        let last = DifficultyRetarget.BlockInfo(
            time: UInt64(params.targetTimespan), chainwork: work
        )
        let bits = DifficultyRetarget.retarget(first: first, last: last, params: params)
        XCTAssertTrue(bits != 0)
    }

    func testRetargetClampMin() {
        let params = ConsensusParams.mainnet
        let work = Target256(0, 0, 0, 1_000_000)
        let first = DifficultyRetarget.BlockInfo(time: 0, chainwork: .zero)
        let last = DifficultyRetarget.BlockInfo(time: 1, chainwork: work)
        let bits = DifficultyRetarget.retarget(first: first, last: last, params: params)
        XCTAssertTrue(bits != 0)
    }

    func testRetargetClampMax() {
        let params = ConsensusParams.mainnet
        let work = Target256(0, 0, 0, 1_000_000)
        let first = DifficultyRetarget.BlockInfo(time: 0, chainwork: .zero)
        // Elapsed time is 10x the target timespan — should clamp to maxActualTimespan
        let last = DifficultyRetarget.BlockInfo(
            time: UInt64(params.targetTimespan) * 10, chainwork: work
        )
        let bits = DifficultyRetarget.retarget(first: first, last: last, params: params)
        XCTAssertTrue(bits != 0)
    }

    func testRetargetReturnsLimitOnZeroHashrate() {
        let params = ConsensusParams.mainnet
        // Both first and last have the same chainwork (zero), so work diff is zero
        let first = DifficultyRetarget.BlockInfo(time: 0, chainwork: .zero)
        let last = DifficultyRetarget.BlockInfo(
            time: UInt64(params.targetTimespan), chainwork: .zero
        )
        let bits = DifficultyRetarget.retarget(first: first, last: last, params: params)
        XCTAssertEqual(bits, params.powBits)
    }

    func testGetSuitableBlockAlreadySorted() {
        // Times already in order: 100, 200, 300
        let a = DifficultyRetarget.BlockInfo(time: 100, chainwork: .zero)
        let b = DifficultyRetarget.BlockInfo(time: 200, chainwork: .zero)
        let c = DifficultyRetarget.BlockInfo(time: 300, chainwork: .zero)
        let median = DifficultyRetarget.getSuitableBlock(c, b, a)
        XCTAssertEqual(median.time, 200)
    }

    func testGetSuitableBlockReverseSorted() {
        // Times in reverse order: 300, 200, 100
        let a = DifficultyRetarget.BlockInfo(time: 300, chainwork: .zero)
        let b = DifficultyRetarget.BlockInfo(time: 200, chainwork: .zero)
        let c = DifficultyRetarget.BlockInfo(time: 100, chainwork: .zero)
        let median = DifficultyRetarget.getSuitableBlock(a, b, c)
        XCTAssertEqual(median.time, 200)
    }

    func testTargetToWorkZero() {
        // Compact bits = 0 decodes to zero target, should return zero work
        let work = DifficultyRetarget.targetToWork(0)
        XCTAssertTrue(work.isZero)
    }

    func testTargetToWorkMaxTarget() {
        // 0x207fffff is the regtest easy target — should produce non-zero work
        let work = DifficultyRetarget.targetToWork(0x207fffff)
        XCTAssertFalse(work.isZero)
    }
}

// MARK: - Block Validator Tests

final class BlockValidatorTests: XCTestCase {

    func testCheckBodyEmptyBlockFails() {
        let block = Block(header: BlockHeader(), transactions: [], balloonProof: regtestProof(for: BlockHeader()))
        XCTAssertThrowsError(try BlockValidator.checkBody(block)) { error in
            XCTAssertEqual(error as? ConsensusError, .noTransactions)
        }
    }

    func testCheckBodyNoCoinbaseFails() throws {
        let prevHash = try Hash256([UInt8](repeating: 0x11, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x22, count: 20))
        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 100, address: addr)]
        )
        let block = Block(header: BlockHeader(), transactions: [tx], balloonProof: regtestProof(for: BlockHeader()))
        XCTAssertThrowsError(try BlockValidator.checkBody(block)) { error in
            XCTAssertEqual(error as? ConsensusError, .missingCoinbase)
        }
    }

    func testCheckBodyValidCoinbase() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x33, count: 20))
        let coinbase = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: 2_000_000_000, address: addr)],
            witnesses: [Witness(items: [[0x01]])]
        )
        let block = Block(header: BlockHeader(), transactions: [coinbase], balloonProof: regtestProof(for: BlockHeader()))
        XCTAssertNoThrow(try BlockValidator.checkBody(block))
    }

    func testCheckTransactionNoInputsFails() {
        let tx = Transaction(inputs: [], outputs: [])
        XCTAssertThrowsError(try BlockValidator.checkTransactionSanity(tx)) { error in
            XCTAssertEqual(error as? ConsensusError, .noInputs)
        }
    }

    func testCheckTransactionNoOutputsFails() {
        let tx = Transaction(inputs: [Input(prevout: .null)], outputs: [])
        XCTAssertThrowsError(try BlockValidator.checkTransactionSanity(tx)) { error in
            XCTAssertEqual(error as? ConsensusError, .noOutputs)
        }
    }

    func testCheckTransactionDuplicateInputFails() throws {
        let hash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))
        let tx = Transaction(
            inputs: [
                Input(prevout: Outpoint(hash: hash, index: 0)),
                Input(prevout: Outpoint(hash: hash, index: 0)),
            ],
            outputs: [Output(value: 100, address: addr)]
        )
        XCTAssertThrowsError(try BlockValidator.checkTransactionSanity(tx)) { error in
            XCTAssertEqual(error as? ConsensusError, .duplicateInput)
        }
    }

    func testCoinbaseMaturity() {
        let params = ConsensusParams.mainnet
        XCTAssertThrowsError(
            try BlockValidator.checkCoinbaseMaturity(coinbaseHeight: 1, spendHeight: 100, params: params)
        )
        XCTAssertNoThrow(
            try BlockValidator.checkCoinbaseMaturity(coinbaseHeight: 1, spendHeight: 101, params: params)
        )
    }

    func testCoinbaseValueTooHigh() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x44, count: 20))
        let tx = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: 3_000_000_000, address: addr)],
            witnesses: [Witness(items: [[0x01]])]
        )
        XCTAssertThrowsError(
            try BlockValidator.checkCoinbaseValue(tx, height: 0, fees: 0, params: .mainnet)
        )
    }

    func testCoinbaseValueWithFees() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x55, count: 20))
        // 500 FBC reward + 500 FBC fees = 1,000,000,000
        let tx = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: 1_000_000_000, address: addr)],
            witnesses: [Witness(items: [[0x01]])]
        )
        XCTAssertNoThrow(
            try BlockValidator.checkCoinbaseValue(tx, height: 0, fees: 500_000_000, params: .mainnet)
        )
    }

    func testCheckTimestampValid() {
        // Header time = currentTime, well within maxFutureBlockTime
        let header = BlockHeader(time: 1000)
        XCTAssertNoThrow(
            try BlockValidator.checkTimestamp(header, currentTime: 1000, params: .mainnet)
        )
    }

    func testCheckTimestampTooNew() {
        let params = ConsensusParams.mainnet
        let currentTime: UInt64 = 10_000
        // Header time exceeds currentTime + maxFutureBlockTime by 1
        let header = BlockHeader(time: currentTime + UInt64(params.maxFutureBlockTime) + 1)
        XCTAssertThrowsError(
            try BlockValidator.checkTimestamp(header, currentTime: currentTime, params: params)
        ) { error in
            XCTAssertEqual(error as? ConsensusError, .timeTooNew)
        }
    }

    func testCheckMedianTimePastValid() {
        // Header time = 1001, MTP = 1000 — time > MTP, should pass
        let header = BlockHeader(time: 1001)
        XCTAssertNoThrow(
            try BlockValidator.checkMedianTimePast(header, medianTimePast: 1000)
        )
    }

    func testCheckMedianTimePastFails() {
        // Header time = 1000, MTP = 1000 — time must be > MTP (not >=), should fail
        let header = BlockHeader(time: 1000)
        XCTAssertThrowsError(
            try BlockValidator.checkMedianTimePast(header, medianTimePast: 1000)
        ) { error in
            XCTAssertEqual(error as? ConsensusError, .timeTooOld)
        }
    }

    func testCheckBodyUnexpectedCoinbase() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x66, count: 20))
        // Two coinbase transactions — second one should trigger unexpectedCoinbase
        let coinbase1 = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: 2_000_000_000, address: addr)],
            witnesses: [Witness(items: [[0x01]])]
        )
        let coinbase2 = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: 100, address: addr)],
            witnesses: [Witness(items: [[0x02]])]
        )
        let block = Block(header: BlockHeader(), transactions: [coinbase1, coinbase2], balloonProof: regtestProof(for: BlockHeader()))
        XCTAssertThrowsError(try BlockValidator.checkBody(block)) { error in
            XCTAssertEqual(error as? ConsensusError, .unexpectedCoinbase)
        }
    }

    func testCheckTransactionInvalidOutputValue() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x77, count: 20))
        let prevHash = try Hash256([UInt8](repeating: 0x11, count: 32))
        // Output value exceeds Amount.maxMoney
        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: UInt64(Amount.maxMoney) + 1, address: addr)]
        )
        XCTAssertThrowsError(try BlockValidator.checkTransactionSanity(tx)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidOutputValue)
        }
    }

    func testCheckTransactionTotalOverflow() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x88, count: 20))
        let prevHash = try Hash256([UInt8](repeating: 0x22, count: 32))
        // Two outputs: first at maxMoney (valid individually), second at 1
        // Total exceeds maxMoney -> totalOutputOverflow
        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [
                Output(value: UInt64(Amount.maxMoney), address: addr),
                Output(value: 1, address: addr),
            ]
        )
        XCTAssertThrowsError(try BlockValidator.checkTransactionSanity(tx)) { error in
            XCTAssertEqual(error as? ConsensusError, .totalOutputOverflow)
        }
    }

    func testCheckProofOfWorkInvalidTarget() {
        // Header with bits=0 produces a zero target, which is invalid
        let header = BlockHeader(bits: 0)
        XCTAssertThrowsError(try BlockValidator.checkProofOfWork(header, params: .regtest)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidTarget)
        }
    }

    func testCoinbaseMaturityExactBoundary() {
        let params = ConsensusParams.mainnet
        // depth = spendHeight - coinbaseHeight
        // At maturity boundary: depth == coinbaseMaturity (100) should pass
        XCTAssertNoThrow(
            try BlockValidator.checkCoinbaseMaturity(
                coinbaseHeight: 0, spendHeight: params.coinbaseMaturity, params: params
            )
        )
        // One block short: depth == coinbaseMaturity - 1 should fail
        XCTAssertThrowsError(
            try BlockValidator.checkCoinbaseMaturity(
                coinbaseHeight: 0, spendHeight: params.coinbaseMaturity - 1, params: params
            )
        ) { error in
            XCTAssertEqual(error as? ConsensusError, .immatureCoinbase)
        }
    }

    func testWitnessCountMismatchRejected() throws {
        let prevHash1 = try Hash256([UInt8](repeating: 0x11, count: 32))
        let prevHash2 = try Hash256([UInt8](repeating: 0x22, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x99, count: 20))
        // 2 inputs but only 1 witness — should be rejected
        let tx = Transaction(
            inputs: [
                Input(prevout: Outpoint(hash: prevHash1, index: 0)),
                Input(prevout: Outpoint(hash: prevHash2, index: 0)),
            ],
            outputs: [Output(value: 100, address: addr)],
            witnesses: [Witness(items: [[0x01]])]
        )
        XCTAssertThrowsError(try BlockValidator.checkTransactionSanity(tx)) { error in
            XCTAssertEqual(error as? ConsensusError, .witnessCountMismatch)
        }
    }

    func testCoinbaseValueOverflowSafe() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0xAA, count: 20))
        let tx = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: UInt64(Amount.maxMoney), address: addr)],
            witnesses: [Witness(items: [[0x01]])]
        )
        // fees = Int64.max should trigger overflow detection, not a crash
        XCTAssertThrowsError(
            try BlockValidator.checkCoinbaseValue(tx, height: 0, fees: Int64.max, params: .mainnet)
        ) { error in
            XCTAssertEqual(error as? ConsensusError, .coinbaseValueTooHigh)
        }
    }

    func testCheckProofOfWorkRejectsTrivialTarget() throws {
        // 0x21100000 decodes to a target larger than mainnet's powLimit (0x200fffff)
        let header = BlockHeader(bits: 0x21100000)
        // Use a dummy hash — target validity is checked before the hash comparison
        let dummyHash = Hash256(unchecked: [UInt8](repeating: 0x00, count: 32))
        XCTAssertThrowsError(
            try BlockValidator.checkProofOfWork(header, hash: dummyHash, params: .mainnet)
        ) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidTarget)
        }
    }
}

// MARK: - PoW Tests (Balloon Hash)

final class ProofOfWorkTests: XCTestCase {

    func testPasswordBuild() {
        let password = ProofOfWork.buildPassword(BlockHeader())
        // prevBlock(32) + merkle(32) + witness(32) + tree(32) + reserved(32) + time(8) + bits(4) + version(4)
        XCTAssertEqual(password.count, 176)
    }

    func testSaltBuild() {
        let salt = ProofOfWork.buildSalt(BlockHeader())
        // nonce(4) + extraNonce(24)
        XCTAssertEqual(salt.count, 28)
    }

    func testPowHashDeterministic() throws {
        let header = BlockHeader(nonce: 42, time: 1000, bits: 0x207fffff)
        let hash1 = try ProofOfWork.powHash(for: header, slots: 4)
        let hash2 = try ProofOfWork.powHash(for: header, slots: 4)
        XCTAssertEqual(hash1, hash2)
    }

    func testDifferentNonceDifferentHash() throws {
        let h1 = BlockHeader(nonce: 1, time: 1000, bits: 0x207fffff)
        let h2 = BlockHeader(nonce: 2, time: 1000, bits: 0x207fffff)
        XCTAssertNotEqual(try ProofOfWork.powHash(for: h1, slots: 4), try ProofOfWork.powHash(for: h2, slots: 4))
    }

    func testVerifyEasyTarget() throws {
        let params = ConsensusParams.regtest
        let bits: UInt32 = 0x207fffff
        for nonce: UInt32 in 0..<100 {
            let header = BlockHeader(nonce: nonce, time: 1000, bits: bits)
            if try ProofOfWork.verify(header, params: params) {
                XCTAssertNoThrow(try BlockValidator.checkProofOfWork(header, params: params))
                return
            }
        }
        XCTFail("Could not find valid nonce within 100 attempts")
    }
}

// MARK: - ConsensusParams Tests

final class ConsensusParamsTests: XCTestCase {

    func testMainnetParams() {
        let p = ConsensusParams.mainnet
        XCTAssertEqual(p.targetSpacing, 120)
        XCTAssertEqual(p.targetWindow, 72)
        XCTAssertEqual(p.halvingInterval, 1_051_200)
        XCTAssertEqual(p.coinbaseMaturity, 100)
        XCTAssertFalse(p.noRetargeting)
    }

    func testRegtestParams() {
        let p = ConsensusParams.regtest
        XCTAssertTrue(p.noRetargeting)
        XCTAssertEqual(p.coinbaseMaturity, 2)
    }

    func testTimespanClamping() {
        let p = ConsensusParams.mainnet
        // 72 blocks * 120 seconds = 8640
        XCTAssertEqual(p.targetTimespan, 8_640)
        XCTAssertEqual(p.minActualTimespan, 2_160)
        XCTAssertEqual(p.maxActualTimespan, 34_560)
    }
}

// MARK: - BalloonProof Verification Tests

final class BalloonProofTests: XCTestCase {

    private let params = ConsensusParams.regtest

    private func validHeaderAndProof() -> (BlockHeader, BalloonProof, Hash256) {
        let header = BlockHeader(nonce: 0, time: 1000, bits: 0x207fffff)
        let (hash, proof) = try! ProofOfWork.powHashWithProof(for: header, params: params)
        return (header, proof, hash)
    }

    func testValidProofVerifies() throws {
        let (header, proof, _) = validHeaderAndProof()
        XCTAssertNoThrow(try ProofOfWork.verifyWithProof(header: header, proof: proof, params: params))
    }

    func testTamperedExpandValueFails() throws {
        let (header, proof, _) = validHeaderAndProof()
        var samples = proof.samples
        let s = samples[1]
        var bad = s.expandValue
        bad[0] ^= 0xFF
        samples[1] = BalloonProof.Sample(
            index: s.index, expandValue: bad, expandPrev: s.expandPrev,
            mixedValue: s.mixedValue, depPrev: s.depPrev,
            randomIdx: s.randomIdx, depRandom: s.depRandom
        )
        let badProof = BalloonProof(samples: samples)
        XCTAssertThrowsError(try ProofOfWork.verifyWithProof(header: header, proof: badProof, params: params)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidProof)
        }
    }

    func testTamperedMixedValueFails() throws {
        let (header, proof, _) = validHeaderAndProof()
        var samples = proof.samples
        let s = samples[2]
        var bad = s.mixedValue
        bad[15] ^= 0x01
        samples[2] = BalloonProof.Sample(
            index: s.index, expandValue: s.expandValue, expandPrev: s.expandPrev,
            mixedValue: bad, depPrev: s.depPrev,
            randomIdx: s.randomIdx, depRandom: s.depRandom
        )
        let badProof = BalloonProof(samples: samples)
        XCTAssertThrowsError(try ProofOfWork.verifyWithProof(header: header, proof: badProof, params: params)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidProof)
        }
    }

    func testTamperedDepRandomFails() throws {
        let (header, proof, _) = validHeaderAndProof()
        var samples = proof.samples
        // Find a sample where randomIdx != index (so depRandom is actually used)
        let si = samples.indices.first { samples[$0].randomIdx != samples[$0].index } ?? 3
        let s = samples[si]
        var bad = s.depRandom
        bad[0] ^= 0xFF
        samples[si] = BalloonProof.Sample(
            index: s.index, expandValue: s.expandValue, expandPrev: s.expandPrev,
            mixedValue: s.mixedValue, depPrev: s.depPrev,
            randomIdx: s.randomIdx, depRandom: bad
        )
        let badProof = BalloonProof(samples: samples)
        XCTAssertThrowsError(try ProofOfWork.verifyWithProof(header: header, proof: badProof, params: params)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidProof)
        }
    }

    func testWrongSampleIndexFails() throws {
        let (header, proof, _) = validHeaderAndProof()
        var samples = proof.samples
        let s = samples[5]
        // Replace index with a different value
        let fakeIdx = (s.index + 1) % UInt32(params.balloonSlots)
        samples[5] = BalloonProof.Sample(
            index: fakeIdx, expandValue: s.expandValue, expandPrev: s.expandPrev,
            mixedValue: s.mixedValue, depPrev: s.depPrev,
            randomIdx: s.randomIdx, depRandom: s.depRandom
        )
        let badProof = BalloonProof(samples: samples)
        XCTAssertThrowsError(try ProofOfWork.verifyWithProof(header: header, proof: badProof, params: params)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidProof)
        }
    }

    func testProofFromDifferentHeaderFails() throws {
        let (_, proof, _) = validHeaderAndProof()
        let otherHeader = BlockHeader(nonce: 99, time: 2000, bits: 0x207fffff)
        XCTAssertThrowsError(try ProofOfWork.verifyWithProof(header: otherHeader, proof: proof, params: params)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidProof)
        }
    }

    func testOutputSlotTamperedFails() throws {
        let (header, proof, _) = validHeaderAndProof()
        var samples = proof.samples
        // Sample 0 is the output slot (index = slots-1). Tamper its mixedValue.
        let s = samples[0]
        var bad = s.mixedValue
        bad[31] ^= 0x01
        samples[0] = BalloonProof.Sample(
            index: s.index, expandValue: s.expandValue, expandPrev: s.expandPrev,
            mixedValue: bad, depPrev: s.depPrev,
            randomIdx: s.randomIdx, depRandom: s.depRandom
        )
        let badProof = BalloonProof(samples: samples)
        XCTAssertThrowsError(try ProofOfWork.verifyWithProof(header: header, proof: badProof, params: params)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidProof)
        }
    }

    func testSerializeDeserializeRoundTrip() throws {
        let (_, proof, _) = validHeaderAndProof()
        let data = proof.serialize()
        XCTAssertEqual(data.count, BalloonProof.serializedSize)
        let decoded = BalloonProof.deserialize(data)
        XCTAssertEqual(decoded, proof)
    }

    func testDeserializeBadLengthReturnsNil() {
        XCTAssertNil(BalloonProof.deserialize([UInt8](repeating: 0, count: 100)))
        XCTAssertNil(BalloonProof.deserialize([]))
    }

    func testVerifyWithProofRejectsTamperedProof() throws {
        let (header, proof, _) = validHeaderAndProof()
        var samples = proof.samples
        let s = samples[0]
        var bad = s.mixedValue
        bad[0] ^= 0xFF
        samples[0] = BalloonProof.Sample(
            index: s.index, expandValue: s.expandValue, expandPrev: s.expandPrev,
            mixedValue: bad, depPrev: s.depPrev,
            randomIdx: s.randomIdx, depRandom: s.depRandom
        )
        let badProof = BalloonProof(samples: samples)

        // verifyWithProof is what Chain.add calls — test it directly
        XCTAssertThrowsError(try ProofOfWork.verifyWithProof(header: header, proof: badProof, params: params)) { error in
            XCTAssertEqual(error as? ConsensusError, .invalidProof)
        }
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
