import XCTest
@testable import Script
import Base
import Protocol

// MARK: - Opcode Tests

final class OpcodeTests: XCTestCase {

    func testSmallIntValues() {
        XCTAssertEqual(Opcode.OP_0.smallIntValue, 0)
        XCTAssertEqual(Opcode.OP_1.smallIntValue, 1)
        XCTAssertEqual(Opcode.OP_16.smallIntValue, 16)
        XCTAssertNil(Opcode.OP_CHECKSIG.smallIntValue)
    }

    func testIsSmallInt() {
        XCTAssertTrue(Opcode.OP_0.isSmallInt)
        XCTAssertTrue(Opcode.OP_1.isSmallInt)
        XCTAssertTrue(Opcode.OP_16.isSmallInt)
        XCTAssertFalse(Opcode.OP_PUSHDATA1.isSmallInt)
        XCTAssertFalse(Opcode.OP_DUP.isSmallInt)
    }

    func testIsDisabled() {
        XCTAssertTrue(Opcode.OP_CAT.isDisabled)
        XCTAssertTrue(Opcode.OP_MUL.isDisabled)
        XCTAssertTrue(Opcode.OP_LSHIFT.isDisabled)
        XCTAssertFalse(Opcode.OP_ADD.isDisabled)
        XCTAssertFalse(Opcode.OP_DUP.isDisabled)
    }

    func testDirectPush() {
        XCTAssertFalse(isDirectPush(0x00))
        XCTAssertTrue(isDirectPush(0x01))
        XCTAssertTrue(isDirectPush(0x4b))
        XCTAssertFalse(isDirectPush(0x4c))
    }
}

// MARK: - ScriptNum Tests

final class ScriptNumTests: XCTestCase {

    func testEncodeZero() {
        XCTAssertEqual(ScriptNum.encode(0), [])
    }

    func testEncodePositive() {
        XCTAssertEqual(ScriptNum.encode(1), [0x01])
        XCTAssertEqual(ScriptNum.encode(127), [0x7F])
        XCTAssertEqual(ScriptNum.encode(128), [0x80, 0x00])
        XCTAssertEqual(ScriptNum.encode(255), [0xFF, 0x00])
        XCTAssertEqual(ScriptNum.encode(256), [0x00, 0x01])
    }

    func testEncodeNegative() {
        XCTAssertEqual(ScriptNum.encode(-1), [0x81])
        XCTAssertEqual(ScriptNum.encode(-127), [0xFF])
        XCTAssertEqual(ScriptNum.encode(-128), [0x80, 0x80])
        XCTAssertEqual(ScriptNum.encode(-255), [0xFF, 0x80])
    }

    func testDecodeEmpty() throws {
        XCTAssertEqual(try ScriptNum.decode([]), 0)
    }

    func testDecodePositive() throws {
        XCTAssertEqual(try ScriptNum.decode([0x01]), 1)
        XCTAssertEqual(try ScriptNum.decode([0x7F]), 127)
        XCTAssertEqual(try ScriptNum.decode([0x80, 0x00]), 128)
        XCTAssertEqual(try ScriptNum.decode([0xFF, 0x00]), 255)
    }

    func testDecodeNegative() throws {
        XCTAssertEqual(try ScriptNum.decode([0x81]), -1)
        XCTAssertEqual(try ScriptNum.decode([0xFF]), -127)
        XCTAssertEqual(try ScriptNum.decode([0x80, 0x80]), -128)
    }

    func testRoundTrip() throws {
        for val: Int64 in [-1000, -1, 0, 1, 127, 128, 255, 256, 1000, 65535] {
            let encoded = ScriptNum.encode(val)
            let decoded = try ScriptNum.decode(encoded, minimalEncoding: false)
            XCTAssertEqual(decoded, val, "Round-trip failed for \(val)")
        }
    }

    func testTooLarge() {
        XCTAssertThrowsError(try ScriptNum.decode([1, 2, 3, 4, 5]))
    }

    func testCastToBool() {
        XCTAssertFalse(ScriptNum.castToBool([]))
        XCTAssertFalse(ScriptNum.castToBool([0x00]))
        XCTAssertFalse(ScriptNum.castToBool([0x80]))  // negative zero
        XCTAssertFalse(ScriptNum.castToBool([0x00, 0x80]))  // negative zero, 2 bytes
        XCTAssertTrue(ScriptNum.castToBool([0x01]))
        XCTAssertTrue(ScriptNum.castToBool([0x80, 0x00]))  // 128, not negative zero
    }
}

// MARK: - Script Tests

final class ScriptTests: XCTestCase {

    func testEmptyScript() {
        let script = Script()
        XCTAssertTrue(script.isEmpty)
        XCTAssertEqual(script.size, 0)
    }

    func testParseDirectPush() throws {
        // Push 3 bytes: [0x03, 0xAA, 0xBB, 0xCC]
        let script = Script([0x03, 0xAA, 0xBB, 0xCC])
        let instructions = try script.instructions()
        XCTAssertEqual(instructions.count, 1)
        XCTAssertEqual(instructions[0], .pushData([0xAA, 0xBB, 0xCC]))
    }

    func testParsePushData1() throws {
        let raw: [UInt8] = [Opcode.OP_PUSHDATA1.rawValue, 0x02, 0xDE, 0xAD]
        let script = Script(raw)
        let instructions = try script.instructions()
        XCTAssertEqual(instructions.count, 1)
        XCTAssertEqual(instructions[0], .pushData([0xDE, 0xAD]))
    }

    func testParseOpcodes() throws {
        let script = Script([
            Opcode.OP_DUP.rawValue,
            Opcode.OP_HASH160.rawValue,
            0x14, // push 20 bytes
        ] + [UInt8](repeating: 0xAA, count: 20) + [
            Opcode.OP_EQUALVERIFY.rawValue,
            Opcode.OP_CHECKSIG.rawValue,
        ])
        let instructions = try script.instructions()
        XCTAssertEqual(instructions.count, 5)
        XCTAssertEqual(instructions[0], .opcode(.OP_DUP))
        XCTAssertEqual(instructions[1], .opcode(.OP_HASH160))
        XCTAssertEqual(instructions[2], .pushData([UInt8](repeating: 0xAA, count: 20)))
        XCTAssertEqual(instructions[3], .opcode(.OP_EQUALVERIFY))
        XCTAssertEqual(instructions[4], .opcode(.OP_CHECKSIG))
    }

    func testBuildingP2PKH() throws {
        let hash = [UInt8](repeating: 0xBB, count: 20)
        let script = Script.p2pkh(hash)
        XCTAssertTrue(script.isP2PKH)
        XCTAssertEqual(script.size, 25)

        let instructions = try script.instructions()
        XCTAssertEqual(instructions.count, 5)
    }

    func testScriptRoundTrip() throws {
        let script = Script.p2pkh([UInt8](repeating: 0xCC, count: 20))

        var writer = BufferWriter()
        script.write(to: &writer)

        var reader = BufferReader(writer.data)
        let decoded = try Script.read(from: &reader)
        XCTAssertEqual(decoded, script)
    }

    func testBuildFromInstructions() throws {
        let script = Script(building: [
            .opcode(.OP_1),
            .opcode(.OP_2),
            .opcode(.OP_ADD),
            .opcode(.OP_3),
            .opcode(.OP_EQUAL),
        ])
        XCTAssertEqual(script.size, 5)
        let instructions = try script.instructions()
        XCTAssertEqual(instructions.count, 5)
    }

    func testInvalidPushDataThrows() {
        // Direct push 5 bytes but only 2 available
        let script = Script([0x05, 0x01, 0x02])
        XCTAssertThrowsError(try script.instructions())
    }
}

// MARK: - ScriptStack Tests

final class ScriptStackTests: XCTestCase {

    func testPushPop() throws {
        var stack = ScriptStack()
        stack.push([0x01])
        stack.push([0x02])
        XCTAssertEqual(stack.count, 2)
        XCTAssertEqual(try stack.pop(), [0x02])
        XCTAssertEqual(try stack.pop(), [0x01])
        XCTAssertTrue(stack.isEmpty)
    }

    func testPopEmpty() {
        var stack = ScriptStack()
        XCTAssertThrowsError(try stack.pop())
    }

    func testPeek() throws {
        var stack = ScriptStack()
        stack.push([0x01])
        stack.push([0x02])
        stack.push([0x03])
        XCTAssertEqual(try stack.peek(0), [0x03])
        XCTAssertEqual(try stack.peek(1), [0x02])
        XCTAssertEqual(try stack.peek(2), [0x01])
    }

    func testPushBool() throws {
        var stack = ScriptStack()
        stack.pushBool(true)
        stack.pushBool(false)
        XCTAssertFalse(try stack.popBool())
        XCTAssertTrue(try stack.popBool())
    }

    func testPushInt() throws {
        var stack = ScriptStack()
        stack.pushInt(42)
        stack.pushInt(-1)
        stack.pushInt(0)
        XCTAssertEqual(try stack.popInt(), 0)
        XCTAssertEqual(try stack.popInt(), -1)
        XCTAssertEqual(try stack.popInt(), 42)
    }

    func testDup() throws {
        var stack = ScriptStack()
        stack.push([0x42])
        try stack.dup()
        XCTAssertEqual(stack.count, 2)
        XCTAssertEqual(try stack.pop(), [0x42])
        XCTAssertEqual(try stack.pop(), [0x42])
    }

    func testSwap() throws {
        var stack = ScriptStack()
        stack.push([0x01])
        stack.push([0x02])
        try stack.swap()
        XCTAssertEqual(try stack.pop(), [0x01])
        XCTAssertEqual(try stack.pop(), [0x02])
    }
}

// MARK: - SigHash Tests

final class SigHashTests: XCTestCase {

    // MARK: - Helpers

    private func makeSimpleTx() throws -> Transaction {
        let hash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))
        return Transaction(
            inputs: [Input(prevout: Outpoint(hash: hash, index: 0))],
            outputs: [Output(value: 100_000, address: addr)]
        )
    }

    private func makeP2WPKHScript() -> Script {
        // OP_0 <20-byte hash> (version 0 witness program)
        Script([0x00, 0x14] + [UInt8](repeating: 0xCC, count: 20))
    }

    // MARK: - SigHash.compute Tests

    func testSigHashAllDeterministic() throws {
        let tx = try makeSimpleTx()
        let script = makeP2WPKHScript()

        let hash1 = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .all)
        let hash2 = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .all)

        XCTAssertEqual(hash1, hash2, "SIGHASH_ALL should be deterministic")
    }

    func testSigHashAllDifferentFromNone() throws {
        let tx = try makeSimpleTx()
        let script = makeP2WPKHScript()

        let hashAll = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .all)
        let hashNone = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .none)

        XCTAssertNotEqual(hashAll, hashNone, "SIGHASH_ALL and SIGHASH_NONE should produce different hashes")
    }

    func testSigHashSingleVsAll() throws {
        let tx = try makeSimpleTx()
        let script = makeP2WPKHScript()

        let hashAll = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .all)
        let hashSingle = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .single)

        XCTAssertNotEqual(hashAll, hashSingle, "SIGHASH_SINGLE and SIGHASH_ALL should produce different hashes")
    }

    func testSigHashSingleReverse() throws {
        let tx = try makeSimpleTx()
        let script = makeP2WPKHScript()

        let hash = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .singleReverse)

        // Verify it produces a valid non-zero hash
        XCTAssertNotEqual(hash, .zero, "SIGHASH_SINGLE_REVERSE should produce a non-zero hash")
    }

    func testSigHashAnyoneCanPay() throws {
        let tx = try makeSimpleTx()
        let script = makeP2WPKHScript()

        let hashAll = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .all)
        let anyoneCanPayType = SigHashType(SigHashType.all.rawValue | SigHashType.anyoneCanPayFlag)
        let hashACP = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: anyoneCanPayType)

        XCTAssertNotEqual(hashAll, hashACP, "SIGHASH_ALL|ANYONECANPAY should differ from plain SIGHASH_ALL")
    }

    func testSigHashNoInput() throws {
        let tx = try makeSimpleTx()
        let script = makeP2WPKHScript()

        let hashAll = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .all)
        let noInputType = SigHashType(SigHashType.all.rawValue | SigHashType.noInputFlag)
        let hashNoInput = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: noInputType)

        XCTAssertNotEqual(hashAll, hashNoInput, "SIGHASH_ALL|NOINPUT should differ from plain SIGHASH_ALL")
    }

    func testSigHashDifferentIndex() throws {
        let hash1 = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let hash2 = try Hash256([UInt8](repeating: 0xDD, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))
        let tx = Transaction(
            inputs: [
                Input(prevout: Outpoint(hash: hash1, index: 0)),
                Input(prevout: Outpoint(hash: hash2, index: 1)),
            ],
            outputs: [
                Output(value: 50_000, address: addr),
                Output(value: 50_000, address: addr),
            ]
        )
        let script = makeP2WPKHScript()

        let sigHash0 = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 50_000, type: .all)
        let sigHash1 = try SigHash.compute(tx: tx, index: 1, prevScript: script, value: 50_000, type: .all)

        XCTAssertNotEqual(sigHash0, sigHash1, "Different input indices should produce different hashes")
    }

    func testSigHashDifferentValue() throws {
        let tx = try makeSimpleTx()
        let script = makeP2WPKHScript()

        let hash1 = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 100_000, type: .all)
        let hash2 = try SigHash.compute(tx: tx, index: 0, prevScript: script, value: 200_000, type: .all)

        XCTAssertNotEqual(hash1, hash2, "Different values should produce different hashes")
    }

    // MARK: - SigHash.extractType Tests

    func testExtractTypeAll() {
        let sig: [UInt8] = [0x01, 0x02, 0x01]
        let sigType = SigHash.extractType(from: sig)
        XCTAssertNotNil(sigType)
        XCTAssertEqual(sigType, .all, "Last byte 0x01 should extract as SIGHASH_ALL")
    }

    func testExtractTypeEmpty() {
        let sigType = SigHash.extractType(from: [])
        XCTAssertNil(sigType, "Empty signature should return nil")
    }

    // MARK: - SigHash.stripType Tests

    func testStripType() {
        let sig: [UInt8] = [0xAA, 0xBB, 0x01]
        let stripped = SigHash.stripType(from: sig)
        XCTAssertEqual(stripped, [0xAA, 0xBB], "stripType should remove the last byte")
    }

    func testStripTypeEmpty() {
        let stripped = SigHash.stripType(from: [])
        XCTAssertEqual(stripped, [], "stripType on empty should return empty")
    }

    // MARK: - SigHashType Flag Tests

    func testSigHashTypeFlags() {
        let acpAll = SigHashType(SigHashType.all.rawValue | SigHashType.anyoneCanPayFlag)
        XCTAssertTrue(acpAll.isAnyoneCanPay, "0x81 should have ANYONECANPAY flag")
        XCTAssertFalse(acpAll.isNoInput, "0x81 should NOT have NOINPUT flag")

        let noInputAll = SigHashType(SigHashType.all.rawValue | SigHashType.noInputFlag)
        XCTAssertFalse(noInputAll.isAnyoneCanPay, "0x41 should NOT have ANYONECANPAY flag")
        XCTAssertTrue(noInputAll.isNoInput, "0x41 should have NOINPUT flag")

        let combined = SigHashType(SigHashType.all.rawValue | SigHashType.anyoneCanPayFlag | SigHashType.noInputFlag)
        XCTAssertTrue(combined.isAnyoneCanPay, "0xC1 should have ANYONECANPAY flag")
        XCTAssertTrue(combined.isNoInput, "0xC1 should have NOINPUT flag")

        let plain = SigHashType.all
        XCTAssertFalse(plain.isAnyoneCanPay, "Plain ALL should NOT have ANYONECANPAY")
        XCTAssertFalse(plain.isNoInput, "Plain ALL should NOT have NOINPUT")
    }

    func testSigHashTypeBaseType() {
        // 0x81 = ALL | ANYONECANPAY → baseType should be 1 (ALL)
        let acpAll = SigHashType(0x81)
        XCTAssertEqual(acpAll.baseType, 1, "baseType of 0x81 should strip flags to 1")

        // 0xC1 = ALL | ANYONECANPAY | NOINPUT → baseType should be 1 (ALL)
        let combined = SigHashType(0xC1)
        XCTAssertEqual(combined.baseType, 1, "baseType of 0xC1 should strip flags to 1")

        // 0x42 = NONE | NOINPUT → baseType should be 2 (NONE)
        let noInputNone = SigHashType(0x42)
        XCTAssertEqual(noInputNone.baseType, 2, "baseType of 0x42 should strip flags to 2")

        // Plain types should pass through unchanged
        XCTAssertEqual(SigHashType.all.baseType, 1)
        XCTAssertEqual(SigHashType.none.baseType, 2)
        XCTAssertEqual(SigHashType.single.baseType, 3)
        XCTAssertEqual(SigHashType.singleReverse.baseType, 4)
    }
}
