import XCTest
@testable import Script
import Base
import Protocol

final class InterpreterTests: XCTestCase {

    /// Helper: create a dummy transaction for script testing.
    private func dummyTx() throws -> Transaction {
        let prevHash = try Hash256([UInt8](repeating: 0x11, count: 32))
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x22, count: 20))
        return Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 100_000, address: addr)],
            witnesses: [.empty]
        )
    }

    /// Helper: execute a script and return the stack.
    private func run(_ script: Script, initialStack: ScriptStack = ScriptStack(), flags: ScriptFlags = .none) throws -> ScriptStack {
        let tx = try dummyTx()
        var stack = initialStack
        try ScriptInterpreter.execute(
            script: script, stack: &stack,
            tx: tx, index: 0, value: 100_000, flags: flags
        )
        return stack
    }

    // MARK: - Push Operations

    func testOP0PushesEmpty() throws {
        let stack = try run(Script([Opcode.OP_0.rawValue]))
        XCTAssertEqual(stack.count, 1)
        XCTAssertEqual(stack.items[0], [])
    }

    func testSmallIntPush() throws {
        let script = Script([Opcode.OP_1.rawValue, Opcode.OP_16.rawValue])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 2)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 1)
        XCTAssertEqual(try ScriptNum.decode(stack.items[1]), 16)
    }

    func testOP1Negate() throws {
        let stack = try run(Script([Opcode.OP_1NEGATE.rawValue]))
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), -1)
    }

    func testDirectDataPush() throws {
        let script = Script([0x03, 0xAA, 0xBB, 0xCC])
        let stack = try run(script)
        XCTAssertEqual(stack.items[0], [0xAA, 0xBB, 0xCC])
    }

    // MARK: - Stack Operations

    func testDupDrop() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_DUP.rawValue,
            Opcode.OP_DROP.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 1)
    }

    func testSwap() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_SWAP.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 2)
        XCTAssertEqual(try ScriptNum.decode(stack.items[1]), 1)
    }

    func testRot() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_3.rawValue,
            Opcode.OP_ROT.rawValue,
        ])
        let stack = try run(script)
        // Before ROT: [1, 2, 3], After: [2, 3, 1]
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 2)
        XCTAssertEqual(try ScriptNum.decode(stack.items[1]), 3)
        XCTAssertEqual(try ScriptNum.decode(stack.items[2]), 1)
    }

    func testOver() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_OVER.rawValue,
        ])
        let stack = try run(script)
        // [1, 2, 1]
        XCTAssertEqual(stack.count, 3)
        XCTAssertEqual(try ScriptNum.decode(stack.items[2]), 1)
    }

    func testNip() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_NIP.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 1)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 2)
    }

    func testTuck() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_TUCK.rawValue,
        ])
        let stack = try run(script)
        // Before: [1, 2], After: [2, 1, 2]
        XCTAssertEqual(stack.count, 3)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 2)
        XCTAssertEqual(try ScriptNum.decode(stack.items[1]), 1)
        XCTAssertEqual(try ScriptNum.decode(stack.items[2]), 2)
    }

    func test2Dup() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_2DUP.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 4)
    }

    func test2Swap() throws {
        let script = Script([
            Opcode.OP_1.rawValue, Opcode.OP_2.rawValue,
            Opcode.OP_3.rawValue, Opcode.OP_4.rawValue,
            Opcode.OP_2SWAP.rawValue,
        ])
        let stack = try run(script)
        // Before: [1, 2, 3, 4], After: [3, 4, 1, 2]
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 3)
        XCTAssertEqual(try ScriptNum.decode(stack.items[1]), 4)
        XCTAssertEqual(try ScriptNum.decode(stack.items[2]), 1)
        XCTAssertEqual(try ScriptNum.decode(stack.items[3]), 2)
    }

    func testDepth() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_3.rawValue,
            Opcode.OP_DEPTH.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[3]), 3)
    }

    func testToFromAltStack() throws {
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_TOALTSTACK.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_FROMALTSTACK.rawValue,
        ])
        let stack = try run(script)
        // Stack: [2, 1]
        XCTAssertEqual(stack.count, 2)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 2)
        XCTAssertEqual(try ScriptNum.decode(stack.items[1]), 1)
    }

    func testIfDup() throws {
        // IFDUP when true: duplicates
        let script1 = Script([Opcode.OP_1.rawValue, Opcode.OP_IFDUP.rawValue])
        let stack1 = try run(script1)
        XCTAssertEqual(stack1.count, 2)

        // IFDUP when false: does not duplicate
        let script2 = Script([Opcode.OP_0.rawValue, Opcode.OP_IFDUP.rawValue])
        let stack2 = try run(script2)
        XCTAssertEqual(stack2.count, 1)
    }

    // MARK: - Arithmetic

    func testAdd() throws {
        let script = Script([
            Opcode.OP_2.rawValue,
            Opcode.OP_3.rawValue,
            Opcode.OP_ADD.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 5)
    }

    func testSub() throws {
        let script = Script([
            Opcode.OP_5.rawValue,
            Opcode.OP_3.rawValue,
            Opcode.OP_SUB.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 2)
    }

    func test1Add1Sub() throws {
        let script = Script([
            Opcode.OP_5.rawValue,
            Opcode.OP_1ADD.rawValue,
            Opcode.OP_1SUB.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 5)
    }

    func testNegate() throws {
        let script = Script([
            Opcode.OP_3.rawValue,
            Opcode.OP_NEGATE.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), -3)
    }

    func testAbs() throws {
        // Push -5 then ABS
        var stack = ScriptStack()
        stack.pushInt(-5)
        let result = try run(
            Script([Opcode.OP_ABS.rawValue]),
            initialStack: stack
        )
        XCTAssertEqual(try ScriptNum.decode(result.items[0]), 5)
    }

    func testNot() throws {
        let script1 = Script([Opcode.OP_0.rawValue, Opcode.OP_NOT.rawValue])
        XCTAssertEqual(try ScriptNum.decode(try run(script1).items[0]), 1)

        let script2 = Script([Opcode.OP_1.rawValue, Opcode.OP_NOT.rawValue])
        XCTAssertEqual(try ScriptNum.decode(try run(script2).items[0]), 0)
    }

    func testBoolAndOr() throws {
        let scriptAnd = Script([
            Opcode.OP_1.rawValue, Opcode.OP_1.rawValue, Opcode.OP_BOOLAND.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(scriptAnd).items[0]), 1)

        let scriptAndFalse = Script([
            Opcode.OP_1.rawValue, Opcode.OP_0.rawValue, Opcode.OP_BOOLAND.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(scriptAndFalse).items[0]), 0)

        let scriptOr = Script([
            Opcode.OP_0.rawValue, Opcode.OP_1.rawValue, Opcode.OP_BOOLOR.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(scriptOr).items[0]), 1)
    }

    func testComparisons() throws {
        // 2 < 3 = true
        let script = Script([
            Opcode.OP_2.rawValue, Opcode.OP_3.rawValue, Opcode.OP_LESSTHAN.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(script).items[0]), 1)

        // 3 > 2 = true
        let script2 = Script([
            Opcode.OP_3.rawValue, Opcode.OP_2.rawValue, Opcode.OP_GREATERTHAN.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(script2).items[0]), 1)
    }

    func testMinMax() throws {
        let scriptMin = Script([
            Opcode.OP_5.rawValue, Opcode.OP_3.rawValue, Opcode.OP_MIN.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(scriptMin).items[0]), 3)

        let scriptMax = Script([
            Opcode.OP_5.rawValue, Opcode.OP_3.rawValue, Opcode.OP_MAX.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(scriptMax).items[0]), 5)
    }

    func testWithin() throws {
        // 3 WITHIN(2, 5) = true
        let script = Script([
            Opcode.OP_3.rawValue, Opcode.OP_2.rawValue, Opcode.OP_5.rawValue,
            Opcode.OP_WITHIN.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(script).items[0]), 1)

        // 5 WITHIN(2, 5) = false (upper exclusive)
        let script2 = Script([
            Opcode.OP_5.rawValue, Opcode.OP_2.rawValue, Opcode.OP_5.rawValue,
            Opcode.OP_WITHIN.rawValue,
        ])
        XCTAssertEqual(try ScriptNum.decode(try run(script2).items[0]), 0)
    }

    // MARK: - Bitwise / Comparison

    func testEqual() throws {
        let script = Script([
            Opcode.OP_1.rawValue, Opcode.OP_1.rawValue, Opcode.OP_EQUAL.rawValue,
        ])
        XCTAssertTrue(try ScriptNum.castToBool(try run(script).items[0]))
    }

    func testEqualVerifySuccess() throws {
        let script = Script([
            Opcode.OP_1.rawValue, Opcode.OP_1.rawValue, Opcode.OP_EQUALVERIFY.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 0)
    }

    func testEqualVerifyFail() {
        let script = Script([
            Opcode.OP_1.rawValue, Opcode.OP_2.rawValue, Opcode.OP_EQUALVERIFY.rawValue,
        ])
        XCTAssertThrowsError(try run(script))
    }

    func testSize() throws {
        // Push 3-byte data, then SIZE
        let script = Script([0x03, 0xAA, 0xBB, 0xCC, Opcode.OP_SIZE.rawValue])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 2)
        XCTAssertEqual(try ScriptNum.decode(stack.items[1]), 3)
    }

    // MARK: - Flow Control

    func testIfTrue() throws {
        // OP_1 OP_IF OP_2 OP_ENDIF
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_IF.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_ENDIF.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 1)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 2)
    }

    func testIfFalse() throws {
        // OP_0 OP_IF OP_2 OP_ENDIF
        let script = Script([
            Opcode.OP_0.rawValue,
            Opcode.OP_IF.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_ENDIF.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 0)
    }

    func testIfElse() throws {
        // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let script = Script([
            Opcode.OP_0.rawValue,
            Opcode.OP_IF.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_ELSE.rawValue,
            Opcode.OP_3.rawValue,
            Opcode.OP_ENDIF.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 3)
    }

    func testNotIf() throws {
        // OP_0 OP_NOTIF OP_5 OP_ENDIF
        let script = Script([
            Opcode.OP_0.rawValue,
            Opcode.OP_NOTIF.rawValue,
            Opcode.OP_5.rawValue,
            Opcode.OP_ENDIF.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 5)
    }

    func testNestedIf() throws {
        // OP_1 OP_IF OP_1 OP_IF OP_7 OP_ENDIF OP_ENDIF
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_IF.rawValue,
            Opcode.OP_1.rawValue,
            Opcode.OP_IF.rawValue,
            Opcode.OP_7.rawValue,
            Opcode.OP_ENDIF.rawValue,
            Opcode.OP_ENDIF.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(try ScriptNum.decode(stack.items[0]), 7)
    }

    func testUnbalancedIfThrows() {
        let script = Script([Opcode.OP_1.rawValue, Opcode.OP_IF.rawValue])
        XCTAssertThrowsError(try run(script))
    }

    func testVerifySuccess() throws {
        let script = Script([Opcode.OP_1.rawValue, Opcode.OP_VERIFY.rawValue])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 0)
    }

    func testVerifyFail() {
        let script = Script([Opcode.OP_0.rawValue, Opcode.OP_VERIFY.rawValue])
        XCTAssertThrowsError(try run(script))
    }

    func testOpReturn() {
        let script = Script([Opcode.OP_RETURN.rawValue])
        XCTAssertThrowsError(try run(script))
    }

    // MARK: - Crypto

    func testSHA256() throws {
        // Push empty, SHA256
        let script = Script([Opcode.OP_0.rawValue, Opcode.OP_SHA256.rawValue])
        let stack = try run(script)
        XCTAssertEqual(stack.items[0].count, 32)
    }

    func testHash160() throws {
        // Push empty, HASH160
        let script = Script([Opcode.OP_0.rawValue, Opcode.OP_HASH160.rawValue])
        let stack = try run(script)
        XCTAssertEqual(stack.items[0].count, 20)
    }

    func testHash256() throws {
        // Push empty, HASH256
        let script = Script([Opcode.OP_0.rawValue, Opcode.OP_HASH256.rawValue])
        let stack = try run(script)
        XCTAssertEqual(stack.items[0].count, 32)
    }

    func testRIPEMD160() throws {
        let script = Script([Opcode.OP_0.rawValue, Opcode.OP_RIPEMD160.rawValue])
        let stack = try run(script)
        XCTAssertEqual(stack.items[0].count, 20)
    }

    func testSHA1() throws {
        let script = Script([Opcode.OP_0.rawValue, Opcode.OP_SHA1.rawValue])
        let stack = try run(script)
        XCTAssertEqual(stack.items[0].count, 20)
    }

    // MARK: - Error Conditions

    func testDisabledOpcodeThrows() {
        let script = Script([Opcode.OP_CAT.rawValue])
        XCTAssertThrowsError(try run(script))
    }

    func testReservedOpcodeThrows() {
        let script = Script([Opcode.OP_RESERVED.rawValue])
        XCTAssertThrowsError(try run(script))
    }

    func testStackUnderflow() {
        let script = Script([Opcode.OP_DUP.rawValue])
        XCTAssertThrowsError(try run(script))
    }

    func testOpCountExceeded() {
        // Create a script with >201 NOPs
        var raw = [UInt8]()
        for _ in 0..<202 {
            raw.append(Opcode.OP_NOP.rawValue)
        }
        let script = Script(raw)
        XCTAssertThrowsError(try run(script))
    }

    // MARK: - Complete Script Execution

    func testOnePlusOneEqualsTwo() throws {
        // OP_1 OP_1 OP_ADD OP_2 OP_EQUAL
        let script = Script([
            Opcode.OP_1.rawValue,
            Opcode.OP_1.rawValue,
            Opcode.OP_ADD.rawValue,
            Opcode.OP_2.rawValue,
            Opcode.OP_EQUAL.rawValue,
        ])
        let stack = try run(script)
        XCTAssertTrue(ScriptNum.castToBool(stack.items[0]))
    }

    func testNumEqualVerify() throws {
        let script = Script([
            Opcode.OP_3.rawValue,
            Opcode.OP_3.rawValue,
            Opcode.OP_NUMEQUALVERIFY.rawValue,
        ])
        let stack = try run(script)
        XCTAssertEqual(stack.count, 0)
    }

    func testPickAndRoll() throws {
        // Push 10, 20, 30, then PICK(2) should get 10
        var initial = ScriptStack()
        initial.pushInt(10)
        initial.pushInt(20)
        initial.pushInt(30)
        initial.pushInt(2)

        let pickScript = Script([Opcode.OP_PICK.rawValue])
        let stack = try run(pickScript, initialStack: initial)
        XCTAssertEqual(try ScriptNum.decode(stack.items[3]), 10)
        XCTAssertEqual(stack.count, 4) // PICK duplicates, doesn't remove
    }

    func testDisabledInNonExecutingBranch() {
        // Disabled opcodes fail even in non-executing IF branches
        let script = Script([
            Opcode.OP_0.rawValue,
            Opcode.OP_IF.rawValue,
            Opcode.OP_CAT.rawValue,
            Opcode.OP_ENDIF.rawValue,
        ])
        XCTAssertThrowsError(try run(script))
    }

    // MARK: - Edge Cases

    func testCheckMultiSigRejectsInvalidPubkey() throws {
        // Build a multisig script: OP_0 <sig> OP_1 <badpubkey> OP_1 OP_CHECKMULTISIG
        // The malformed key is 32 bytes (wrong length; must be 33) with valid prefix.
        let badPubkey = [UInt8](repeating: 0x02, count: 32)
        let emptySig: [UInt8] = []

        var stack = ScriptStack()
        stack.push([])           // null dummy (BIP 147)
        stack.push(emptySig)     // signature (empty -> won't check, but keys are validated first)
        stack.pushInt(1)         // nSigs
        stack.push(badPubkey)    // malformed pubkey
        stack.pushInt(1)         // nKeys

        let script = Script([Opcode.OP_CHECKMULTISIG.rawValue])
        XCTAssertThrowsError(try run(script, initialStack: stack)) { error in
            XCTAssertEqual(error as? ScriptError, ScriptError.invalidPublicKey)
        }
    }

    func testCheckMultiSigRejectsNoinput() throws {
        // Build a CHECKMULTISIG with a signature that has NOINPUT flag (0x40) set.
        // Valid compressed pubkey (33 bytes, prefix 0x02).
        let pubkey = [UInt8]([0x02] + [UInt8](repeating: 0xAA, count: 32))
        // 64-byte fake signature + sighash type byte with NOINPUT (0x40 | ALL=0x01 = 0x41)
        let sig = [UInt8](repeating: 0xBB, count: 64) + [0x41]

        var stack = ScriptStack()
        stack.push([])           // null dummy
        stack.push(sig)          // signature with NOINPUT
        stack.pushInt(1)         // nSigs
        stack.push(pubkey)       // valid pubkey
        stack.pushInt(1)         // nKeys

        let script = Script([Opcode.OP_CHECKMULTISIG.rawValue])
        XCTAssertThrowsError(try run(script, initialStack: stack)) { error in
            XCTAssertEqual(error as? ScriptError, ScriptError.invalidSigHashType)
        }
    }

    func testOpTypeThrowsOnMissingOutput() throws {
        // Create a transaction with 0 outputs, then execute OP_TYPE at index 0.
        let prevHash = try Hash256([UInt8](repeating: 0x11, count: 32))
        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [],
            witnesses: [.empty]
        )

        var stack = ScriptStack()
        let script = Script([Opcode.OP_TYPE.rawValue])

        XCTAssertThrowsError(
            try ScriptInterpreter.execute(
                script: script, stack: &stack,
                tx: tx, index: 0, value: 100_000, flags: .none
            )
        ) { error in
            XCTAssertEqual(error as? ScriptError, ScriptError.opTypeMissingOutput)
        }
    }

    func testScriptNumEncodeInt64Min() {
        // Int64.min is -9223372036854775808. Previously this could trap
        // on negation overflow. Verify encode returns valid bytes.
        let encoded = ScriptNum.encode(Int64.min)
        XCTAssertFalse(encoded.isEmpty, "Int64.min should not encode to empty (zero)")
        // The encoded value should be 9 bytes: 8 bytes for 2^63, plus a sign byte (0x80).
        XCTAssertEqual(encoded.count, 9)
        // The last byte must have the sign bit set.
        XCTAssertEqual(encoded.last! & 0x80, 0x80)
    }
}
