import Base
import ExtCrypto
import Protocol

/// Stack-based script execution engine for Handshake.
public enum ScriptInterpreter {

    /// Maximum script size in bytes.
    public static let maxScriptSize = 10_000

    /// Maximum number of non-push opcodes per script.
    public static let maxOps = 201

    /// Maximum number of items on the stack + altstack.
    public static let maxStackSize = 1000

    /// Maximum size of a data push.
    public static let maxPushSize = 520

    /// Maximum number of keys in a CHECKMULTISIG.
    public static let maxMultisigKeys = 20

    // MARK: - Public API

    /// Execute a script on the given stack with transaction context.
    public static func execute(
        script: Script,
        stack: inout ScriptStack,
        tx: Transaction,
        index: Int,
        value: UInt64,
        flags: ScriptFlags
    ) throws {
        var state = ExecState(
            stack: stack,
            tx: tx,
            index: index,
            value: value,
            flags: flags,
            script: script
        )
        try state.run()
        stack = state.stack
    }
}

// MARK: - Execution State

private struct ExecState {
    var stack: ScriptStack
    var altStack = ScriptStack()
    var condStack: [Bool] = []
    var opCount = 0
    let tx: Transaction
    let index: Int
    let value: UInt64
    let flags: ScriptFlags
    let script: Script
    var lastCodeSepOffset = 0

    var executing: Bool {
        condStack.allSatisfy { $0 }
    }

    mutating func run() throws {
        guard script.size <= ScriptInterpreter.maxScriptSize else {
            throw ScriptError.scriptTooLarge
        }

        let parsed = try parseWithOffsets()

        for (instruction, nextOffset) in parsed {
            switch instruction {
            case .pushData(let data):
                guard data.count <= ScriptInterpreter.maxPushSize else {
                    throw ScriptError.pushSizeExceeded
                }
                if executing {
                    stack.push(data)
                }

            case .opcode(let opcode):
                if opcode.isDisabled {
                    throw ScriptError.disabledOpcode(opcode)
                }

                // OP_VERIF/OP_VERNOTIF fail unconditionally, even in non-executing branches
                if opcode == .OP_VERIF || opcode == .OP_VERNOTIF {
                    throw ScriptError.reservedOpcode(opcode)
                }

                if opcode.rawValue > Opcode.OP_16.rawValue {
                    opCount += 1
                    guard opCount <= ScriptInterpreter.maxOps else {
                        throw ScriptError.opCountExceeded
                    }
                }

                switch opcode {
                case .OP_IF, .OP_NOTIF:
                    try handleIf(opcode)
                    continue
                case .OP_ELSE:
                    try handleElse()
                    continue
                case .OP_ENDIF:
                    try handleEndIf()
                    continue
                default:
                    break
                }

                guard executing else { continue }

                try executeOpcode(opcode, nextOffset: nextOffset)

            case .unknownOpcode(let byte):
                guard executing else { continue }
                throw ScriptError.badOpcode(byte)
            }

            guard stack.count + altStack.count <= ScriptInterpreter.maxStackSize else {
                throw ScriptError.stackOverflow
            }
        }

        guard condStack.isEmpty else {
            throw ScriptError.unbalancedConditional
        }
    }

    // MARK: - Parsing with byte offsets

    private func parseWithOffsets() throws -> [(Instruction, Int)] {
        var result: [(Instruction, Int)] = []
        var offset = 0
        let raw = script.raw

        while offset < raw.count {
            let byte = raw[offset]
            offset += 1

            if isDirectPush(byte) {
                let count = Int(byte)
                guard offset + count <= raw.count else {
                    throw ScriptError.invalidPushData
                }
                result.append((.pushData(Array(raw[offset..<(offset + count)])), offset + count))
                offset += count
            } else if let opcode = Opcode(rawValue: byte) {
                switch opcode {
                case .OP_PUSHDATA1:
                    guard offset < raw.count else { throw ScriptError.unexpectedEndOfScript }
                    let count = Int(raw[offset]); offset += 1
                    guard offset + count <= raw.count else { throw ScriptError.invalidPushData }
                    result.append((.pushData(Array(raw[offset..<(offset + count)])), offset + count))
                    offset += count
                case .OP_PUSHDATA2:
                    guard offset + 2 <= raw.count else { throw ScriptError.unexpectedEndOfScript }
                    let count = Int(raw[offset]) | (Int(raw[offset + 1]) << 8); offset += 2
                    guard offset + count <= raw.count else { throw ScriptError.invalidPushData }
                    result.append((.pushData(Array(raw[offset..<(offset + count)])), offset + count))
                    offset += count
                case .OP_PUSHDATA4:
                    guard offset + 4 <= raw.count else { throw ScriptError.unexpectedEndOfScript }
                    let count = Int(raw[offset]) | (Int(raw[offset + 1]) << 8)
                        | (Int(raw[offset + 2]) << 16) | (Int(raw[offset + 3]) << 24)
                    offset += 4
                    guard offset + count <= raw.count else { throw ScriptError.invalidPushData }
                    result.append((.pushData(Array(raw[offset..<(offset + count)])), offset + count))
                    offset += count
                default:
                    result.append((.opcode(opcode), offset))
                }
            } else {
                // Unknown opcode byte — parseable but fails on execution
                result.append((.unknownOpcode(byte), offset))
            }
        }
        return result
    }

    // MARK: - Flow Control

    private mutating func handleIf(_ opcode: Opcode) throws {
        if executing {
            if flags.contains(.verifyMinimalIf) {
                let top = try stack.peek()
                if top.count > 1 || (top.count == 1 && top[0] != 1) {
                    throw ScriptError.nonMinimalData
                }
            }
            let val = try stack.popBool()
            condStack.append(opcode == .OP_IF ? val : !val)
        } else {
            condStack.append(false)
        }
    }

    private mutating func handleElse() throws {
        guard !condStack.isEmpty else { throw ScriptError.unbalancedConditional }
        condStack[condStack.count - 1].toggle()
    }

    private mutating func handleEndIf() throws {
        guard !condStack.isEmpty else { throw ScriptError.unbalancedConditional }
        condStack.removeLast()
    }

    // MARK: - Opcode Dispatch

    private mutating func executeOpcode(_ opcode: Opcode, nextOffset: Int) throws {
        switch opcode {

        // -- Push value --
        case .OP_0:
            stack.push([])
        case .OP_1NEGATE:
            stack.pushInt(-1)
        case .OP_1, .OP_2, .OP_3, .OP_4, .OP_5, .OP_6, .OP_7, .OP_8,
             .OP_9, .OP_10, .OP_11, .OP_12, .OP_13, .OP_14, .OP_15, .OP_16:
            stack.pushInt(Int64(opcode.smallIntValue!))

        // -- Reserved (fail if executed) --
        case .OP_RESERVED, .OP_VER, .OP_RESERVED1, .OP_RESERVED2,
             .OP_VERIF, .OP_VERNOTIF:
            throw ScriptError.reservedOpcode(opcode)

        // -- Flow control --
        case .OP_NOP:
            break
        case .OP_VERIFY:
            guard try stack.popBool() else { throw ScriptError.verifyFailed }
        case .OP_RETURN:
            throw ScriptError.opReturnEncountered

        // -- Stack operations --
        case .OP_TOALTSTACK:
            altStack.push(try stack.pop())
        case .OP_FROMALTSTACK:
            guard !altStack.isEmpty else { throw ScriptError.stackUnderflow }
            stack.push(try altStack.pop())
        case .OP_2DROP:
            _ = try stack.pop(); _ = try stack.pop()
        case .OP_2DUP:
            let a = try stack.peek(1); let b = try stack.peek(0)
            stack.push(a); stack.push(b)
        case .OP_3DUP:
            let a = try stack.peek(2); let b = try stack.peek(1); let c = try stack.peek(0)
            stack.push(a); stack.push(b); stack.push(c)
        case .OP_2OVER:
            let a = try stack.peek(3); let b = try stack.peek(2)
            stack.push(a); stack.push(b)
        case .OP_2ROT:
            guard stack.count >= 6 else { throw ScriptError.stackUnderflow }
            let f = try stack.pop(); let e = try stack.pop()
            let d = try stack.pop(); let c = try stack.pop()
            let b = try stack.pop(); let a = try stack.pop()
            stack.push(c); stack.push(d); stack.push(e); stack.push(f)
            stack.push(a); stack.push(b)
        case .OP_2SWAP:
            guard stack.count >= 4 else { throw ScriptError.stackUnderflow }
            let d = try stack.pop(); let c = try stack.pop()
            let b = try stack.pop(); let a = try stack.pop()
            stack.push(c); stack.push(d); stack.push(a); stack.push(b)
        case .OP_IFDUP:
            let top = try stack.peek()
            if ScriptNum.castToBool(top) { stack.push(top) }
        case .OP_DEPTH:
            stack.pushInt(Int64(stack.count))
        case .OP_DROP:
            _ = try stack.pop()
        case .OP_DUP:
            try stack.dup()
        case .OP_NIP:
            _ = try stack.remove(at: 1)
        case .OP_OVER:
            stack.push(try stack.peek(1))
        case .OP_PICK:
            let n = try stack.popInt()
            guard n >= 0 else { throw ScriptError.stackUnderflow }
            stack.push(try stack.peek(Int(n)))
        case .OP_ROLL:
            let n = try stack.popInt()
            guard n >= 0 else { throw ScriptError.stackUnderflow }
            stack.push(try stack.remove(at: Int(n)))
        case .OP_ROT:
            let item = try stack.remove(at: 2)
            stack.push(item)
        case .OP_SWAP:
            try stack.swap()
        case .OP_TUCK:
            guard stack.count >= 2 else { throw ScriptError.stackUnderflow }
            let top = try stack.peek()
            stack.insert(top, at: 2)

        // -- Splice (only OP_SIZE enabled) --
        case .OP_SIZE:
            let top = try stack.peek()
            stack.pushInt(Int64(top.count))

        // -- Bitwise --
        case .OP_EQUAL:
            let b = try stack.pop(); let a = try stack.pop()
            stack.pushBool(a == b)
        case .OP_EQUALVERIFY:
            let b = try stack.pop(); let a = try stack.pop()
            guard a == b else { throw ScriptError.verifyFailed }

        // -- Arithmetic --
        case .OP_1ADD:       let a = try stack.popInt(); stack.pushInt(a + 1)
        case .OP_1SUB:       let a = try stack.popInt(); stack.pushInt(a - 1)
        case .OP_NEGATE:     let a = try stack.popInt(); stack.pushInt(-a)
        case .OP_ABS:        let a = try stack.popInt(); stack.pushInt(abs(a))
        case .OP_NOT:        let a = try stack.popInt(); stack.pushInt(a == 0 ? 1 : 0)
        case .OP_0NOTEQUAL:  let a = try stack.popInt(); stack.pushInt(a != 0 ? 1 : 0)
        case .OP_ADD:
            let b = try stack.popInt(); let a = try stack.popInt(); stack.pushInt(a + b)
        case .OP_SUB:
            let b = try stack.popInt(); let a = try stack.popInt(); stack.pushInt(a - b)
        case .OP_BOOLAND:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt((a != 0 && b != 0) ? 1 : 0)
        case .OP_BOOLOR:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt((a != 0 || b != 0) ? 1 : 0)
        case .OP_NUMEQUAL:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt(a == b ? 1 : 0)
        case .OP_NUMEQUALVERIFY:
            let b = try stack.popInt(); let a = try stack.popInt()
            guard a == b else { throw ScriptError.verifyFailed }
        case .OP_NUMNOTEQUAL:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt(a != b ? 1 : 0)
        case .OP_LESSTHAN:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt(a < b ? 1 : 0)
        case .OP_GREATERTHAN:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt(a > b ? 1 : 0)
        case .OP_LESSTHANOREQUAL:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt(a <= b ? 1 : 0)
        case .OP_GREATERTHANOREQUAL:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt(a >= b ? 1 : 0)
        case .OP_MIN:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt(min(a, b))
        case .OP_MAX:
            let b = try stack.popInt(); let a = try stack.popInt()
            stack.pushInt(max(a, b))
        case .OP_WITHIN:
            let upper = try stack.popInt(); let lower = try stack.popInt()
            let x = try stack.popInt()
            stack.pushInt((x >= lower && x < upper) ? 1 : 0)

        // -- Crypto --
        case .OP_RIPEMD160:
            stack.push(RIPEMD160.hash(try stack.pop()))
        case .OP_SHA1:
            stack.push(SHA1Hash.hash(try stack.pop()))
        case .OP_SHA256:
            stack.push(SHA256Hash.hash(try stack.pop()).bytes)
        case .OP_HASH160:
            // Bitcoin: RIPEMD160(SHA256(data))
            let h160data = SHA256Hash.hash(try stack.pop()).bytes
            stack.push(RIPEMD160.hash(h160data))
        case .OP_HASH256:
            // Bitcoin: SHA256(SHA256(data))
            let h256first = SHA256Hash.hash(try stack.pop()).bytes
            stack.push(SHA256Hash.hash(h256first).bytes)
        case .OP_BLAKE160:
            // Handshake: BLAKE2b-160
            stack.push(try Blake2bHash.hash(try stack.pop(), size: 20))
        case .OP_BLAKE256:
            // Handshake: BLAKE2b-256
            stack.push(try Blake2bHash.hash(try stack.pop(), size: 32))
        case .OP_SHA3:
            // Handshake: SHA3-256
            stack.push(SHA3Hash.sha3_256(try stack.pop()).bytes)
        case .OP_KECCAK:
            // Handshake: Keccak-256 (pre-FIPS)
            stack.push(SHA3Hash.keccak_256(try stack.pop()).bytes)
        case .OP_TYPE:
            // Handshake: push covenant type of output at current input index
            guard index < tx.outputs.count else {
                throw ScriptError.opTypeMissingOutput
            }
            stack.pushInt(Int64(tx.outputs[index].covenant.type.rawValue))
        case .OP_INVALIDOPCODE:
            throw ScriptError.badOpcode(0xff)
        case .OP_CODESEPARATOR:
            lastCodeSepOffset = nextOffset
        case .OP_CHECKSIG:
            try executeCheckSig(verify: false)
        case .OP_CHECKSIGVERIFY:
            try executeCheckSig(verify: true)
        case .OP_CHECKMULTISIG:
            try executeCheckMultiSig(verify: false)
        case .OP_CHECKMULTISIGVERIFY:
            try executeCheckMultiSig(verify: true)

        // -- Locktime --
        case .OP_CHECKLOCKTIMEVERIFY:
            try executeCheckLockTimeVerify()
        case .OP_CHECKSEQUENCEVERIFY:
            try executeCheckSequenceVerify()

        // -- Expansion NOPs --
        case .OP_NOP1, .OP_NOP4, .OP_NOP5, .OP_NOP6,
             .OP_NOP7, .OP_NOP8, .OP_NOP9, .OP_NOP10:
            if flags.contains(.verifyDiscourageUpgradableNops) {
                throw ScriptError.reservedOpcode(opcode)
            }

        // Data push opcodes handled by parser
        case .OP_PUSHDATA1, .OP_PUSHDATA2, .OP_PUSHDATA4:
            break

        // IF/ELSE/ENDIF handled above
        case .OP_IF, .OP_NOTIF, .OP_ELSE, .OP_ENDIF:
            break

        // Disabled opcodes caught earlier
        case .OP_CAT, .OP_SUBSTR, .OP_LEFT, .OP_RIGHT,
             .OP_INVERT, .OP_AND, .OP_OR, .OP_XOR,
             .OP_2MUL, .OP_2DIV, .OP_MUL, .OP_DIV, .OP_MOD,
             .OP_LSHIFT, .OP_RSHIFT:
            throw ScriptError.disabledOpcode(opcode)
        }
    }

    // MARK: - CHECKSIG

    private mutating func executeCheckSig(verify: Bool) throws {
        let pubkeyData = try stack.pop()
        let sigData = try stack.pop()

        var success = false

        if !sigData.isEmpty {
            guard let sigType = SigHash.extractType(from: sigData) else {
                throw ScriptError.invalidSigHashType
            }

            let rawSig = SigHash.stripType(from: sigData)

            if rawSig.count == 64 {
                let scriptCode = getScriptCode()

                let hash = try SigHash.compute(
                    tx: tx,
                    index: index,
                    prevScript: scriptCode,
                    value: value,
                    type: sigType
                )

                do {
                    success = try ECDSASigner.verify(
                        signature: rawSig,
                        hash: hash,
                        publicKey: PublicKey(pubkeyData)
                    )
                } catch {
                    success = false
                }
            }
        }

        if !success && flags.contains(.verifyNullFail) && !sigData.isEmpty {
            throw ScriptError.nullFailViolation
        }

        if verify {
            guard success else { throw ScriptError.verifyFailed }
        } else {
            stack.pushBool(success)
        }
    }

    // MARK: - CHECKMULTISIG

    private mutating func executeCheckMultiSig(verify: Bool) throws {
        let nKeys = try stack.popInt()
        guard nKeys >= 0 && nKeys <= Int64(ScriptInterpreter.maxMultisigKeys) else {
            throw ScriptError.invalidMultisigKeyCount
        }

        opCount += Int(nKeys)
        guard opCount <= ScriptInterpreter.maxOps else {
            throw ScriptError.opCountExceeded
        }

        var pubkeys: [[UInt8]] = []
        for _ in 0..<Int(nKeys) {
            pubkeys.append(try stack.pop())
        }

        let nSigs = try stack.popInt()
        guard nSigs >= 0 && nSigs <= nKeys else {
            throw ScriptError.invalidMultisigKeyCount
        }

        var sigs: [[UInt8]] = []
        for _ in 0..<Int(nSigs) {
            sigs.append(try stack.pop())
        }

        // Null dummy element (BIP 147)
        let dummy = try stack.pop()
        if !dummy.isEmpty {
            throw ScriptError.nullDummyNotEmpty
        }

        // Validate that all public keys are valid compressed pubkeys upfront.
        for pk in pubkeys {
            guard pk.count == 33 && (pk[0] == 0x02 || pk[0] == 0x03) else {
                throw ScriptError.invalidPublicKey
            }
        }

        let scriptCode = getScriptCode()
        var success = true
        var keyIdx = 0
        var sigIdx = 0

        while sigIdx < sigs.count && success {
            let sigData = sigs[sigIdx]
            if sigData.isEmpty { success = false; break }

            guard let sigType = SigHash.extractType(from: sigData) else {
                throw ScriptError.invalidSigHashType
            }

            // Reject NOINPUT in multisig — only allowed for CHECKSIG.
            if sigType.rawValue & 0x40 != 0 { // NOINPUT
                throw ScriptError.invalidSigHashType // reject NOINPUT in multisig
            }

            let rawSig = SigHash.stripType(from: sigData)

            var matched = false
            if rawSig.count == 64 {
                let hash = try SigHash.compute(
                    tx: tx, index: index,
                    prevScript: scriptCode,
                    value: value, type: sigType
                )

                while keyIdx < pubkeys.count {
                    let ok: Bool
                    do {
                        ok = try ECDSASigner.verify(
                            signature: rawSig, hash: hash,
                            publicKey: try PublicKey(pubkeys[keyIdx])
                        )
                    } catch {
                        ok = false
                    }
                    keyIdx += 1
                    if ok { matched = true; break }
                }
            }

            if !matched { success = false }
            sigIdx += 1
        }

        if !success && flags.contains(.verifyNullFail) {
            for sig in sigs where !sig.isEmpty {
                throw ScriptError.nullFailViolation
            }
        }

        if verify {
            guard success else { throw ScriptError.verifyFailed }
        } else {
            stack.pushBool(success)
        }
    }

    // MARK: - Locktime

    private func executeCheckLockTimeVerify() throws {
        let locktime = try stack.peekInt()
        guard locktime >= 0 else { throw ScriptError.negativeLocktime }

        let txLocktime = Int64(tx.locktime)
        let threshold: Int64 = 500_000_000

        if (locktime < threshold) != (txLocktime < threshold) {
            throw ScriptError.unsatisfiedLocktime
        }
        guard txLocktime >= locktime else { throw ScriptError.unsatisfiedLocktime }
        guard index < tx.inputs.count else { throw ScriptError.unsatisfiedLocktime }
        guard tx.inputs[index].sequence != 0xFFFFFFFF else {
            throw ScriptError.unsatisfiedLocktime
        }
    }

    private func executeCheckSequenceVerify() throws {
        let sequence = try stack.peekInt()
        guard sequence >= 0 else { throw ScriptError.negativeLocktime }

        let nSequence = UInt32(sequence)
        if nSequence & (1 << 31) != 0 { return }  // Disable flag set, NOP

        guard tx.version >= 2 else { throw ScriptError.unsatisfiedLocktime }

        guard index < tx.inputs.count else { throw ScriptError.unsatisfiedLocktime }
        let txSequence = tx.inputs[index].sequence
        guard txSequence & (1 << 31) == 0 else { throw ScriptError.unsatisfiedLocktime }

        let typeFlag: UInt32 = 1 << 22
        guard (nSequence & typeFlag) == (txSequence & typeFlag) else {
            throw ScriptError.unsatisfiedLocktime
        }

        let mask: UInt32 = 0x0000FFFF
        guard (txSequence & mask) >= (nSequence & mask) else {
            throw ScriptError.unsatisfiedLocktime
        }
    }

    // MARK: - Helpers

    private func getScriptCode() -> Script {
        if lastCodeSepOffset > 0 {
            return Script(Array(script.raw[lastCodeSepOffset...]))
        }
        return script
    }
}
