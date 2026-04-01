/// Errors that can occur during script parsing or execution.
public enum ScriptError: Error, Equatable, Sendable {
    // MARK: - Parse errors

    /// Unexpected end of script data.
    case unexpectedEndOfScript

    /// A data push exceeds the remaining script bytes.
    case invalidPushData

    // MARK: - Execution errors

    /// Script executed a disabled opcode.
    case disabledOpcode(Opcode)

    /// Script executed a reserved opcode (OP_RESERVED, OP_VER, etc.).
    case reservedOpcode(Opcode)

    /// Stack underflow (not enough items).
    case stackUnderflow

    /// Stack size exceeded the maximum of 1000.
    case stackOverflow

    /// Script size exceeded the maximum of 10,000 bytes.
    case scriptTooLarge

    /// Too many non-push opcodes (> 201).
    case opCountExceeded

    /// Push size exceeded maximum of 520 bytes.
    case pushSizeExceeded

    /// Numeric operand exceeds 4 bytes.
    case numberTooLarge

    /// OP_VERIFY / OP_EQUALVERIFY / etc. failed.
    case verifyFailed

    /// OP_RETURN encountered.
    case opReturnEncountered

    /// Unbalanced OP_IF / OP_ELSE / OP_ENDIF.
    case unbalancedConditional

    /// OP_CHECKMULTISIG n or m out of range.
    case invalidMultisigKeyCount

    /// Division or modulo by zero.
    case divisionByZero

    /// Negative lock time.
    case negativeLocktime

    /// Sequence comparison failed.
    case unsatisfiedLocktime

    /// Final stack top is not true.
    case evalFalse

    /// Clean stack rule violated (stack has more than one item).
    case cleanStackViolation

    /// Witness program hash mismatch.
    case witnessProgramMismatch

    /// Witness program has unexpected witness item count.
    case witnessMalleated

    /// Unknown witness program version.
    case unknownWitnessVersion(UInt8)

    /// Null dummy element for CHECKMULTISIG not empty.
    case nullDummyNotEmpty

    /// Signature must use low-S form.
    case nonLowSSignature

    /// Signature must use strict DER encoding.
    case nonStrictDERSignature

    /// NULLFAIL: non-empty signature must succeed.
    case nullFailViolation

    /// Minimal data encoding required.
    case nonMinimalData

    /// Invalid signature hash type.
    case invalidSigHashType

    /// Witness program version 0 with invalid hash length (not 20 or 32).
    case invalidWitnessProgram

    /// P2WSH witness has no items.
    case witnessEmpty

    /// Upgradable witness program rejected by policy.
    case discourageUpgradableWitnessProgram

    /// Public key is not a valid 33-byte compressed key.
    case invalidPublicKey

    /// OP_TYPE: no matching output at the current input index.
    case opTypeMissingOutput

    /// Unrecognized opcode encountered during execution.
    case badOpcode(UInt8)
}
