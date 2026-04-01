import Base
import ExtCrypto
import Protocol

/// Witness program dispatcher for Fistbump transaction verification.
///
/// Handshake is all-witness: every output has an `Address` with a version (0–31)
/// and hash (2–40 bytes). This verifier routes to the correct verification logic
/// based on the witness program version and hash length.
///
/// | Version | Hash Length | Type    | Verification                              |
/// |---------|------------ |---------|-------------------------------------------|
/// | 0       | 20 bytes    | P2WPKH  | BLAKE2b-160(pubkey) == hash, run P2PKH    |
/// | 0       | 32 bytes    | P2WSH   | SHA3-256(witnessScript) == hash, run script|
/// | 0       | other       | Invalid | Always fails                              |
/// | 1–31    | any         | Future  | Pass (anyone-can-spend for softfork compat)|
public enum WitnessVerifier {

    /// Verify a single input's witness against its previous output's address.
    ///
    /// - Parameters:
    ///   - tx: The spending transaction.
    ///   - index: The input index being verified.
    ///   - address: The previous output's address (witness program).
    ///   - value: The previous output's value in bumps.
    ///   - flags: Script verification flags.
    /// - Throws: `ScriptError` if verification fails.
    public static func verify(
        tx: Transaction,
        index: Int,
        address: Address,
        value: UInt64,
        flags: ScriptFlags
    ) throws {
        let version = address.version
        let hash = address.hash

        if version == 0 {
            switch hash.count {
            case 20:
                try verifyP2WPKH(
                    tx: tx, index: index,
                    hash: hash, value: value, flags: flags
                )
            case 32:
                try verifyP2WSH(
                    tx: tx, index: index,
                    hash: hash, value: value, flags: flags
                )
            default:
                throw ScriptError.invalidWitnessProgram
            }
        } else {
            // Version 1–31: future witness programs (anyone-can-spend for softfork compat)
            if flags.contains(.verifyDiscourageUpgradableWitnessProgram) {
                throw ScriptError.discourageUpgradableWitnessProgram
            }
            // Pass — unknown version is valid for consensus
        }
    }

    // MARK: - P2WPKH

    /// Verify a P2WPKH (Pay-to-Witness-Public-Key-Hash) input.
    ///
    /// Witness must contain exactly [signature, pubkey].
    /// BLAKE2b-160(pubkey) must match the address hash.
    /// Runs a synthetic P2PKH script to verify the signature.
    private static func verifyP2WPKH(
        tx: Transaction,
        index: Int,
        hash: [UInt8],
        value: UInt64,
        flags: ScriptFlags
    ) throws {
        let witness = tx.witnesses[index]

        // P2WPKH requires exactly 2 witness items: [sig, pubkey]
        guard witness.items.count == 2 else {
            throw ScriptError.witnessMalleated
        }

        let sig = witness.items[0]
        let pubkey = witness.items[1]

        // Enforce witness item size limit (consensus rule)
        guard sig.count <= 520 && pubkey.count <= 520 else {
            throw ScriptError.pushSizeExceeded
        }

        // Verify pubkey hashes to the address hash
        let pubkeyHash = try Blake2bHash.hash(pubkey, size: 20)
        guard pubkeyHash == hash else {
            throw ScriptError.witnessProgramMismatch
        }

        // Build and execute the P2PKH script: OP_DUP OP_BLAKE160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        let script = Script.p2pkh(hash)
        var stack = ScriptStack([[UInt8]](arrayLiteral: sig, pubkey))

        try ScriptInterpreter.execute(
            script: script,
            stack: &stack,
            tx: tx,
            index: index,
            value: value,
            flags: flags
        )

        // Final stack must be exactly [true]
        guard stack.count == 1, ScriptNum.castToBool(try stack.peek(0)) else {
            throw ScriptError.evalFalse
        }
    }

    // MARK: - P2WSH

    /// Verify a P2WSH (Pay-to-Witness-Script-Hash) input.
    ///
    /// Last witness item is the witness script; preceding items are the stack.
    /// SHA3-256(witnessScript) must match the address hash.
    /// Runs the witness script with the provided stack items.
    private static func verifyP2WSH(
        tx: Transaction,
        index: Int,
        hash: [UInt8],
        value: UInt64,
        flags: ScriptFlags
    ) throws {
        let witness = tx.witnesses[index]

        // P2WSH requires at least one witness item (the script)
        guard !witness.items.isEmpty else {
            throw ScriptError.witnessEmpty
        }

        let witnessScript = witness.items.last!
        let stackItems = Array(witness.items.dropLast())

        // Enforce witness item size limit (consensus rule)
        for item in stackItems {
            guard item.count <= 520 else {
                throw ScriptError.pushSizeExceeded
            }
        }

        // Verify script hashes to the address hash
        let scriptHash = SHA3Hash.sha3_256(witnessScript)
        guard scriptHash.bytes == hash else {
            throw ScriptError.witnessProgramMismatch
        }

        // Witness script size limit
        guard witnessScript.count <= 10_000 else {
            throw ScriptError.scriptTooLarge
        }

        // Build script and execute with provided stack items
        let script = Script(witnessScript)
        var stack = ScriptStack(stackItems)

        try ScriptInterpreter.execute(
            script: script,
            stack: &stack,
            tx: tx,
            index: index,
            value: value,
            flags: flags
        )

        // Final stack must be exactly [true]
        guard stack.count == 1, ScriptNum.castToBool(try stack.peek(0)) else {
            throw ScriptError.evalFalse
        }
    }
}
