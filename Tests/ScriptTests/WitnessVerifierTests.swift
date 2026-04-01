import XCTest
@testable import Script
import Base
import ExtCrypto
import Protocol

final class WitnessVerifierTests: XCTestCase {

    // MARK: - Test Helpers

    /// Generate a key pair and return (privateKey, compressedPublicKey).
    private func generateKeyPair() throws -> ([UInt8], [UInt8]) {
        let privkey = try ECDSASigner.generatePrivateKey()
        let pubkey = try ECDSASigner.publicKey(from: privkey)
        return (privkey.bytes, pubkey.bytes)
    }

    /// Build a P2WPKH address from a compressed public key.
    private func makeP2WPKHAddress(pubkey: [UInt8]) throws -> Address {
        let hash = try Blake2bHash.hash(pubkey, size: 20)
        return try Address(version: 0, hash: hash)
    }

    /// Build a P2WSH address from a witness script.
    private func makeP2WSHAddress(script: Script) throws -> Address {
        let hash = SHA3Hash.sha3_256(script.raw)
        return try Address(version: 0, hash: hash.bytes)
    }

    /// Sign a sighash and return [compact_sig || sighash_type_byte].
    private func makeSignature(hash: Hash256, privkey: [UInt8]) throws -> [UInt8] {
        let rawSig = try ECDSASigner.sign(hash: hash, privateKey: PrivateKey(unchecked: privkey))
        return rawSig + [SigHashType.all.rawValue.asUInt8]
    }

    /// Build a P2WPKH transaction with one input spending the given address.
    private func makeP2WPKHTx(
        privkey: [UInt8],
        pubkey: [UInt8],
        address: Address,
        value: UInt64 = 50_000
    ) throws -> Transaction {
        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        // Build the unsigned tx first to compute sighash
        let unsignedTx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: value - 1000, address: outAddr)],
            witnesses: [Witness(items: [[0x00], [0x00]])]  // placeholder
        )

        // Compute sighash with P2PKH script (OP_DUP OP_BLAKE160 <hash> OP_EQUALVERIFY OP_CHECKSIG)
        let p2pkh = Script.p2pkh(address.hash)
        let sighash = try SigHash.compute(
            tx: unsignedTx, index: 0,
            prevScript: p2pkh, value: value,
            type: .all
        )

        let sig = try makeSignature(hash: sighash, privkey: privkey)

        // Rebuild with actual witness
        return Transaction(
            inputs: unsignedTx.inputs,
            outputs: unsignedTx.outputs,
            witnesses: [Witness(items: [sig, pubkey])]
        )
    }

    // MARK: - P2WPKH Tests

    func testP2WPKH_valid() throws {
        let (privkey, pubkey) = try generateKeyPair()
        let address = try makeP2WPKHAddress(pubkey: pubkey)
        let tx = try makeP2WPKHTx(privkey: privkey, pubkey: pubkey, address: address)

        XCTAssertNoThrow(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        ))
    }

    func testP2WPKH_wrongPubkey() throws {
        let (privkey, pubkey) = try generateKeyPair()
        let address = try makeP2WPKHAddress(pubkey: pubkey)

        // Use a different pubkey in the witness
        let (_, wrongPubkey) = try generateKeyPair()
        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let unsignedTx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [[0x00], [0x00]])]
        )

        let p2pkh = Script.p2pkh(address.hash)
        let sighash = try SigHash.compute(
            tx: unsignedTx, index: 0,
            prevScript: p2pkh, value: 50_000, type: .all
        )
        let sig = try makeSignature(hash: sighash, privkey: privkey)

        let tx = Transaction(
            inputs: unsignedTx.inputs,
            outputs: unsignedTx.outputs,
            witnesses: [Witness(items: [sig, wrongPubkey])]
        )

        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        )) { error in
            XCTAssertEqual(error as? ScriptError, .witnessProgramMismatch)
        }
    }

    func testP2WPKH_badSignature() throws {
        let (_, pubkey) = try generateKeyPair()
        let address = try makeP2WPKHAddress(pubkey: pubkey)

        // Use a random signature (wrong key)
        let (otherPrivkey, _) = try generateKeyPair()
        let tx = try makeP2WPKHTx(privkey: otherPrivkey, pubkey: pubkey, address: address)

        // Script execution should fail (NULLFAIL or verifyFailed)
        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        ))
    }

    func testP2WPKH_wrongWitnessCount_one() throws {
        let (_, pubkey) = try generateKeyPair()
        let address = try makeP2WPKHAddress(pubkey: pubkey)

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [pubkey])]  // only 1 item
        )

        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        )) { error in
            XCTAssertEqual(error as? ScriptError, .witnessMalleated)
        }
    }

    func testP2WPKH_wrongWitnessCount_three() throws {
        let (_, pubkey) = try generateKeyPair()
        let address = try makeP2WPKHAddress(pubkey: pubkey)

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [[0x01], [0x02], pubkey])]  // 3 items
        )

        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        )) { error in
            XCTAssertEqual(error as? ScriptError, .witnessMalleated)
        }
    }

    // MARK: - P2WSH Tests

    func testP2WSH_valid() throws {
        let (privkey, pubkey) = try generateKeyPair()

        // Build a P2PKH witness script (the script that will be run inside P2WSH)
        let pubkeyHash = try Blake2bHash.hash(pubkey, size: 20)
        let witnessScript = Script.p2pkh(pubkeyHash)
        let address = try makeP2WSHAddress(script: witnessScript)

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        // Build unsigned tx with placeholder witness
        let unsignedTx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [[0x00], [0x00], witnessScript.raw])]
        )

        // Compute sighash using the witness script as prevScript
        let sighash = try SigHash.compute(
            tx: unsignedTx, index: 0,
            prevScript: witnessScript, value: 50_000, type: .all
        )
        let sig = try makeSignature(hash: sighash, privkey: privkey)

        // Build final tx with [sig, pubkey, witnessScript]
        let tx = Transaction(
            inputs: unsignedTx.inputs,
            outputs: unsignedTx.outputs,
            witnesses: [Witness(items: [sig, pubkey, witnessScript.raw])]
        )

        XCTAssertNoThrow(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        ))
    }

    func testP2WSH_scriptHashMismatch() throws {
        let (_, pubkey) = try generateKeyPair()

        let pubkeyHash = try Blake2bHash.hash(pubkey, size: 20)
        let witnessScript = Script.p2pkh(pubkeyHash)

        // Use a different script to compute the address hash (mismatch)
        let wrongScript = Script([Opcode.OP_1.rawValue])
        let address = try makeP2WSHAddress(script: wrongScript)

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [[0x01], pubkey, witnessScript.raw])]
        )

        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        )) { error in
            XCTAssertEqual(error as? ScriptError, .witnessProgramMismatch)
        }
    }

    func testP2WSH_emptyWitness() throws {
        // P2WSH address (32-byte hash)
        let address = try Address(version: 0, hash: [UInt8](repeating: 0xCC, count: 32))

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [])]  // empty
        )

        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        )) { error in
            XCTAssertEqual(error as? ScriptError, .witnessEmpty)
        }
    }

    func testP2WSH_oversizeScript() throws {
        // Build an oversized witness script (> 10,000 bytes)
        let bigScript = [UInt8](repeating: Opcode.OP_NOP.rawValue, count: 10_001)
        let hash = SHA3Hash.sha3_256(bigScript)
        let address = try Address(version: 0, hash: hash.bytes)

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [bigScript])]
        )

        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        )) { error in
            XCTAssertEqual(error as? ScriptError, .scriptTooLarge)
        }
    }

    // MARK: - Unknown Version Tests

    func testUnknownVersion_passes() throws {
        // Version 1 with mandatory flags should pass (softfork compat)
        let address = try Address(version: 1, hash: [UInt8](repeating: 0xDD, count: 20))

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [[0x01]])]
        )

        XCTAssertNoThrow(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        ))
    }

    func testUnknownVersion_discouraged() throws {
        // Version 1 with standard flags should be rejected
        let address = try Address(version: 1, hash: [UInt8](repeating: 0xDD, count: 20))

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [[0x01]])]
        )

        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .standard
        )) { error in
            XCTAssertEqual(error as? ScriptError, .discourageUpgradableWitnessProgram)
        }
    }

    // MARK: - Invalid Hash Length

    func testVersion0_invalidHashLength() throws {
        // Version 0 with 16-byte hash (not 20 or 32) should fail
        let address = try Address(version: 0, hash: [UInt8](repeating: 0xEE, count: 16))

        let prevHash = try Hash256([UInt8](repeating: 0xAA, count: 32))
        let outAddr = try Address(version: 0, hash: [UInt8](repeating: 0xBB, count: 20))

        let tx = Transaction(
            inputs: [Input(prevout: Outpoint(hash: prevHash, index: 0))],
            outputs: [Output(value: 49_000, address: outAddr)],
            witnesses: [Witness(items: [[0x01]])]
        )

        XCTAssertThrowsError(try WitnessVerifier.verify(
            tx: tx, index: 0,
            address: address, value: 50_000,
            flags: .mandatory
        )) { error in
            XCTAssertEqual(error as? ScriptError, .invalidWitnessProgram)
        }
    }
}

// MARK: - Helpers

private extension UInt32 {
    var asUInt8: UInt8 { UInt8(self & 0xFF) }
}
