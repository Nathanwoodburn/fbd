import XCTest
@testable import Script
import Base
import ExtCrypto
import Protocol

/// Tests using exact data from mainnet block 132729, tx 1, input 0.
///
/// Validates that our sighash computation and ECDSA verification match
/// the reference hsd implementation. The scriptCode uses OP_BLAKE160 (0xc0),
/// Handshake's equivalent of Bitcoin's OP_HASH160 (0xa9).
final class MainnetVerifyTests: XCTestCase {

    // Exact data from mainnet block 132729, tx 1, input 0
    let rawSigHex = "2b5bbc71ca783234b7fa15e729897229a048701aaf3754164ed8326db754a6595fdc93f97358065052bc047a4157aee1ee21795f2e7e3f884494f223abfe3463"
    let pubkeyHex = "03d5f43339645e12c717c0658aa8433793f833df369f5da20c06f1cc0068ba63eb"

    // Correct preimage uses OP_BLAKE160 (0xc0) in scriptCode: 76 c0 14 <hash> 88 ac
    let preimageHex = "000000009806f76370d9c5e4510143bf68520660440767a90e9aa112df20d5a11c2f427be2d93df6a2e919e879551686bc301480fc50c54dc949b14b916d5834113bb061e3064ace03bca2a236cd5387dd7c5b7cf4f01efa216cd845d0e98b2d90ef9541000000001976c014fe0660fba4a8a1f2b35dd577e8fc74db7dfa5b8b88ac0000000000000000ffffffffd6eb6e70cf4c1c22bebd74837b95913113b504442efe71d32e4841ec27a195980000000001000000"

    // Correct sighash (verified against hsd)
    let expectedSighashHex = "b5ed26f3fb8315e5cdaf230e47efbabaaecbaa8c16c2620fad3ba7dcaf4e27bc"

    /// BLAKE2b hash of preimage matches expected sighash.
    func testBlake2bPreimage() throws {
        let preimage = try HexEncoding.decode(preimageHex)
        let sighash = try Blake2bHash.hash256(preimage)
        XCTAssertEqual(sighash.hex, expectedSighashHex)
    }

    /// ECDSA verification passes with the correct sighash.
    func testECDSAVerifyWithPreimage() throws {
        let preimage = try HexEncoding.decode(preimageHex)
        let sighash = try Blake2bHash.hash256(preimage)
        let rawSig = try HexEncoding.decode(rawSigHex)
        let pubkey = try HexEncoding.decode(pubkeyHex)
        let result = try ECDSASigner.verify(signature: rawSig, hash: sighash, publicKey: try PublicKey(pubkey))
        XCTAssertTrue(result, "ECDSA verify should pass with correct sighash")
    }

    /// BLAKE2b-160 of pubkey matches the address hash.
    func testPubkeyHashMatchesAddress() throws {
        let pubkey = try HexEncoding.decode(pubkeyHex)
        let expectedHash = try HexEncoding.decode("fe0660fba4a8a1f2b35dd577e8fc74db7dfa5b8b")
        let computedHash = try Blake2bHash.hash(pubkey, size: 20)
        XCTAssertEqual(computedHash, expectedHash)
    }

    /// ECDSA sign+verify round trip (proves our ECDSA implementation works).
    func testECDSARoundTrip() throws {
        let preimage = try HexEncoding.decode(preimageHex)
        let sighash = try Blake2bHash.hash256(preimage)
        let privkey = try ECDSASigner.generatePrivateKey()
        let pubkey = try ECDSASigner.publicKey(from: privkey)
        let sig = try ECDSASigner.sign(hash: sighash, privateKey: privkey)
        let ok = try ECDSASigner.verify(signature: sig, hash: sighash, publicKey: pubkey)
        XCTAssertTrue(ok)
    }

    /// SigHash.compute produces the correct sighash and ECDSA verification passes.
    func testSigHashComputeMatchesPreimage() throws {
        let prevHash0 = try Hash256(HexEncoding.decode("e3064ace03bca2a236cd5387dd7c5b7cf4f01efa216cd845d0e98b2d90ef9541"))
        let prevHash1 = try Hash256(HexEncoding.decode("9d67a6bef8bea94ad6b2a2f0a9215fe0312464fcd4fefcaa0fc9aa03bf336e94"))

        let input0 = Input(prevout: Outpoint(hash: prevHash0, index: 0), sequence: 0xffffffff)
        let input1 = Input(prevout: Outpoint(hash: prevHash1, index: 1), sequence: 0xffffffff)

        // Decode outputs from raw serialized bytes (avoids manual reconstruction errors)
        let outputsHex = "00000000000000000014c6d78fa046448cdffd0d2931cda03b56cd70bb0b" +
            "0a0720248c7345e02ca07e4f3ef228be239ae4d04571e93530de0bd32aa4b9b74c14ba" +
            "0457f50100056c796c616d01000400000000040000000020" +
            "0000000000000002f629929c11ee87fe51961ad751aa990daec3d28741dc9500" +
            "c56c782f0000000000149eeb7ab4dd96526e9271c7c564e573e20bc1e9aa0000"
        let outputsBytes = try HexEncoding.decode(outputsHex)
        var outReader = BufferReader(outputsBytes)
        let output0 = try Output.read(from: &outReader)
        let output1 = try Output.read(from: &outReader)

        let tx = Transaction(
            version: 0,
            inputs: [input0, input1],
            outputs: [output0, output1],
            locktime: 0,
            witnesses: [Witness(items: []), Witness(items: [])]
        )

        // P2PKH scriptCode with OP_BLAKE160
        let addressHash = try HexEncoding.decode("fe0660fba4a8a1f2b35dd577e8fc74db7dfa5b8b")
        let p2pkh = Script.p2pkh(addressHash)

        // Verify scriptCode uses OP_BLAKE160 (0xc0), not OP_HASH160 (0xa9)
        XCTAssertEqual(p2pkh.raw[1], 0xc0, "P2PKH script should use OP_BLAKE160")

        let sighash = try SigHash.compute(
            tx: tx, index: 0,
            prevScript: p2pkh, value: 0,
            type: .all
        )

        XCTAssertEqual(sighash.hex, expectedSighashHex)

        // ECDSA verification with computed sighash
        let rawSig = try HexEncoding.decode(rawSigHex)
        let pubkey = try HexEncoding.decode(pubkeyHex)
        let result = try ECDSASigner.verify(signature: rawSig, hash: sighash, publicKey: try PublicKey(pubkey))
        XCTAssertTrue(result, "ECDSA verify should pass with SigHash.compute result")
    }

    /// Verify individual sub-hashes (hashPrevouts, hashSequence).
    func testSubHashes() throws {
        let prevHash0 = try Hash256(HexEncoding.decode("e3064ace03bca2a236cd5387dd7c5b7cf4f01efa216cd845d0e98b2d90ef9541"))
        let prevHash1 = try Hash256(HexEncoding.decode("9d67a6bef8bea94ad6b2a2f0a9215fe0312464fcd4fefcaa0fc9aa03bf336e94"))

        var prevoutsWriter = BufferWriter()
        Outpoint(hash: prevHash0, index: 0).write(to: &prevoutsWriter)
        Outpoint(hash: prevHash1, index: 1).write(to: &prevoutsWriter)
        let hashPrevouts = try Blake2bHash.hash(prevoutsWriter.data, size: 32)
        XCTAssertEqual(
            HexEncoding.encode(hashPrevouts),
            "9806f76370d9c5e4510143bf68520660440767a90e9aa112df20d5a11c2f427b"
        )

        var seqWriter = BufferWriter()
        seqWriter.writeUInt32LE(0xffffffff)
        seqWriter.writeUInt32LE(0xffffffff)
        let hashSequence = try Blake2bHash.hash(seqWriter.data, size: 32)
        XCTAssertEqual(
            HexEncoding.encode(hashSequence),
            "e2d93df6a2e919e879551686bc301480fc50c54dc949b14b916d5834113bb061"
        )
    }
}
