import XCTest
@testable import ExtCrypto
import Base

final class Secp256k1Tests: XCTestCase {

    // MARK: - Key Generation

    func testGeneratePrivateKey() throws {
        let key = try ECDSASigner.generatePrivateKey()
        XCTAssertEqual(key.bytes.count, 32)
    }

    func testDeriveCompressedPublicKey() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.publicKey(from: privKey)
        XCTAssertEqual(pubKey.bytes.count, 33)
        // Compressed keys start with 02 or 03
        XCTAssertTrue(pubKey.bytes[0] == 0x02 || pubKey.bytes[0] == 0x03)
    }

    func testDeriveUncompressedPublicKey() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.uncompressedPublicKey(from: privKey)
        XCTAssertEqual(pubKey.count, 65)
        // Uncompressed keys start with 04
        XCTAssertEqual(pubKey[0], 0x04)
    }

    func testPublicKeyDeterministic() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey1 = try ECDSASigner.publicKey(from: privKey)
        let pubKey2 = try ECDSASigner.publicKey(from: privKey)
        XCTAssertEqual(pubKey1, pubKey2)
    }

    func testInvalidPrivateKeyThrows() {
        // All zeros is not a valid private key
        let zeros = [UInt8](repeating: 0, count: 32)
        XCTAssertThrowsError(try ECDSASigner.publicKey(from: zeros))
    }

    // MARK: - ECDSA Sign / Verify

    func testSignAndVerifyCompact() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.publicKey(from: privKey)
        let message = try Hash256([UInt8](repeating: 0xAB, count: 32))

        let signature = try ECDSASigner.sign(hash: message, privateKey: privKey)
        XCTAssertEqual(signature.count, 64)

        let valid = try ECDSASigner.verify(signature: signature, hash: message, publicKey: pubKey)
        XCTAssertTrue(valid)
    }

    func testSignAndVerifyDER() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.publicKey(from: privKey)
        let message = try Hash256([UInt8](repeating: 0xCD, count: 32))

        let signature = try ECDSASigner.signDER(hash: message, privateKey: privKey)
        // DER signatures are typically 70-72 bytes
        XCTAssertTrue(signature.count >= 68 && signature.count <= 73)

        let valid = try ECDSASigner.verifyDER(signature: signature, hash: message, publicKey: pubKey)
        XCTAssertTrue(valid)
    }

    func testVerifyWrongMessageFails() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.publicKey(from: privKey)
        let message1 = try Hash256([UInt8](repeating: 0x01, count: 32))
        let message2 = try Hash256([UInt8](repeating: 0x02, count: 32))

        let signature = try ECDSASigner.sign(hash: message1, privateKey: privKey)
        let valid = try ECDSASigner.verify(signature: signature, hash: message2, publicKey: pubKey)
        XCTAssertFalse(valid)
    }

    func testVerifyWrongKeyFails() throws {
        let privKey1 = try ECDSASigner.generatePrivateKey()
        let privKey2 = try ECDSASigner.generatePrivateKey()
        let pubKey2 = try ECDSASigner.publicKey(from: privKey2)
        let message = try Hash256([UInt8](repeating: 0xEF, count: 32))

        let signature = try ECDSASigner.sign(hash: message, privateKey: privKey1)
        let valid = try ECDSASigner.verify(signature: signature, hash: message, publicKey: pubKey2)
        XCTAssertFalse(valid)
    }

    // MARK: - Recoverable Signatures

    func testSignRecoverableReturns65Bytes() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let message = try Hash256([UInt8](repeating: 0x42, count: 32))
        let sig = try ECDSASigner.signRecoverable(hash: message, privateKey: privKey)
        XCTAssertEqual(sig.count, 65, "Recoverable signature should be 65 bytes")
        // Recovery ID should be 0-3
        XCTAssertTrue(sig[0] <= 3, "Recovery ID byte should be 0-3")
    }

    func testRecoverPublicKeyMatchesOriginal() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.publicKey(from: privKey)
        let message = try Hash256([UInt8](repeating: 0xAA, count: 32))

        let sig = try ECDSASigner.signRecoverable(hash: message, privateKey: privKey)
        let recovered = ECDSASigner.recoverPublicKey(signature: sig, hash: message)

        XCTAssertNotNil(recovered)
        XCTAssertEqual(recovered, pubKey, "Recovered public key should match original")
    }

    func testRecoverPublicKeyMultipleMessages() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.publicKey(from: privKey)

        for i: UInt8 in 0..<10 {
            let msg = try Hash256([UInt8](repeating: i, count: 32))
            let sig = try ECDSASigner.signRecoverable(hash: msg, privateKey: privKey)
            let recovered = ECDSASigner.recoverPublicKey(signature: sig, hash: msg)
            XCTAssertEqual(recovered, pubKey, "Recovery should work for message \(i)")
        }
    }

    func testRecoverPublicKeyWrongHashFails() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.publicKey(from: privKey)
        let msg1 = try Hash256([UInt8](repeating: 0x01, count: 32))
        let msg2 = try Hash256([UInt8](repeating: 0x02, count: 32))

        let sig = try ECDSASigner.signRecoverable(hash: msg1, privateKey: privKey)
        let recovered = ECDSASigner.recoverPublicKey(signature: sig, hash: msg2)

        // Recovery succeeds but returns a different key
        XCTAssertNotNil(recovered)
        XCTAssertNotEqual(recovered, pubKey, "Wrong hash should recover a different key")
    }

    func testRecoverPublicKeyInvalidSignatureLength() {
        let hash = Hash256(unchecked: [UInt8](repeating: 0, count: 32))
        XCTAssertNil(ECDSASigner.recoverPublicKey(signature: [], hash: hash))
        XCTAssertNil(ECDSASigner.recoverPublicKey(signature: [UInt8](repeating: 0, count: 64), hash: hash))
        XCTAssertNil(ECDSASigner.recoverPublicKey(signature: [UInt8](repeating: 0, count: 66), hash: hash))
    }

    func testRecoverPublicKeyInvalidRecoveryID() {
        let hash = Hash256(unchecked: [UInt8](repeating: 0, count: 32))
        var sig = [UInt8](repeating: 0, count: 65)
        sig[0] = 4 // Invalid recovery ID (must be 0-3)
        XCTAssertNil(ECDSASigner.recoverPublicKey(signature: sig, hash: hash))
    }

    func testRecoverableSignatureDeterministic() throws {
        let privKey = try ECDSASigner.generatePrivateKey()
        let msg = try Hash256([UInt8](repeating: 0x77, count: 32))

        let sig1 = try ECDSASigner.signRecoverable(hash: msg, privateKey: privKey)
        let sig2 = try ECDSASigner.signRecoverable(hash: msg, privateKey: privKey)
        XCTAssertEqual(sig1, sig2, "Same key + message should produce same signature")
    }

    func testSignRecoverableMessageSigningRoundTrip() throws {
        // Simulate the signmessage/verifymessage flow
        let privKey = try ECDSASigner.generatePrivateKey()
        let pubKey = try ECDSASigner.publicKey(from: privKey)

        let prefix = "fistbump signed message:\n"
        let message = "Hello, Fistbump!"
        let msgBytes = Array((prefix + message).utf8)
        let hash = try Blake2bHash.hash256(msgBytes)

        let sig = try ECDSASigner.signRecoverable(hash: hash, privateKey: privKey)
        let recovered = ECDSASigner.recoverPublicKey(signature: sig, hash: hash)

        XCTAssertEqual(recovered, pubKey)

        // Verify the BLAKE2b-160 hash of the recovered key matches
        let pubHash = try Blake2bHash.hash(recovered!.bytes, size: 20)
        let expectedHash = try Blake2bHash.hash(pubKey.bytes, size: 20)
        XCTAssertEqual(pubHash, expectedHash)
    }

    // MARK: - ECDH

    func testECDHSharedSecret() throws {
        let privKeyA = try ECDSASigner.generatePrivateKey()
        let pubKeyA = try ECDSASigner.publicKey(from: privKeyA)

        let privKeyB = try ECDSASigner.generatePrivateKey()
        let pubKeyB = try ECDSASigner.publicKey(from: privKeyB)

        // A computes shared secret with B's public key
        let secretA = try ECDH.sharedSecret(privateKey: privKeyA, publicKey: pubKeyB)
        // B computes shared secret with A's public key
        let secretB = try ECDH.sharedSecret(privateKey: privKeyB, publicKey: pubKeyA)

        // Both should arrive at the same shared secret
        XCTAssertEqual(secretA, secretB)
        XCTAssertFalse(secretA.isEmpty)
    }

    func testECDHDifferentPairsDifferentSecrets() throws {
        let privKey1 = try ECDSASigner.generatePrivateKey()
        let privKey2 = try ECDSASigner.generatePrivateKey()
        let privKey3 = try ECDSASigner.generatePrivateKey()
        let pubKey2 = try ECDSASigner.publicKey(from: privKey2)
        let pubKey3 = try ECDSASigner.publicKey(from: privKey3)

        let secret12 = try ECDH.sharedSecret(privateKey: privKey1, publicKey: pubKey2)
        let secret13 = try ECDH.sharedSecret(privateKey: privKey1, publicKey: pubKey3)

        XCTAssertNotEqual(secret12, secret13)
    }
}
