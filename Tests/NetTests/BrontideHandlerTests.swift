import XCTest
@testable import Net
import Base
import ExtCrypto
import Logging

final class BrontideHandlerTests: XCTestCase {

    /// Helper: perform a full Brontide handshake between two sides using BrontideHandshake directly.
    private func performHandshake() throws -> (initiator: BrontideHandshake, responder: BrontideHandshake) {
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiatorHS = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responderHS = try BrontideHandshake(
            initiator: false,
            localStatic: responderKey
        )

        // Act 1: initiator → responder
        let act1 = try initiatorHS.genActOne()
        XCTAssertEqual(act1.count, BrontideHandshake.actOneSize)
        try responderHS.recvActOne(act1)

        // Act 2: responder → initiator
        let act2 = try responderHS.genActTwo()
        XCTAssertEqual(act2.count, BrontideHandshake.actTwoSize)
        try initiatorHS.recvActTwo(act2)

        // Act 3: initiator → responder
        let act3 = try initiatorHS.genActThree()
        XCTAssertEqual(act3.count, BrontideHandshake.actThreeSize)
        try responderHS.recvActThree(act3)

        return (initiatorHS, responderHS)
    }

    // MARK: - Handshake

    func testHandshakeCompletes() throws {
        let (initiator, responder) = try performHandshake()
        XCTAssertFalse(initiator.remoteStatic.isEmpty)
        XCTAssertFalse(responder.remoteStatic.isEmpty)
    }

    func testPhaseTransitions() throws {
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(
            initiator: false,
            localStatic: responderKey
        )

        XCTAssertEqual(initiator.phase, .none)
        XCTAssertEqual(responder.phase, .none)

        let act1 = try initiator.genActOne()
        XCTAssertEqual(initiator.phase, .actOne)
        try responder.recvActOne(act1)
        XCTAssertEqual(responder.phase, .actOne)

        let act2 = try responder.genActTwo()
        XCTAssertEqual(responder.phase, .actTwo)
        try initiator.recvActTwo(act2)
        XCTAssertEqual(initiator.phase, .actTwo)

        let act3 = try initiator.genActThree()
        XCTAssertEqual(initiator.phase, .done)
        try responder.recvActThree(act3)
        XCTAssertEqual(responder.phase, .done)
    }

    // MARK: - Transport

    func testTransportRoundTrip() throws {
        var (initiator, responder) = try performHandshake()

        let message: [UInt8] = Array("Hello, Brontide!".utf8)
        let ciphertext = try initiator.write(message)
        XCTAssertGreaterThan(ciphertext.count, message.count)

        let headerSize = NetConstants.brontideHeaderSize
        let headerBytes = Array(ciphertext[0..<headerSize])
        let payloadLen = try responder.readHeader(headerBytes)

        let bodyBytes = Array(ciphertext[headerSize...])
        let decrypted = try responder.readBody(bodyBytes, length: payloadLen)
        XCTAssertEqual(decrypted, message)
    }

    func testBidirectionalTransport() throws {
        var (initiator, responder) = try performHandshake()

        let msg1: [UInt8] = [1, 2, 3, 4, 5]
        let enc1 = try initiator.write(msg1)
        let hdr1 = Array(enc1[0..<NetConstants.brontideHeaderSize])
        let len1 = try responder.readHeader(hdr1)
        let dec1 = try responder.readBody(Array(enc1[NetConstants.brontideHeaderSize...]), length: len1)
        XCTAssertEqual(dec1, msg1)

        let msg2: [UInt8] = [6, 7, 8, 9, 10]
        let enc2 = try responder.write(msg2)
        let hdr2 = Array(enc2[0..<NetConstants.brontideHeaderSize])
        let len2 = try initiator.readHeader(hdr2)
        let dec2 = try initiator.readBody(Array(enc2[NetConstants.brontideHeaderSize...]), length: len2)
        XCTAssertEqual(dec2, msg2)
    }

    func testMultipleMessages() throws {
        var (initiator, responder) = try performHandshake()

        for i in 0..<5 {
            let msg = [UInt8](repeating: UInt8(i), count: 50)
            let enc = try initiator.write(msg)
            let hdr = Array(enc[0..<NetConstants.brontideHeaderSize])
            let len = try responder.readHeader(hdr)
            let dec = try responder.readBody(Array(enc[NetConstants.brontideHeaderSize...]), length: len)
            XCTAssertEqual(dec, msg, "Message \(i) mismatch")
        }
    }

    func testEmptyPayloadRoundTrip() throws {
        var (initiator, responder) = try performHandshake()

        let msg: [UInt8] = []
        let enc = try initiator.write(msg)
        let hdr = Array(enc[0..<NetConstants.brontideHeaderSize])
        let len = try responder.readHeader(hdr)
        XCTAssertEqual(len, 0)
        let dec = try responder.readBody(Array(enc[NetConstants.brontideHeaderSize...]), length: len)
        XCTAssertEqual(dec, [])
    }

    func testLargePayloadRoundTrip() throws {
        var (initiator, responder) = try performHandshake()

        let msg = [UInt8](repeating: 0xAB, count: 65536)
        let enc = try initiator.write(msg)
        let hdr = Array(enc[0..<NetConstants.brontideHeaderSize])
        let len = try responder.readHeader(hdr)
        XCTAssertEqual(len, 65536)
        let dec = try responder.readBody(Array(enc[NetConstants.brontideHeaderSize...]), length: len)
        XCTAssertEqual(dec, msg)
    }

    func testSplitReadSimulation() throws {
        // Regression test: read header and body separately, verifying cipher state
        // is preserved across the two calls (the defer fix).
        var (initiator, responder) = try performHandshake()

        let msg: [UInt8] = Array("split-read test".utf8)
        let enc = try initiator.write(msg)

        // Read header first
        let headerData = Array(enc[0..<NetConstants.brontideHeaderSize])
        let payloadLen = try responder.readHeader(headerData)
        XCTAssertEqual(payloadLen, msg.count)

        // Read body separately (different call)
        let bodyData = Array(enc[NetConstants.brontideHeaderSize...])
        let decrypted = try responder.readBody(bodyData, length: payloadLen)
        XCTAssertEqual(decrypted, msg)
    }

    func testManyMessagesBothDirectionsInterleaved() throws {
        var (initiator, responder) = try performHandshake()

        for i in 0..<50 {
            // Initiator → Responder
            let msgA = [UInt8](repeating: UInt8(i & 0xFF), count: 20)
            let encA = try initiator.write(msgA)
            let lenA = try responder.readHeader(Array(encA[0..<NetConstants.brontideHeaderSize]))
            let decA = try responder.readBody(Array(encA[NetConstants.brontideHeaderSize...]), length: lenA)
            XCTAssertEqual(decA, msgA, "A→B message \(i) mismatch")

            // Responder → Initiator
            let msgB = [UInt8](repeating: UInt8((i + 128) & 0xFF), count: 20)
            let encB = try responder.write(msgB)
            let lenB = try initiator.readHeader(Array(encB[0..<NetConstants.brontideHeaderSize]))
            let decB = try initiator.readBody(Array(encB[NetConstants.brontideHeaderSize...]), length: lenB)
            XCTAssertEqual(decB, msgB, "B→A message \(i) mismatch")
        }
    }

    func testLargeMessageSplitHeaderBody() throws {
        // 64KB message: read header first, then body — verifies cipher state preserved
        var (initiator, responder) = try performHandshake()

        let msg = [UInt8](repeating: 0xCD, count: 65000)
        let enc = try initiator.write(msg)

        let header = Array(enc[0..<NetConstants.brontideHeaderSize])
        let len = try responder.readHeader(header)
        XCTAssertEqual(len, 65000)

        let body = Array(enc[NetConstants.brontideHeaderSize...])
        let dec = try responder.readBody(body, length: len)
        XCTAssertEqual(dec, msg)
    }

    // MARK: - Key Rotation Across Transport

    func testKeyRotationAcrossTransport() throws {
        var (initiator, responder) = try performHandshake()

        // Send 1001 messages — at message 1000, key rotation happens
        for i in 0..<1001 {
            let msg = [UInt8(i & 0xFF)]
            let enc = try initiator.write(msg)
            let len = try responder.readHeader(Array(enc[0..<NetConstants.brontideHeaderSize]))
            let dec = try responder.readBody(Array(enc[NetConstants.brontideHeaderSize...]), length: len)
            XCTAssertEqual(dec, msg, "Message \(i) failed after key rotation")
        }
    }

    func testKeyRotationSymmetry() throws {
        // Both directions rotate independently — after 1000+ messages each way, both still work
        var (initiator, responder) = try performHandshake()

        // Send 1005 messages initiator → responder
        for i in 0..<1005 {
            let msg = [UInt8(i & 0xFF)]
            let enc = try initiator.write(msg)
            let len = try responder.readHeader(Array(enc[0..<NetConstants.brontideHeaderSize]))
            let dec = try responder.readBody(Array(enc[NetConstants.brontideHeaderSize...]), length: len)
            XCTAssertEqual(dec, msg)
        }

        // Send 1005 messages responder → initiator
        for i in 0..<1005 {
            let msg = [UInt8(i & 0xFF)]
            let enc = try responder.write(msg)
            let len = try initiator.readHeader(Array(enc[0..<NetConstants.brontideHeaderSize]))
            let dec = try initiator.readBody(Array(enc[NetConstants.brontideHeaderSize...]), length: len)
            XCTAssertEqual(dec, msg)
        }
    }

    // MARK: - Handshake Error Cases

    func testBadActOneSize() throws {
        let responderKey = try ECDSASigner.generatePrivateKey()
        var responder = try BrontideHandshake(initiator: false, localStatic: responderKey)

        // Act 1 should be 49 bytes; pass wrong size
        let badData = [UInt8](repeating: 0, count: 30)
        XCTAssertThrowsError(try responder.recvActOne(badData))
    }

    func testBadActTwoSize() throws {
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(initiator: false, localStatic: responderKey)

        let act1 = try initiator.genActOne()
        try responder.recvActOne(act1)

        // Act 2 should be 49 bytes; pass wrong size
        XCTAssertThrowsError(try initiator.recvActTwo([UInt8](repeating: 0, count: 10)))
    }

    func testBadActThreeSize() throws {
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(initiator: false, localStatic: responderKey)

        let act1 = try initiator.genActOne()
        try responder.recvActOne(act1)
        let act2 = try responder.genActTwo()
        try initiator.recvActTwo(act2)

        // Act 3 should be 65 bytes; pass wrong size
        XCTAssertThrowsError(try responder.recvActThree([UInt8](repeating: 0, count: 20)))
    }

    func testTamperedActOneThrows() throws {
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(initiator: false, localStatic: responderKey)

        var act1 = try initiator.genActOne()
        // Tamper with tag bytes at end
        act1[act1.count - 1] ^= 0xFF
        XCTAssertThrowsError(try responder.recvActOne(act1))
    }

    func testTamperedActThreeThrows() throws {
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(initiator: false, localStatic: responderKey)

        let act1 = try initiator.genActOne()
        try responder.recvActOne(act1)
        let act2 = try responder.genActTwo()
        try initiator.recvActTwo(act2)

        var act3 = try initiator.genActThree()
        // Tamper with tag
        act3[act3.count - 1] ^= 0xFF
        XCTAssertThrowsError(try responder.recvActThree(act3))
    }

    // MARK: - Transport Error Cases

    func testReadHeaderBadTag() throws {
        var (initiator, responder) = try performHandshake()

        let msg: [UInt8] = [1, 2, 3]
        let enc = try initiator.write(msg)
        var header = Array(enc[0..<NetConstants.brontideHeaderSize])
        // Corrupt the header tag
        header[header.count - 1] ^= 0xFF
        XCTAssertThrowsError(try responder.readHeader(header))
    }

    func testReadBodyBadTag() throws {
        var (initiator, responder) = try performHandshake()

        let msg: [UInt8] = [1, 2, 3]
        let enc = try initiator.write(msg)
        let header = Array(enc[0..<NetConstants.brontideHeaderSize])
        let len = try responder.readHeader(header)

        var body = Array(enc[NetConstants.brontideHeaderSize...])
        // Corrupt the body tag
        body[body.count - 1] ^= 0xFF
        XCTAssertThrowsError(try responder.readBody(body, length: len))
    }

    func testSameMessageDifferentCiphertext() throws {
        var (initiator, _) = try performHandshake()

        let msg: [UInt8] = [1, 2, 3]
        let enc1 = try initiator.write(msg)
        let enc2 = try initiator.write(msg)
        // Same plaintext should produce different ciphertext due to nonce advance
        XCTAssertNotEqual(enc1, enc2)
    }
}

// MARK: - CipherState Tests

final class CipherStateExtendedTests: XCTestCase {

    func testEncryptDecryptRoundTrip() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x42, count: 32)
        sender.initKey(key)
        receiver.initKey(key)

        var plaintext: [UInt8] = Array("hello cipher".utf8)
        let original = plaintext
        let tag = try sender.encrypt(&plaintext)

        let ok = receiver.decrypt(&plaintext, tag: tag)
        XCTAssertTrue(ok)
        XCTAssertEqual(plaintext, original)
    }

    func testWrongTagFails() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x42, count: 32)
        sender.initKey(key)
        receiver.initKey(key)

        var plaintext: [UInt8] = [1, 2, 3]
        let tag = try sender.encrypt(&plaintext)

        var badTag = tag
        badTag[0] ^= 0xFF
        let ok = receiver.decrypt(&plaintext, tag: badTag)
        XCTAssertFalse(ok)
    }

    func testEmptyPlaintext() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x11, count: 32)
        sender.initKey(key)
        receiver.initKey(key)

        var plaintext: [UInt8] = []
        let tag = try sender.encrypt(&plaintext)

        let ok = receiver.decrypt(&plaintext, tag: tag)
        XCTAssertTrue(ok)
        XCTAssertEqual(plaintext, [])
    }

    func testLargePayload() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x55, count: 32)
        sender.initKey(key)
        receiver.initKey(key)

        var plaintext = [UInt8](repeating: 0xAB, count: 100_000)
        let original = plaintext
        let tag = try sender.encrypt(&plaintext)

        let ok = receiver.decrypt(&plaintext, tag: tag)
        XCTAssertTrue(ok)
        XCTAssertEqual(plaintext, original)
    }

    func testNonceAdvancesProducesDifferentCiphertext() throws {
        var cipher = CipherState()
        cipher.initKey([UInt8](repeating: 0x01, count: 32))

        var data1: [UInt8] = [1, 2, 3]
        let tag1 = try cipher.encrypt(&data1)

        var data2: [UInt8] = [1, 2, 3]
        let tag2 = try cipher.encrypt(&data2)

        // Same plaintext, different nonce → different ciphertext
        XCTAssertNotEqual(data1, data2)
        XCTAssertNotEqual(tag1, tag2)
    }

    func testKeyRotationAt1000() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x01, count: 32)
        let salt = [UInt8](repeating: 0x02, count: 32)
        sender.initSalt(key, salt)
        receiver.initSalt(key, salt)

        // Encrypt 1001 messages — rotation at message 1000
        for i in 0..<1001 {
            var data: [UInt8] = [UInt8(i & 0xFF)]
            let original = data
            let tag = try sender.encrypt(&data)

            let ok = receiver.decrypt(&data, tag: tag)
            XCTAssertTrue(ok, "Failed at message \(i)")
            XCTAssertEqual(data, original)
        }
    }

    func testADMismatchFails() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x42, count: 32)
        sender.initKey(key)
        receiver.initKey(key)

        let ad1: [UInt8] = [0xAA, 0xBB]
        let ad2: [UInt8] = [0xCC, 0xDD]

        var plaintext: [UInt8] = [1, 2, 3]
        let tag = try sender.encrypt(&plaintext, ad: ad1)

        // Decrypt with different AD
        let ok = receiver.decrypt(&plaintext, tag: tag, ad: ad2)
        XCTAssertFalse(ok)
    }

    func testInitSaltSetsBothFields() throws {
        var cipher = CipherState()
        let key = [UInt8](repeating: 0xAA, count: 32)
        let salt = [UInt8](repeating: 0xBB, count: 32)
        cipher.initSalt(key, salt)

        XCTAssertEqual(cipher.key, key)
        XCTAssertEqual(cipher.salt, salt)
        XCTAssertEqual(cipher.nonce, 0)
    }
}

// MARK: - HKDF256 Tests

final class HKDF256ExtendedTests: XCTestCase {

    func testDeterminism() {
        let secret: [UInt8] = [1, 2, 3, 4]
        let salt: [UInt8] = [5, 6, 7, 8]
        let (k1a, k2a) = HKDF256.expand(secret: secret, salt: salt)
        let (k1b, k2b) = HKDF256.expand(secret: secret, salt: salt)
        XCTAssertEqual(k1a, k1b)
        XCTAssertEqual(k2a, k2b)
    }

    func testDifferentSaltProducesDifferentKeys() {
        let secret: [UInt8] = [1, 2, 3, 4]
        let (k1a, k2a) = HKDF256.expand(secret: secret, salt: [0])
        let (k1b, k2b) = HKDF256.expand(secret: secret, salt: [1])
        XCTAssertNotEqual(k1a, k1b)
        XCTAssertNotEqual(k2a, k2b)
    }

    func testOutputLength() {
        let (k1, k2) = HKDF256.expand(secret: [1], salt: [2])
        XCTAssertEqual(k1.count, 32)
        XCTAssertEqual(k2.count, 32)
    }

    func testKeysAreDifferent() {
        let (k1, k2) = HKDF256.expand(secret: [1, 2, 3], salt: [4, 5, 6])
        XCTAssertNotEqual(k1, k2, "The two derived keys should differ")
    }
}

// MARK: - SymmetricState Tests

final class SymmetricStateExtendedTests: XCTestCase {

    func testInitProtocol() {
        var state = SymmetricState()
        state.initProtocol("TestProtocol")

        let nameBytes = Array("TestProtocol".utf8)
        let expectedDigest = Array(SHA256Hash.hash(nameBytes).bytes)
        XCTAssertEqual(state.digest, expectedDigest)
        XCTAssertEqual(state.chain, expectedDigest)
    }

    func testMixHash() {
        var state = SymmetricState()
        state.initProtocol("Test")
        let digestBefore = state.digest

        state.mixHash([1, 2, 3])
        XCTAssertNotEqual(state.digest, digestBefore)
        XCTAssertEqual(state.digest.count, 32)
    }

    func testMixKey() {
        var state = SymmetricState()
        state.initProtocol("Test")
        let chainBefore = state.chain

        state.mixKey([0xAA, 0xBB, 0xCC])
        XCTAssertNotEqual(state.chain, chainBefore)
        XCTAssertEqual(state.chain.count, 32)
    }

    func testEncryptHashDecryptHashRoundTrip() throws {
        // Two symmetric states initialized identically
        var sender = SymmetricState()
        var receiver = SymmetricState()
        sender.initProtocol("RoundTrip")
        receiver.initProtocol("RoundTrip")

        // Mix a shared key
        let sharedKey = [UInt8](repeating: 0x42, count: 32)
        sender.mixKey(sharedKey)
        receiver.mixKey(sharedKey)

        var plaintext: [UInt8] = Array("secret data".utf8)
        let original = plaintext
        let tag = try sender.encryptHash(&plaintext)

        let ok = receiver.decryptHash(&plaintext, tag: tag)
        XCTAssertTrue(ok)
        XCTAssertEqual(plaintext, original)
    }

    func testMixDigestDoesNotMutate() {
        var state = SymmetricState()
        state.initProtocol("Test")
        let digestBefore = state.digest

        let _ = state.mixDigest([1, 2, 3])
        XCTAssertEqual(state.digest, digestBefore, "mixDigest should not modify state")
    }
}
