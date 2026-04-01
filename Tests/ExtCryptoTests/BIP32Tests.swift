import XCTest
@testable import ExtCrypto
import Base

final class BIP32Tests: XCTestCase {

    // MARK: - Master Key from Seed

    func testMasterKeyFromSeed() throws {
        // BIP32 test vector 1: seed = "000102030405060708090a0b0c0d0e0f"
        let seed = try HexEncoding.decode("000102030405060708090a0b0c0d0e0f")
        let master = ExtendedPrivateKey.fromSeed(seed)

        XCTAssertEqual(master.depth, 0)
        XCTAssertEqual(master.fingerprint, 0)
        XCTAssertEqual(master.index, 0)
        XCTAssertEqual(master.key.count, 32)
        XCTAssertEqual(master.chainCode.count, 32)

        // Known expected private key for this seed
        let keyHex = master.key.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(keyHex, "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")

        let chainHex = master.chainCode.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(chainHex, "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
    }

    func testMasterPublicKey() throws {
        let seed = try HexEncoding.decode("000102030405060708090a0b0c0d0e0f")
        let master = ExtendedPrivateKey.fromSeed(seed)
        let pubKey = try master.compressedPublicKey

        XCTAssertEqual(pubKey.bytes.count, 33, "Compressed public key should be 33 bytes")
        XCTAssertTrue(pubKey.bytes[0] == 0x02 || pubKey.bytes[0] == 0x03, "Should start with 02 or 03")

        let pubHex = pubKey.hex
        XCTAssertEqual(pubHex, "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
    }

    // MARK: - Child Key Derivation

    func testHardenedChildDerivation() throws {
        let seed = try HexEncoding.decode("000102030405060708090a0b0c0d0e0f")
        let master = ExtendedPrivateKey.fromSeed(seed)
        let child = try master.derive(0x8000_0000) // m/0'

        XCTAssertEqual(child.depth, 1)
        XCTAssertNotEqual(child.fingerprint, 0)
        XCTAssertEqual(child.index, 0x8000_0000)

        let keyHex = child.key.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(keyHex, "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
    }

    func testNormalChildDerivation() throws {
        let seed = try HexEncoding.decode("000102030405060708090a0b0c0d0e0f")
        let master = ExtendedPrivateKey.fromSeed(seed)
        let child0h = try master.derive(0x8000_0000) // m/0'
        let child1 = try child0h.derive(1)           // m/0'/1

        XCTAssertEqual(child1.depth, 2)
        XCTAssertEqual(child1.index, 1)

        let keyHex = child1.key.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(keyHex, "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
    }

    // MARK: - Path Derivation

    func testDerivePath() throws {
        let seed = try HexEncoding.decode("000102030405060708090a0b0c0d0e0f")
        let master = ExtendedPrivateKey.fromSeed(seed)

        // m/0'/1
        let child = try master.derivePath("m/0'/1")
        XCTAssertEqual(child.depth, 2)
        XCTAssertEqual(child.index, 1)

        let keyHex = child.key.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(keyHex, "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
    }

    func testBIP44FBDPath() throws {
        // Standard Fistbump BIP44 path: m/44'/14159'/0'/0/0
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let seed = BIP39.toSeed(mnemonic: mnemonic)
        let master = ExtendedPrivateKey.fromSeed(seed)
        let key = try master.derivePath("m/44'/14159'/0'/0/0")

        XCTAssertEqual(key.depth, 5)
        XCTAssertEqual(key.key.count, 32)

        // Verify we can derive a public key
        let pubKey = try key.compressedPublicKey
        XCTAssertEqual(pubKey.bytes.count, 33)
    }

    func testConsecutiveAddresses() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let seed = BIP39.toSeed(mnemonic: mnemonic)
        let master = ExtendedPrivateKey.fromSeed(seed)

        let key0 = try master.derivePath("m/44'/14159'/0'/0/0")
        let key1 = try master.derivePath("m/44'/14159'/0'/0/1")

        XCTAssertNotEqual(key0.key, key1.key, "Consecutive addresses should have different keys")
    }

    // MARK: - Public Key Derivation

    func testPublicKeyDerivation() throws {
        let seed = try HexEncoding.decode("000102030405060708090a0b0c0d0e0f")
        let master = ExtendedPrivateKey.fromSeed(seed)

        // Derive account key privately
        let accountKey = try master.derivePath("m/44'/14159'/0'")
        let accountPub = try accountKey.publicKey()

        // Derive child 0 from public key
        let childPub = try accountPub.derive(0)
        XCTAssertEqual(childPub.key.count, 33)
        XCTAssertEqual(childPub.depth, accountPub.depth + 1)

        // Should match the same child derived privately
        let childPriv = try accountKey.derive(0)
        let childPrivPub = try childPriv.compressedPublicKey
        XCTAssertEqual(childPub.key, childPrivPub.bytes,
                      "Public derivation should match private derivation for non-hardened")
    }

    func testPublicKeyHardenedFails() throws {
        let seed = try HexEncoding.decode("000102030405060708090a0b0c0d0e0f")
        let master = ExtendedPrivateKey.fromSeed(seed)
        let pub = try master.publicKey()

        XCTAssertThrowsError(try pub.derive(0x8000_0000)) { error in
            guard case BIP32Error.hardenedFromPublic = error else {
                XCTFail("Expected hardenedFromPublic error")
                return
            }
        }
    }

    // MARK: - Invalid Path

    func testInvalidPath() throws {
        let seed = try HexEncoding.decode("000102030405060708090a0b0c0d0e0f")
        let master = ExtendedPrivateKey.fromSeed(seed)

        XCTAssertThrowsError(try master.derivePath("m/abc")) { error in
            guard case BIP32Error.invalidPath = error else {
                XCTFail("Expected invalidPath error")
                return
            }
        }
    }
}
