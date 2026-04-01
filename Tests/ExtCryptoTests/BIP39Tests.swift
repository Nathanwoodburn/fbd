import XCTest
#if canImport(CommonCrypto)
import CommonCrypto
#endif
@testable import ExtCrypto
import Base

final class BIP39Tests: XCTestCase {

    // MARK: - Mnemonic Generation

    func testGenerateMnemonic24Words() {
        let mnemonic = BIP39.generateMnemonic(strength: 256)
        let words = mnemonic.split(separator: " ")
        XCTAssertEqual(words.count, 24, "24-word mnemonic expected for 256-bit entropy")
    }

    func testGenerateMnemonic12Words() {
        let mnemonic = BIP39.generateMnemonic(strength: 128)
        let words = mnemonic.split(separator: " ")
        XCTAssertEqual(words.count, 12, "12-word mnemonic expected for 128-bit entropy")
    }

    func testGeneratedMnemonicIsValid() {
        let mnemonic = BIP39.generateMnemonic()
        XCTAssertTrue(BIP39.validateMnemonic(mnemonic), "Generated mnemonic should be valid")
    }

    func testDeterministicFromEntropy() {
        // Known test vector from BIP39 spec
        // Entropy: all zeros (32 bytes)
        let entropy = [UInt8](repeating: 0, count: 32)
        let mnemonic = BIP39.mnemonicFromEntropy(entropy)
        XCTAssertEqual(
            mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "Known vector: all-zero entropy should produce known mnemonic"
        )
    }

    // MARK: - Validation

    func testValidMnemonic() {
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        XCTAssertTrue(BIP39.validateMnemonic(valid))
    }

    func testInvalidWordCount() {
        let invalid = "abandon abandon abandon"
        XCTAssertFalse(BIP39.validateMnemonic(invalid), "3-word mnemonic should be invalid")
    }

    func testInvalidWord() {
        let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz"
        XCTAssertFalse(BIP39.validateMnemonic(invalid), "Unknown word should fail")
    }

    func testBadChecksum() {
        // Valid words but wrong checksum
        let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        XCTAssertFalse(BIP39.validateMnemonic(invalid), "Bad checksum should fail")
    }

    // MARK: - Seed Derivation

    func testSeedDerivationKnownVector() {
        // BIP39 test vector #1 (all-zero 128-bit entropy)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let seed = BIP39.toSeed(mnemonic: mnemonic, passphrase: "TREZOR")
        XCTAssertEqual(seed.count, 64, "Seed should be 64 bytes")

        // Verify seed is consistent and deterministic
        let seed2 = BIP39.toSeed(mnemonic: mnemonic, passphrase: "TREZOR")
        XCTAssertEqual(seed, seed2, "Same inputs should produce same seed")

        // The first few bytes should match the known prefix
        let hex = seed.map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(hex.hasPrefix("c55257c360c07c72029aebc1b53c05ed"),
                      "Seed should start with known prefix")
    }

    func testSeedLength() {
        let mnemonic = BIP39.generateMnemonic()
        let seed = BIP39.toSeed(mnemonic: mnemonic)
        XCTAssertEqual(seed.count, 64, "Seed should be 64 bytes")
    }

    func testSeedDeterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let seed1 = BIP39.toSeed(mnemonic: mnemonic)
        let seed2 = BIP39.toSeed(mnemonic: mnemonic)
        XCTAssertEqual(seed1, seed2, "Same mnemonic should produce same seed")
    }

    func testSeedPassphraseDiffers() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let seed1 = BIP39.toSeed(mnemonic: mnemonic, passphrase: "")
        let seed2 = BIP39.toSeed(mnemonic: mnemonic, passphrase: "password")
        XCTAssertNotEqual(seed1, seed2, "Different passphrases should produce different seeds")
    }

    // MARK: - PBKDF2 Verification

    #if canImport(CommonCrypto)
    func testPBKDF2MatchesCommonCrypto() {
        // Verify our PBKDF2 implementation against CommonCrypto's reference
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let passphrase = "TREZOR"
        let password = Array(mnemonic.utf8)
        let salt = Array(("mnemonic" + passphrase).utf8)

        // Our implementation
        let ours = PBKDF2.sha512(password: password, salt: salt, rounds: 2048, keyLength: 64)

        // CommonCrypto reference
        var reference = [UInt8](repeating: 0, count: 64)
        CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            String(bytes: password, encoding: .utf8)!, password.count,
            salt, salt.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
            2048,
            &reference, 64
        )

        XCTAssertEqual(ours, reference, "PBKDF2 should match CommonCrypto reference")
    }
    #endif

    // MARK: - Wordlist

    func testWordlistSize() {
        XCTAssertEqual(BIP39.englishWordlist.count, 2048, "Wordlist should have 2048 words")
    }

    func testWordlistSorted() {
        let sorted = BIP39.englishWordlist.sorted()
        XCTAssertEqual(BIP39.englishWordlist, sorted, "BIP39 wordlist should be sorted alphabetically")
    }
}
