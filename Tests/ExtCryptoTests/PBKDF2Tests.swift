import XCTest
@testable import ExtCrypto

final class PBKDF2Tests: XCTestCase {

    func testBIP39StandardDerivation() {
        // BIP39 uses PBKDF2-HMAC-SHA512 with rounds=2048, keyLength=64
        // Verify our implementation produces the expected seed for a known mnemonic
        let password = Array("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".utf8)
        let salt = Array("mnemonic".utf8) // BIP39: "mnemonic" + passphrase (empty here)

        let derived = PBKDF2.sha512(password: password, salt: salt, rounds: 2048, keyLength: 64)
        XCTAssertEqual(derived.count, 64)

        // Known BIP39 test vector for this mnemonic with empty passphrase
        // First 4 bytes of the expected seed
        let hex = derived.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex.prefix(8), "5eb00bbd")
    }

    func testOutputLength() {
        let derived = PBKDF2.sha512(
            password: Array("test".utf8),
            salt: Array("salt".utf8),
            rounds: 1,
            keyLength: 32
        )
        XCTAssertEqual(derived.count, 32)
    }

    func testDifferentPasswordsDifferentOutput() {
        let salt = Array("salt".utf8)
        let d1 = PBKDF2.sha512(password: Array("pass1".utf8), salt: salt, rounds: 1, keyLength: 64)
        let d2 = PBKDF2.sha512(password: Array("pass2".utf8), salt: salt, rounds: 1, keyLength: 64)
        XCTAssertNotEqual(d1, d2)
    }

    func testDifferentSaltsDifferentOutput() {
        let password = Array("password".utf8)
        let d1 = PBKDF2.sha512(password: password, salt: Array("salt1".utf8), rounds: 1, keyLength: 64)
        let d2 = PBKDF2.sha512(password: password, salt: Array("salt2".utf8), rounds: 1, keyLength: 64)
        XCTAssertNotEqual(d1, d2)
    }

    func testDeterministic() {
        let password = Array("password".utf8)
        let salt = Array("salt".utf8)
        let d1 = PBKDF2.sha512(password: password, salt: salt, rounds: 10, keyLength: 64)
        let d2 = PBKDF2.sha512(password: password, salt: salt, rounds: 10, keyLength: 64)
        XCTAssertEqual(d1, d2)
    }

    func testMoreRoundsChangesOutput() {
        let password = Array("password".utf8)
        let salt = Array("salt".utf8)
        let d1 = PBKDF2.sha512(password: password, salt: salt, rounds: 1, keyLength: 64)
        let d2 = PBKDF2.sha512(password: password, salt: salt, rounds: 2, keyLength: 64)
        XCTAssertNotEqual(d1, d2)
    }
}
