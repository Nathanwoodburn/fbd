import XCTest
@testable import ExtCrypto
import Base

final class SHA256Tests: XCTestCase {

    // MARK: - SHA-256 known vectors

    func testSHA256Empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = SHA256Hash.hash([])
        XCTAssertEqual(hash.hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testSHA256ABC() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = SHA256Hash.hash(Array("abc".utf8))
        XCTAssertEqual(hash.hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    // MARK: - Double SHA-256

    func testDoubleSHA256Empty() {
        // SHA256(SHA256("")) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        let hash = SHA256Hash.doubleHash([])
        XCTAssertEqual(hash.hex, "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
    }

    func testDoubleSHA256ABC() {
        // Double-SHA256 of "abc"
        // First: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        // Second: SHA256 of that = 4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358
        let hash = SHA256Hash.doubleHash(Array("abc".utf8))
        XCTAssertEqual(hash.hex, "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")
    }

    // MARK: - HMAC-SHA256

    func testHMACSHA256() {
        // RFC 4231 Test Case 2:
        // Key = "Jefe" (4 bytes)
        // Data = "what do ya want for nothing?" (28 bytes)
        // HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
        let key = Array("Jefe".utf8)
        let data = Array("what do ya want for nothing?".utf8)
        let mac = SHA256Hash.hmac(key: key, data: data)
        XCTAssertEqual(mac.hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    }
}
