import XCTest
@testable import ExtCrypto
import Base

final class SHA3Tests: XCTestCase {

    func testSHA3_256Empty() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let hash = SHA3Hash.sha3_256([])
        XCTAssertEqual(hash.hex, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    }

    func testSHA3_256ABC() {
        // SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
        let hash = SHA3Hash.sha3_256(Array("abc".utf8))
        XCTAssertEqual(hash.hex, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    }

    func testSHA3_256LongerInput() {
        // SHA3-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // Verified with Python hashlib.sha3_256
        let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let hash = SHA3Hash.sha3_256(Array(input.utf8))
        XCTAssertEqual(hash.hex, "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")
    }
}
