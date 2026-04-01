import XCTest
@testable import ExtCrypto
import Base

final class RIPEMD160Tests: XCTestCase {

    func testEmptyString() {
        // RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        let hash = RIPEMD160.hash([])
        XCTAssertEqual(hash.count, 20)
        XCTAssertEqual(
            hash.map { String(format: "%02x", $0) }.joined(),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        )
    }

    func testABC() {
        // RIPEMD-160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
        let hash = RIPEMD160.hash(Array("abc".utf8))
        XCTAssertEqual(
            hash.map { String(format: "%02x", $0) }.joined(),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        )
    }

    func testMessageDigest() {
        // RIPEMD-160("message digest") = 5d0689ef49d2fae572b881b123a85ffa21595f36
        let hash = RIPEMD160.hash(Array("message digest".utf8))
        XCTAssertEqual(
            hash.map { String(format: "%02x", $0) }.joined(),
            "5d0689ef49d2fae572b881b123a85ffa21595f36"
        )
    }

    func testAlphabet() {
        // RIPEMD-160("abcdefghijklmnopqrstuvwxyz") = f71c27109c692c1b56bbdceb5b9d2865b3708dbc
        let hash = RIPEMD160.hash(Array("abcdefghijklmnopqrstuvwxyz".utf8))
        XCTAssertEqual(
            hash.map { String(format: "%02x", $0) }.joined(),
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
        )
    }

    func testHash160() {
        // HASH160(x) = RIPEMD160(SHA256(x))
        let data: [UInt8] = [0x01, 0x02, 0x03]
        let h160 = RIPEMD160.hash160(data)
        XCTAssertEqual(h160.bytes.count, 20)

        // Verify manually: SHA256 then RIPEMD160
        let sha = SHA256Hash.hash(data)
        let ripe = RIPEMD160.hash(sha.bytes)
        XCTAssertEqual(h160.bytes, ripe)
    }
}
