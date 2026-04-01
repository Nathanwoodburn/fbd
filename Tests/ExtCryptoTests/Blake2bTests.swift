import XCTest
@testable import ExtCrypto
import Base

final class Blake2bTests: XCTestCase {

    func testBlake2b256Empty() throws {
        let hash = try Blake2bHash.hash256([])
        XCTAssertEqual(hash.bytes.count, 32)
        // Known BLAKE2b-256 of empty input
        let expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        XCTAssertEqual(hash.hex, expected, "BLAKE2b-256 of empty input should match known test vector")
    }

    func testBlake2b256Abc() throws {
        // BLAKE2b-256("abc") = known test vector
        let hash = try Blake2bHash.hash256(Array("abc".utf8))
        let expected = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        XCTAssertEqual(hash.hex, expected, "BLAKE2b-256 of 'abc' should match known test vector")
    }

    func testBlake2b512Empty_RFC7693() throws {
        // RFC 7693 Appendix A: BLAKE2b-512 of empty string (unkeyed)
        let hash = try Blake2bHash.hash([], size: 64)
        let expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        let hex = hash.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex, expected, "BLAKE2b-512 of empty should match RFC 7693")
    }

    func testBlake2b256EmptyPrint() throws {
        // Debug: print the actual BLAKE2b-256 of empty input
        let hash = try Blake2bHash.hash256([])
        print("BLAKE2b-256('') = \(hash.hex)")
    }

    func testBlake2bCustomSize() throws {
        let hash = try Blake2bHash.hash(Array("test".utf8), size: 16)
        XCTAssertEqual(hash.count, 16)
    }

    func testBlake2b256Deterministic() throws {
        // Same input always produces same output
        let data = Array("hello world".utf8)
        let hash1 = try Blake2bHash.hash256(data)
        let hash2 = try Blake2bHash.hash256(data)
        XCTAssertEqual(hash1, hash2)
    }

    func testBlake2b256DifferentInputs() throws {
        let hash1 = try Blake2bHash.hash256(Array("hello".utf8))
        let hash2 = try Blake2bHash.hash256(Array("world".utf8))
        XCTAssertNotEqual(hash1, hash2)
    }

    func testBlake2bKeyed() throws {
        let data = Array("message".utf8)
        let key = Array("secret".utf8)
        let keyed = try Blake2bHash.hash(data, key: key, size: 32)
        let unkeyed = try Blake2bHash.hash(data, size: 32)
        // Keyed and unkeyed hashes should differ
        XCTAssertNotEqual(keyed, unkeyed)
    }
}
