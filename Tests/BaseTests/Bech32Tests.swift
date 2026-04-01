import XCTest
@testable import Base

final class Bech32Tests: XCTestCase {

    // MARK: - Encode / Decode Round-Trip

    func testRoundTrip() {
        let hrp = "fb"
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let encoded = Bech32.encode(hrp: hrp, data: data)

        let decoded = Bech32.decode(encoded)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.hrp, hrp)
        XCTAssertEqual(decoded?.data, data)
    }

    func testRoundTripTestnet() {
        let hrp = "ft"
        let data: [UInt8] = [0, 15, 31, 0, 10, 20]
        let encoded = Bech32.encode(hrp: hrp, data: data)

        let decoded = Bech32.decode(encoded)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.hrp, hrp)
        XCTAssertEqual(decoded?.data, data)
    }

    // MARK: - Invalid Decode

    func testDecodeNoSeparator() {
        XCTAssertNil(Bech32.decode("noseparatorhere"))
    }

    func testDecodeEmptyHRP() {
        XCTAssertNil(Bech32.decode("1qqqqqp3eahe"))
    }

    func testDecodeInvalidCharacter() {
        // 'b' is not in the Bech32 charset
        XCTAssertNil(Bech32.decode("fb1bqqqqqqqqq"))
    }

    func testDecodeTooShort() {
        // Less than 6 data characters (checksum)
        XCTAssertNil(Bech32.decode("fb1q"))
    }

    // MARK: - Bit Conversion

    func testConvertBits8to5() {
        // 0xFF = 11111111 → 5-bit groups: 11111 11100 (padded) = [31, 28]
        let data: [UInt8] = [0xFF]
        let result = Bech32.convertBits(from: 8, to: 5, data: data, pad: true)
        XCTAssertNotNil(result)
        XCTAssertEqual(result, [31, 28])
    }

    func testConvertBits5to8() {
        // [31, 28] = 11111 11100 → 8-bit: 11111111 (trailing 00 ignored) = [0xFF]
        let data5: [UInt8] = [31, 28]
        let result = Bech32.convertBits(from: 5, to: 8, data: data5, pad: false)
        XCTAssertNotNil(result)
        XCTAssertEqual(result, [0xFF])
    }

    func testConvertBitsRoundTrip() {
        let original: [UInt8] = [0x00, 0x14, 0x1A, 0xFF, 0xDE, 0xAD]
        let to5 = Bech32.convertBits(from: 8, to: 5, data: original, pad: true)
        XCTAssertNotNil(to5)
        let back = Bech32.convertBits(from: 5, to: 8, data: to5!, pad: false)
        XCTAssertNotNil(back)
        XCTAssertEqual(back, original)
    }

    // MARK: - FBD Address Encoding

    func testFBDAddressEncode() {
        // Encode a version 0 + 20-byte hash as a Bech32 FBD address
        let version: UInt8 = 0
        let hash = [UInt8](repeating: 0, count: 20)
        var data = [version]
        if let converted = Bech32.convertBits(from: 8, to: 5, data: hash, pad: true) {
            data.append(contentsOf: converted)
        }
        let address = Bech32.encode(hrp: "fb", data: data)
        XCTAssertTrue(address.hasPrefix("fb1"))

        // Decode it back
        let decoded = Bech32.decode(address)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.hrp, "fb")
        XCTAssertEqual(decoded?.data.first, 0) // version 0
    }

    func testFBDAddressDecodeRoundTrip() {
        let version: UInt8 = 0
        let hash: [UInt8] = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0xcd, 0xef, 0x01,
        ]

        // Encode
        var data = [version]
        data.append(contentsOf: Bech32.convertBits(from: 8, to: 5, data: hash, pad: true)!)
        let encoded = Bech32.encode(hrp: "fb", data: data)

        // Decode
        let decoded = Bech32.decode(encoded)!
        XCTAssertEqual(decoded.hrp, "fb")
        XCTAssertEqual(decoded.data[0], version)
        let recoveredHash = Bech32.convertBits(from: 5, to: 8, data: Array(decoded.data.dropFirst()), pad: false)!
        XCTAssertEqual(recoveredHash, hash)
    }

    // MARK: - Case Insensitivity

    func testCaseInsensitiveDecode() {
        let data: [UInt8] = [0, 1, 2, 3]
        let encoded = Bech32.encode(hrp: "fb", data: data)
        let upper = encoded.uppercased()

        let decoded = Bech32.decode(upper)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.data, data)
    }
}
