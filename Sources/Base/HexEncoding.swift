/// Hex string encoding and decoding utilities.
public enum HexEncoding {
    private static let hexChars: [UInt8] = Array("0123456789abcdef".utf8)

    /// Encode bytes to a lowercase hex string.
    public static func encode(_ bytes: some Sequence<UInt8>) -> String {
        var result: [UInt8] = []
        for byte in bytes {
            result.append(hexChars[Int(byte >> 4)])
            result.append(hexChars[Int(byte & 0x0F)])
        }
        return String(decoding: result, as: UTF8.self)
    }

    /// Decode a hex string to bytes.
    ///
    /// - Throws: `BaseError.invalidHexString` if the string is not valid hex.
    public static func decode(_ hex: String) throws -> [UInt8] {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else {
            throw BaseError.invalidHexString
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(chars.count / 2)

        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let high = hexValue(chars[i]),
                  let low = hexValue(chars[i + 1]) else {
                throw BaseError.invalidHexString
            }
            bytes.append((high << 4) | low)
        }
        return bytes
    }

    private static func hexValue(_ char: UInt8) -> UInt8? {
        switch char {
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            return char - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"):
            return char - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"):
            return char - UInt8(ascii: "A") + 10
        default:
            return nil
        }
    }
}
