/// Minimal Base64 encoder/decoder — no Foundation dependency.
public enum Base64 {
    /// The standard Base64 alphabet (used for both encode and decode).
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

    private static let decodeTable: [UInt8] = {
        var table = [UInt8](repeating: 255, count: 256)
        for (i, c) in alphabet.enumerated() {
            table[Int(c)] = UInt8(i)
        }
        return table
    }()

    /// Encode bytes to a Base64 string.
    public static func encode(_ bytes: [UInt8]) -> String {
        guard !bytes.isEmpty else { return "" }
        var result = [UInt8]()
        result.reserveCapacity((bytes.count + 2) / 3 * 4)

        var i = 0
        while i < bytes.count {
            let b0 = bytes[i]
            let b1 = (i + 1 < bytes.count) ? bytes[i + 1] : 0
            let b2 = (i + 2 < bytes.count) ? bytes[i + 2] : 0

            result.append(alphabet[Int(b0 >> 2)])
            result.append(alphabet[Int((b0 & 0x03) << 4 | b1 >> 4)])

            if i + 1 < bytes.count {
                result.append(alphabet[Int((b1 & 0x0F) << 2 | b2 >> 6)])
            } else {
                result.append(UInt8(ascii: "="))
            }

            if i + 2 < bytes.count {
                result.append(alphabet[Int(b2 & 0x3F)])
            } else {
                result.append(UInt8(ascii: "="))
            }

            i += 3
        }

        return String(bytes: result, encoding: .utf8) ?? ""
    }

    /// Decode a Base64-encoded string to bytes. Returns nil on invalid input.
    public static func decode(_ string: String) -> [UInt8]? {
        let input = Array(string.utf8).filter { $0 != UInt8(ascii: "=") }
        guard !input.isEmpty else { return [] }

        var output = [UInt8]()
        output.reserveCapacity(input.count * 3 / 4)

        var i = 0
        while i < input.count {
            let remaining = input.count - i
            var sextet = [UInt8]()
            for j in 0..<min(4, remaining) {
                let val = decodeTable[Int(input[i + j])]
                guard val != 255 else { return nil }
                sextet.append(val)
            }

            if sextet.count >= 2 {
                output.append((sextet[0] << 2) | (sextet[1] >> 4))
            }
            if sextet.count >= 3 {
                output.append((sextet[1] << 4) | (sextet[2] >> 2))
            }
            if sextet.count >= 4 {
                output.append((sextet[2] << 6) | sextet[3])
            }

            i += 4
        }

        return output
    }

    /// Decode a Base64-encoded string to a UTF-8 string. Returns nil on invalid input.
    public static func decodeString(_ string: String) -> String? {
        guard let bytes = decode(string) else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }
}
