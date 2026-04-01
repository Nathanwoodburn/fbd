/// Bech32 encoding and decoding (BIP173).
public enum Bech32 {
    private static let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private static let charsetArray = Array(charset)
    private static let charsetMap: [Character: UInt8] = {
        var map = [Character: UInt8]()
        for (i, c) in charset.enumerated() {
            map[c] = UInt8(i)
        }
        return map
    }()

    /// Encode data with a human-readable part into a Bech32 string.
    ///
    /// - Parameters:
    ///   - hrp: The human-readable part (e.g., "hs").
    ///   - data: The 5-bit data values.
    /// - Returns: The Bech32-encoded string.
    public static func encode(hrp: String, data: [UInt8]) -> String {
        let checksum = createChecksum(hrp: hrp, data: data)
        var result = hrp + "1"
        for d in data + checksum {
            result.append(charsetArray[Int(d)])
        }
        return result
    }

    /// Decode a Bech32 string into HRP and 5-bit data.
    ///
    /// - Parameter string: The Bech32-encoded string.
    /// - Returns: The HRP and 5-bit data, or nil if invalid.
    public static func decode(_ string: String) -> (hrp: String, data: [UInt8])? {
        let lower = string.lowercased()
        guard let separatorIndex = lower.lastIndex(of: "1") else { return nil }
        let hrp = String(lower[lower.startIndex..<separatorIndex])
        guard !hrp.isEmpty else { return nil }

        let dataStart = lower.index(after: separatorIndex)
        guard dataStart < lower.endIndex else { return nil }
        let dataPartStr = String(lower[dataStart...])

        var values = [UInt8]()
        for c in dataPartStr {
            guard let v = charsetMap[c] else { return nil }
            values.append(v)
        }

        guard values.count >= 6 else { return nil }
        guard verifyChecksum(hrp: hrp, data: values) else { return nil }

        return (hrp, Array(values.dropLast(6)))
    }

    /// Convert between bit groups (e.g., 8-bit to 5-bit and back).
    ///
    /// - Parameters:
    ///   - from: Source bits per value.
    ///   - to: Target bits per value.
    ///   - data: Input data.
    ///   - pad: Whether to pad the final group with zeros.
    /// - Returns: The converted data, or nil if padding is disabled and there are non-zero leftover bits.
    public static func convertBits(from: Int, to: Int, data: [UInt8], pad: Bool) -> [UInt8]? {
        var acc = 0
        var bits = 0
        var result = [UInt8]()
        let maxv = (1 << to) - 1

        for value in data {
            let v = Int(value)
            if v < 0 || (v >> from) != 0 { return nil }
            acc = (acc << from) | v
            bits += from
            while bits >= to {
                bits -= to
                result.append(UInt8((acc >> bits) & maxv))
            }
        }

        if pad {
            if bits > 0 {
                result.append(UInt8((acc << (to - bits)) & maxv))
            }
        } else {
            if bits >= from { return nil }
            if (acc << (to - bits)) & maxv != 0 { return nil }
        }

        return result
    }

    // MARK: - Internal

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]
        var chk: UInt32 = 1
        for v in values {
            let b = chk >> 25
            chk = ((chk & 0x01ff_ffff) << 5) ^ UInt32(v)
            for i in 0..<5 {
                if (b >> i) & 1 != 0 {
                    chk ^= gen[i]
                }
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        var result = [UInt8]()
        for c in hrp.unicodeScalars {
            result.append(UInt8(c.value >> 5))
        }
        result.append(0)
        for c in hrp.unicodeScalars {
            result.append(UInt8(c.value & 31))
        }
        return result
    }

    private static func verifyChecksum(hrp: String, data: [UInt8]) -> Bool {
        polymod(hrpExpand(hrp) + data) == 1
    }

    private static func createChecksum(hrp: String, data: [UInt8]) -> [UInt8] {
        let values = hrpExpand(hrp) + data + [0, 0, 0, 0, 0, 0]
        let mod = polymod(values) ^ 1
        var result = [UInt8]()
        for i in 0..<6 {
            result.append(UInt8((mod >> (5 * (5 - i))) & 31))
        }
        return result
    }
}
