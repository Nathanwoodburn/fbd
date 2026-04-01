/// Bitcoin CScriptNum-style number encoding for script execution.
///
/// Numbers are encoded as variable-length little-endian byte arrays where
/// the most significant bit of the last byte is the sign bit.
/// Zero is represented as an empty byte array.
public enum ScriptNum {
    /// Maximum number of bytes for a script number (default).
    public static let defaultMaxSize = 4

    /// Decode a script number from bytes.
    ///
    /// - Parameters:
    ///   - data: The encoded bytes (little-endian, sign bit in MSB of last byte).
    ///   - maxSize: Maximum allowed byte length (default 4).
    ///   - minimalEncoding: If true, enforce minimal encoding rules.
    /// - Returns: The decoded integer value.
    public static func decode(_ data: [UInt8], maxSize: Int = defaultMaxSize, minimalEncoding: Bool = true) throws -> Int64 {
        guard !data.isEmpty else { return 0 }

        guard data.count <= maxSize else {
            throw ScriptError.numberTooLarge
        }

        if minimalEncoding {
            // Check that the number is minimally encoded:
            // 1. If last byte is 0x00 or 0x80, the second-to-last byte must have high bit set
            let last = data[data.count - 1]
            if last & 0x7F == 0 {
                if data.count <= 1 || (data[data.count - 2] & 0x80) == 0 {
                    throw ScriptError.nonMinimalData
                }
            }
        }

        // Read as little-endian
        var result: Int64 = 0
        for i in 0..<data.count {
            result |= Int64(data[i]) << (8 * i)
        }

        // Check sign bit (MSB of last byte)
        if data[data.count - 1] & 0x80 != 0 {
            // Clear the sign bit and negate
            result &= ~(Int64(0x80) << (8 * (data.count - 1)))
            result = -result
        }

        return result
    }

    /// Encode an integer as script number bytes.
    ///
    /// - Parameter value: The integer value to encode.
    /// - Returns: The encoded bytes (empty for zero).
    public static func encode(_ value: Int64) -> [UInt8] {
        guard value != 0 else { return [] }

        let negative = value < 0
        var absVal: UInt64
        if value == Int64.min {
            absVal = UInt64(Int64.max) + 1  // 2^63
        } else {
            absVal = negative ? UInt64(-value) : UInt64(value)
        }

        var result: [UInt8] = []
        while absVal > 0 {
            result.append(UInt8(absVal & 0xFF))
            absVal >>= 8
        }

        // If the high bit is set, we need an extra byte for the sign
        if result[result.count - 1] & 0x80 != 0 {
            result.append(negative ? 0x80 : 0x00)
        } else if negative {
            result[result.count - 1] |= 0x80
        }

        return result
    }

    /// Cast a byte array to a boolean (script true/false).
    /// Any non-zero value is true, but negative zero (0x80) is false.
    public static func castToBool(_ data: [UInt8]) -> Bool {
        for i in 0..<data.count {
            if data[i] != 0 {
                // Negative zero: last byte is 0x80, all others 0x00
                if i == data.count - 1 && data[i] == 0x80 {
                    return false
                }
                return true
            }
        }
        return false
    }
}
