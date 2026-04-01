/// A 256-bit unsigned integer for PoW target and chainwork calculations.
///
/// Stored as four 64-bit words in little-endian order: `w0` is the lowest.
public struct Target256: Equatable, Sendable {
    public var w0: UInt64  // bits 0-63
    public var w1: UInt64  // bits 64-127
    public var w2: UInt64  // bits 128-191
    public var w3: UInt64  // bits 192-255

    public init(_ w3: UInt64, _ w2: UInt64, _ w1: UInt64, _ w0: UInt64) {
        self.w0 = w0; self.w1 = w1; self.w2 = w2; self.w3 = w3
    }

    public static let zero = Target256(0, 0, 0, 0)
    public static let one  = Target256(0, 0, 0, 1)

    /// The maximum 256-bit value (2^256 - 1).
    public static let max = Target256(.max, .max, .max, .max)

    /// Whether this value is zero.
    public var isZero: Bool { w0 == 0 && w1 == 0 && w2 == 0 && w3 == 0 }

    /// The number of significant bits.
    public var bitLength: Int {
        if w3 != 0 { return 192 + Self.bits(w3) }
        if w2 != 0 { return 128 + Self.bits(w2) }
        if w1 != 0 { return 64 + Self.bits(w1) }
        return Self.bits(w0)
    }

    private static func bits(_ v: UInt64) -> Int {
        v == 0 ? 0 : 64 - v.leadingZeroBitCount
    }

    // MARK: - Byte conversion

    /// Create from 32 big-endian bytes.
    public init(bigEndian bytes: [UInt8]) {
        precondition(bytes.count == 32)
        var w3: UInt64 = 0; var w2: UInt64 = 0
        var w1: UInt64 = 0; var w0: UInt64 = 0
        for i in 0..<8 { w3 = (w3 << 8) | UInt64(bytes[i]) }
        for i in 8..<16 { w2 = (w2 << 8) | UInt64(bytes[i]) }
        for i in 16..<24 { w1 = (w1 << 8) | UInt64(bytes[i]) }
        for i in 24..<32 { w0 = (w0 << 8) | UInt64(bytes[i]) }
        self.w0 = w0; self.w1 = w1; self.w2 = w2; self.w3 = w3
    }

    /// Convert to 32 big-endian bytes.
    public func bigEndianBytes() -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        for i in 0..<8 { result[i] = UInt8((w3 >> (56 - i * 8)) & 0xFF) }
        for i in 0..<8 { result[8 + i] = UInt8((w2 >> (56 - i * 8)) & 0xFF) }
        for i in 0..<8 { result[16 + i] = UInt8((w1 >> (56 - i * 8)) & 0xFF) }
        for i in 0..<8 { result[24 + i] = UInt8((w0 >> (56 - i * 8)) & 0xFF) }
        return result
    }

    // MARK: - Compact target (nBits)

    /// Decode a compact target (Bitcoin-style nBits).
    ///
    /// Format: `[exponent:8][mantissa:24]`
    /// Target = mantissa * 256^(exponent - 3)
    /// If the high bit of mantissa is set, the value is negative.
    public static func fromCompact(_ bits: UInt32) -> Target256 {
        let exp = Int(bits >> 24)
        let mantissaMask: UInt32 = 0x7FFFFF      // low 23 bits
        let negativeFlag: UInt32 = 0x800000       // bit 23 (sign bit of mantissa)
        let mantissa = bits & mantissaMask
        let negative = (bits & negativeFlag) != 0

        if negative { return .zero } // Negative targets are invalid

        var target = Target256.zero
        if exp <= 3 {
            let shift = (3 - exp) * 8
            let val = UInt64(mantissa) >> shift
            target.w0 = val
        } else {
            let byteOffset = exp - 3
            let wordIdx = byteOffset / 8
            let bitShift = (byteOffset % 8) * 8

            let val = UInt64(mantissa)
            let lo = val << bitShift
            let hi = bitShift > 0 ? val >> (64 - bitShift) : 0

            switch wordIdx {
            case 0: target.w0 = lo; target.w1 = hi
            case 1: target.w1 = lo; target.w2 = hi
            case 2: target.w2 = lo; target.w3 = hi
            case 3: target.w3 = lo // hi would overflow, but valid targets are <= 256 bits
            default: break // exponent too large
            }
        }
        return target
    }

    /// Encode as a compact target (nBits).
    public func toCompact() -> UInt32 {
        let bl = bitLength
        if bl == 0 { return 0 }

        let byteLen = (bl + 7) / 8 // number of significant bytes

        // Extract top 3 bytes of the number
        var mantissa: UInt32
        if byteLen <= 3 {
            let shift = (3 - byteLen) * 8
            mantissa = UInt32(w0 << shift)
        } else {
            // Shift right by (byteLen - 3) bytes
            let bytes = bigEndianBytes()
            let startIdx = 32 - byteLen
            mantissa = UInt32(bytes[startIdx]) << 16
                | UInt32(bytes[startIdx + 1]) << 8
                | UInt32(bytes[startIdx + 2])
        }

        // If high bit of mantissa is set, shift right to avoid "negative" encoding
        var exp = UInt32(byteLen)
        if mantissa & 0x800000 != 0 {
            mantissa >>= 8
            exp += 1
        }

        return (exp << 24) | (mantissa & 0x7FFFFF)
    }

    // MARK: - Comparison

    public static func < (lhs: Target256, rhs: Target256) -> Bool {
        if lhs.w3 != rhs.w3 { return lhs.w3 < rhs.w3 }
        if lhs.w2 != rhs.w2 { return lhs.w2 < rhs.w2 }
        if lhs.w1 != rhs.w1 { return lhs.w1 < rhs.w1 }
        return lhs.w0 < rhs.w0
    }

    public static func <= (lhs: Target256, rhs: Target256) -> Bool {
        lhs == rhs || lhs < rhs
    }

    public static func > (lhs: Target256, rhs: Target256) -> Bool {
        rhs < lhs
    }

    public static func >= (lhs: Target256, rhs: Target256) -> Bool {
        rhs <= lhs
    }

    // MARK: - Arithmetic

    /// Add two 256-bit values (overflow wraps).
    public static func + (lhs: Target256, rhs: Target256) -> Target256 {
        var r = Target256.zero
        var carry: UInt64 = 0

        let (s0, c0) = lhs.w0.addingReportingOverflow(rhs.w0)
        let (s0c, c0c) = s0.addingReportingOverflow(carry)
        r.w0 = s0c; carry = (c0 ? 1 : 0) + (c0c ? 1 : 0)

        let (s1, c1) = lhs.w1.addingReportingOverflow(rhs.w1)
        let (s1c, c1c) = s1.addingReportingOverflow(carry)
        r.w1 = s1c; carry = (c1 ? 1 : 0) + (c1c ? 1 : 0)

        let (s2, c2) = lhs.w2.addingReportingOverflow(rhs.w2)
        let (s2c, c2c) = s2.addingReportingOverflow(carry)
        r.w2 = s2c; carry = (c2 ? 1 : 0) + (c2c ? 1 : 0)

        let (s3, _) = lhs.w3.addingReportingOverflow(rhs.w3)
        let (s3c, _) = s3.addingReportingOverflow(carry)
        r.w3 = s3c

        return r
    }

    /// Subtract (wrapping).
    public static func - (lhs: Target256, rhs: Target256) -> Target256 {
        var r = Target256.zero
        var borrow: UInt64 = 0

        let (s0, b0) = lhs.w0.subtractingReportingOverflow(rhs.w0)
        let (s0b, b0b) = s0.subtractingReportingOverflow(borrow)
        r.w0 = s0b; borrow = (b0 ? 1 : 0) + (b0b ? 1 : 0)

        let (s1, b1) = lhs.w1.subtractingReportingOverflow(rhs.w1)
        let (s1b, b1b) = s1.subtractingReportingOverflow(borrow)
        r.w1 = s1b; borrow = (b1 ? 1 : 0) + (b1b ? 1 : 0)

        let (s2, b2) = lhs.w2.subtractingReportingOverflow(rhs.w2)
        let (s2b, b2b) = s2.subtractingReportingOverflow(borrow)
        r.w2 = s2b; borrow = (b2 ? 1 : 0) + (b2b ? 1 : 0)

        let (s3, _) = lhs.w3.subtractingReportingOverflow(rhs.w3)
        let (s3b, _) = s3.subtractingReportingOverflow(borrow)
        r.w3 = s3b

        return r
    }

    /// Multiply by a 64-bit scalar (overflow wraps to 256 bits).
    public func multiplied(by scalar: UInt64) -> Target256 {
        var r = Target256.zero
        var carry: UInt64 = 0

        let p0 = w0.multipliedFullWidth(by: scalar)
        let (r0, c0) = p0.low.addingReportingOverflow(carry)
        r.w0 = r0; carry = p0.high &+ (c0 ? 1 : 0)

        let p1 = w1.multipliedFullWidth(by: scalar)
        let (r1, c1) = p1.low.addingReportingOverflow(carry)
        r.w1 = r1; carry = p1.high &+ (c1 ? 1 : 0)

        let p2 = w2.multipliedFullWidth(by: scalar)
        let (r2, c2) = p2.low.addingReportingOverflow(carry)
        r.w2 = r2; carry = p2.high &+ (c2 ? 1 : 0)

        let p3 = w3.multipliedFullWidth(by: scalar)
        r.w3 = p3.low &+ carry

        return r
    }

    /// Divide by a 64-bit scalar. Returns (quotient, remainder).
    public func dividedBy(_ scalar: UInt64) -> (quotient: Target256, remainder: UInt64) {
        precondition(scalar != 0, "division by zero")
        var q = Target256.zero
        var rem: UInt64 = 0

        // Process from high word to low
        let (q3, r3) = div128(rem, w3, scalar)
        q.w3 = q3; rem = r3
        let (q2, r2) = div128(rem, w2, scalar)
        q.w2 = q2; rem = r2
        let (q1, r1) = div128(rem, w1, scalar)
        q.w1 = q1; rem = r1
        let (q0, r0) = div128(rem, w0, scalar)
        q.w0 = q0; rem = r0

        return (q, rem)
    }

    /// Divide (hi:lo) / divisor, returning (quotient, remainder).
    /// Implements 128-bit by 64-bit division without UInt128.
    private func div128(_ hi: UInt64, _ lo: UInt64, _ divisor: UInt64) -> (UInt64, UInt64) {
        if hi == 0 {
            return (lo / divisor, lo % divisor)
        }
        // Long division: process bit by bit from MSB to LSB
        var remainder: UInt64 = 0
        var quotient: UInt64 = 0

        // Process high word bits (63 downto 0)
        for i in stride(from: 63, through: 0, by: -1) {
            remainder = (remainder << 1) | ((hi >> i) & 1)
            if remainder >= divisor {
                remainder -= divisor
                // This bit position in quotient is bit (64 + i), but since
                // we know hi < divisor (invariant from caller), the quotient
                // for high bits fits in the high portion. However the final
                // quotient is 64-bit, so we track it across both words.
            }
        }
        // remainder now holds the remainder after dividing hi by divisor,
        // effectively: remainder = hi % divisor, and we've consumed high word.
        // Now process low word with the carry from high word.
        // Restart: we have (remainder * 2^64 + lo) / divisor
        // Process all 64 bits of lo
        for i in stride(from: 63, through: 0, by: -1) {
            let newRem = (remainder << 1) | ((lo >> i) & 1)
            if newRem >= divisor {
                remainder = newRem - divisor
                quotient |= (1 << i)
            } else {
                remainder = newRem
            }
        }
        return (quotient, remainder)
    }

    /// Full 256-bit division. Returns (quotient, remainder).
    public func divmod(_ divisor: Target256) -> (quotient: Target256, remainder: Target256) {
        precondition(!divisor.isZero, "division by zero")

        if self < divisor { return (.zero, self) }
        if self == divisor { return (.one, .zero) }

        var quotient = Target256.zero
        var remainder = Target256.zero

        // Bit-by-bit long division
        for i in stride(from: bitLength - 1, through: 0, by: -1) {
            remainder = remainder.shiftedLeft(by: 1)
            if bit(i) {
                remainder.w0 |= 1
            }
            if remainder >= divisor {
                remainder = remainder - divisor
                quotient.setBit(i)
            }
        }

        return (quotient, remainder)
    }

    /// Compute floor(2^256 / self).
    ///
    /// Uses: floor(2^256 / d) = floor((~d + 1) / d) + 1, where ~d + 1 is the
    /// two's complement (= 2^256 - d for d > 0, since we're in 256-bit space).
    public func inversePow2_256() -> Target256 {
        precondition(!isZero)
        let neg = twosComplement()
        let (q, _) = neg.divmod(self)
        return q + .one
    }

    // MARK: - Bit operations

    /// Get bit at position `i` (0 = LSB).
    public func bit(_ i: Int) -> Bool {
        let word = i / 64
        let pos = i % 64
        switch word {
        case 0: return (w0 >> pos) & 1 != 0
        case 1: return (w1 >> pos) & 1 != 0
        case 2: return (w2 >> pos) & 1 != 0
        case 3: return (w3 >> pos) & 1 != 0
        default: return false
        }
    }

    /// Set bit at position `i`.
    public mutating func setBit(_ i: Int) {
        let word = i / 64
        let pos = i % 64
        switch word {
        case 0: w0 |= (1 << pos)
        case 1: w1 |= (1 << pos)
        case 2: w2 |= (1 << pos)
        case 3: w3 |= (1 << pos)
        default: break
        }
    }

    /// Shift left by `n` bits.
    public func shiftedLeft(by n: Int) -> Target256 {
        guard n > 0 else { return self }
        guard n < 256 else { return .zero }

        let wordShift = n / 64
        let bitShift = n % 64

        // First: shift by whole words
        let w = [w0, w1, w2, w3]
        var shifted: [UInt64] = [0, 0, 0, 0]
        for i in wordShift..<4 {
            shifted[i] = w[i - wordShift]
        }

        if bitShift == 0 {
            return Target256(shifted[3], shifted[2], shifted[1], shifted[0])
        }

        // Then: shift by remaining bits
        var result: [UInt64] = [0, 0, 0, 0]
        for i in 0..<4 {
            result[i] = shifted[i] << bitShift
            if i > 0 {
                result[i] |= shifted[i - 1] >> (64 - bitShift)
            }
        }
        return Target256(result[3], result[2], result[1], result[0])
    }

    /// Two's complement (~self + 1).
    public func twosComplement() -> Target256 {
        let inverted = Target256(~w3, ~w2, ~w1, ~w0)
        return inverted + .one
    }
}

// MARK: - CustomStringConvertible

extension Target256: CustomStringConvertible {
    public var description: String {
        let hex = Array("0123456789abcdef".unicodeScalars)
        var result = ""
        result.reserveCapacity(64)
        for byte in bigEndianBytes() {
            result.append(Character(hex[Int(byte >> 4)]))
            result.append(Character(hex[Int(byte & 0x0F)]))
        }
        return result
    }
}
