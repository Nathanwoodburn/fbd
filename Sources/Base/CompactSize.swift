/// Bitcoin-style variable-length integer encoding.
///
/// Values are encoded using 1, 3, 5, or 9 bytes depending on magnitude:
/// - `0x00...0xFC`:       1 byte  (the value itself)
/// - `0x00FD...0xFFFF`:   3 bytes (0xFD prefix + UInt16 LE)
/// - `0x10000...0xFFFFFFFF`: 5 bytes (0xFE prefix + UInt32 LE)
/// - `0x100000000...`:    9 bytes (0xFF prefix + UInt64 LE)
public enum CompactSize: Sendable {

    /// The number of bytes needed to encode the given value.
    public static func encodedSize(of value: UInt64) -> Int {
        switch value {
        case 0...0xFC:
            return 1
        case 0xFD...0xFFFF:
            return 3
        case 0x10000...0xFFFF_FFFF:
            return 5
        default:
            return 9
        }
    }

    /// Encode a value into a byte array.
    public static func encode(_ value: UInt64) -> [UInt8] {
        switch value {
        case 0...0xFC:
            return [UInt8(value)]
        case 0xFD...0xFFFF:
            var buf = [UInt8](repeating: 0, count: 3)
            buf[0] = 0xFD
            let v = UInt16(value)
            buf[1] = UInt8(v & 0xFF)
            buf[2] = UInt8(v >> 8)
            return buf
        case 0x10000...0xFFFF_FFFF:
            var buf = [UInt8](repeating: 0, count: 5)
            buf[0] = 0xFE
            let v = UInt32(value)
            buf[1] = UInt8(v & 0xFF)
            buf[2] = UInt8((v >> 8) & 0xFF)
            buf[3] = UInt8((v >> 16) & 0xFF)
            buf[4] = UInt8(v >> 24)
            return buf
        default:
            var buf = [UInt8](repeating: 0, count: 9)
            buf[0] = 0xFF
            let v = value
            buf[1] = UInt8(v & 0xFF)
            buf[2] = UInt8((v >> 8) & 0xFF)
            buf[3] = UInt8((v >> 16) & 0xFF)
            buf[4] = UInt8((v >> 24) & 0xFF)
            buf[5] = UInt8((v >> 32) & 0xFF)
            buf[6] = UInt8((v >> 40) & 0xFF)
            buf[7] = UInt8((v >> 48) & 0xFF)
            buf[8] = UInt8(v >> 56)
            return buf
        }
    }

    /// Decode a compact size from the beginning of a byte slice.
    ///
    /// - Returns: A tuple of the decoded value and the number of bytes consumed.
    /// - Throws: `BaseError.bufferUnderflow` or `BaseError.compactSizeNonCanonical`.
    public static func decode(from bytes: some Collection<UInt8>) throws -> (value: UInt64, bytesRead: Int) {
        guard let first = bytes.first else {
            throw BaseError.bufferUnderflow
        }

        switch first {
        case 0x00...0xFC:
            return (UInt64(first), 1)

        case 0xFD:
            guard bytes.count >= 3 else { throw BaseError.bufferUnderflow }
            let startIndex = bytes.index(bytes.startIndex, offsetBy: 1)
            let value = UInt64(bytes[startIndex]) |
                        (UInt64(bytes[bytes.index(startIndex, offsetBy: 1)]) << 8)
            guard value >= 0xFD else { throw BaseError.compactSizeNonCanonical }
            return (value, 3)

        case 0xFE:
            guard bytes.count >= 5 else { throw BaseError.bufferUnderflow }
            let startIndex = bytes.index(bytes.startIndex, offsetBy: 1)
            let value = UInt64(bytes[startIndex]) |
                        (UInt64(bytes[bytes.index(startIndex, offsetBy: 1)]) << 8) |
                        (UInt64(bytes[bytes.index(startIndex, offsetBy: 2)]) << 16) |
                        (UInt64(bytes[bytes.index(startIndex, offsetBy: 3)]) << 24)
            guard value > 0xFFFF else { throw BaseError.compactSizeNonCanonical }
            return (value, 5)

        default: // 0xFF
            guard bytes.count >= 9 else { throw BaseError.bufferUnderflow }
            let si = bytes.index(bytes.startIndex, offsetBy: 1)
            let b0 = UInt64(bytes[si])
            let b1 = UInt64(bytes[bytes.index(si, offsetBy: 1)]) << 8
            let b2 = UInt64(bytes[bytes.index(si, offsetBy: 2)]) << 16
            let b3 = UInt64(bytes[bytes.index(si, offsetBy: 3)]) << 24
            let b4 = UInt64(bytes[bytes.index(si, offsetBy: 4)]) << 32
            let b5 = UInt64(bytes[bytes.index(si, offsetBy: 5)]) << 40
            let b6 = UInt64(bytes[bytes.index(si, offsetBy: 6)]) << 48
            let b7 = UInt64(bytes[bytes.index(si, offsetBy: 7)]) << 56
            let value = b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7
            guard value > 0xFFFF_FFFF else { throw BaseError.compactSizeNonCanonical }
            return (value, 9)
        }
    }
}
