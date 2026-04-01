/// Base58 and Base58Check encoding (used for BIP32 xpub/xprv serialization).

private let base58Alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".unicodeScalars.map { UInt8(ascii: $0) })

/// Encode raw bytes as a Base58 string.
public func base58Encode(_ bytes: [UInt8]) -> String {
    // Count leading zeros
    var leadingZeros = 0
    for b in bytes {
        if b == 0 { leadingZeros += 1 } else { break }
    }

    // Convert to base-58 digits (big-endian long division)
    var digits = [UInt8]()
    for byte in bytes {
        var carry = Int(byte)
        for j in 0..<digits.count {
            carry += Int(digits[j]) << 8
            digits[j] = UInt8(carry % 58)
            carry /= 58
        }
        while carry > 0 {
            digits.append(UInt8(carry % 58))
            carry /= 58
        }
    }

    var result = [UInt8]()
    result.reserveCapacity(leadingZeros + digits.count)
    for _ in 0..<leadingZeros {
        result.append(base58Alphabet[0])
    }
    for d in digits.reversed() {
        result.append(base58Alphabet[Int(d)])
    }
    return String(result.map { Character(UnicodeScalar($0)) })
}

/// Decode a Base58 string to raw bytes.
public func base58Decode(_ string: String) -> [UInt8]? {
    // Build reverse lookup table
    var table = [UInt8](repeating: 255, count: 128)
    for (i, c) in base58Alphabet.enumerated() {
        table[Int(c)] = UInt8(i)
    }

    // Count leading '1's (encoded zeros)
    var leadingZeros = 0
    for ch in string.utf8 {
        if ch == base58Alphabet[0] { leadingZeros += 1 } else { break }
    }

    // Convert from base-58 digits to bytes
    var bytes = [UInt8]()
    for ch in string.utf8 {
        guard ch < 128 else { return nil }
        let digit = table[Int(ch)]
        guard digit != 255 else { return nil }
        var carry = Int(digit)
        for j in 0..<bytes.count {
            carry += Int(bytes[j]) * 58
            bytes[j] = UInt8(carry & 0xFF)
            carry >>= 8
        }
        while carry > 0 {
            bytes.append(UInt8(carry & 0xFF))
            carry >>= 8
        }
    }

    var result = [UInt8]()
    result.reserveCapacity(leadingZeros + bytes.count)
    for _ in 0..<leadingZeros {
        result.append(0)
    }
    result.append(contentsOf: bytes.reversed())
    return result
}
