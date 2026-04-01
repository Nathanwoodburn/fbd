/// A variable-length bit string used for trie node prefixes.
///
/// Bits are stored MSB-first within each byte (big-endian bit ordering).
/// This matches the Fistbump Urkel trie convention where bit 0 of the
/// key is the most significant bit of the first byte.
public struct Bits: Equatable, Sendable {
    /// The packed bit data (MSB-first within each byte).
    public private(set) var data: [UInt8]

    /// The number of valid bits in `data`.
    public let size: Int

    /// Create an empty bit string.
    public init() {
        self.data = []
        self.size = 0
    }

    /// Create a bit string from packed bytes and a bit count.
    public init(data: [UInt8], size: Int) {
        precondition(data.count >= (size + 7) / 8)
        self.data = data
        self.size = size
    }

    /// Whether this bit string is empty.
    public var isEmpty: Bool { size == 0 }

    /// Get the bit at the given index (0-indexed, MSB-first).
    public func get(_ index: Int) -> Int {
        precondition(index >= 0 && index < size)
        let oct = index >> 3
        let bit = index & 7
        return Int((data[oct] >> (7 - bit)) & 1)
    }

    /// Check if a key's bits match this prefix starting at the given depth.
    ///
    /// Returns `true` if all bits in this prefix match the key bits
    /// starting at `depth`.
    public func has(_ key: [UInt8], _ depth: Int) -> Bool {
        for i in 0..<size {
            let keyBit = Bits.getBit(key, depth + i)
            if get(i) != keyBit {
                return false
            }
        }
        return true
    }

    /// Count how many bits of this prefix match the key starting at depth.
    public func count(_ key: [UInt8], _ depth: Int) -> Int {
        for i in 0..<size {
            let keyBit = Bits.getBit(key, depth + i)
            if get(i) != keyBit {
                return i
            }
        }
        return size
    }

    /// Split this prefix at the given index.
    ///
    /// Returns `(front, back)` where `front` is bits `[0, index)` and
    /// `back` is bits `[index+1, size)`. The bit at `index` itself is
    /// excluded (it becomes the branching bit).
    public func split(_ index: Int) -> (Bits, Bits) {
        let front = slice(0, index)
        let back = slice(index + 1, size)
        return (front, back)
    }

    /// Extract a sub-bitstring from `start` to `end` (exclusive).
    public func slice(_ start: Int, _ end: Int) -> Bits {
        let len = end - start
        if len == 0 { return Bits() }

        var result = [UInt8](repeating: 0, count: (len + 7) / 8)
        for i in 0..<len {
            let bit = get(start + i)
            if bit == 1 {
                let oct = i >> 3
                let off = i & 7
                result[oct] |= UInt8(1 << (7 - off))
            }
        }
        return Bits(data: result, size: len)
    }

    /// Join this prefix, a branching bit, and another prefix.
    ///
    /// Result = `self` + `bit` + `other`
    public func join(_ other: Bits, _ bit: Int) -> Bits {
        let totalSize = size + 1 + other.size
        var result = [UInt8](repeating: 0, count: (totalSize + 7) / 8)

        // Copy self
        for i in 0..<size {
            if get(i) == 1 {
                Bits.setBitInPlace(&result, i)
            }
        }

        // Insert branching bit
        if bit == 1 {
            Bits.setBitInPlace(&result, size)
        }

        // Copy other
        for i in 0..<other.size {
            if other.get(i) == 1 {
                Bits.setBitInPlace(&result, size + 1 + i)
            }
        }

        return Bits(data: result, size: totalSize)
    }

    /// Compute the shared prefix between a key (starting at `depth`) and
    /// another key (starting at `depth`), up to a maximum of `maxBits` bits.
    public static func collide(_ key1: [UInt8], _ key2: [UInt8], depth: Int, maxBits: Int) -> Bits {
        var matchCount = 0
        for i in 0..<maxBits {
            let b1 = getBit(key1, depth + i)
            let b2 = getBit(key2, depth + i)
            if b1 != b2 { break }
            matchCount += 1
        }

        if matchCount == 0 { return Bits() }

        var result = [UInt8](repeating: 0, count: (matchCount + 7) / 8)
        for i in 0..<matchCount {
            if getBit(key1, depth + i) == 1 {
                setBitInPlace(&result, i)
            }
        }
        return Bits(data: result, size: matchCount)
    }

    // MARK: - Static Bit Helpers

    /// Get a single bit from a key byte array (MSB-first ordering).
    public static func getBit(_ key: [UInt8], _ index: Int) -> Int {
        let oct = index >> 3
        let bit = index & 7
        return Int((key[oct] >> (7 - bit)) & 1)
    }

    /// Set a bit in a byte array (MSB-first ordering).
    static func setBitInPlace(_ data: inout [UInt8], _ index: Int) {
        let oct = index >> 3
        let bit = index & 7
        data[oct] |= UInt8(1 << (7 - bit))
    }

    // MARK: - Serialization

    /// Serialize this bit string for use in proofs.
    ///
    /// Format: 1 or 2 byte size, then packed bit data.
    public func serialize() -> [UInt8] {
        var out = [UInt8]()
        if size < 0x80 {
            out.append(UInt8(size))
        } else {
            out.append(UInt8(0x80 | (size >> 8)))
            out.append(UInt8(size & 0xFF))
        }
        let byteCount = (size + 7) / 8
        out.append(contentsOf: data.prefix(byteCount))
        return out
    }

    /// Deserialize a bit string from raw bytes.
    ///
    /// - Returns: The parsed `Bits` and the number of bytes consumed.
    public static func deserialize(from bytes: [UInt8], at offset: Int) -> (Bits, Int)? {
        guard offset < bytes.count else { return nil }

        var pos = offset
        var bitSize: Int

        if bytes[pos] & 0x80 != 0 {
            guard pos + 1 < bytes.count else { return nil }
            bitSize = Int(bytes[pos] & 0x7F) << 8
            pos += 1
            bitSize |= Int(bytes[pos])
            pos += 1
        } else {
            bitSize = Int(bytes[pos])
            pos += 1
        }

        guard bitSize <= 256 else { return nil }
        let byteCount = (bitSize + 7) / 8
        guard pos + byteCount <= bytes.count else { return nil }

        let data = Array(bytes[pos..<pos + byteCount])
        pos += byteCount

        return (Bits(data: data, size: bitSize), pos - offset)
    }
}
