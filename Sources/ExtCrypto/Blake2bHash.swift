import Base

/// BLAKE2b hashing utilities.
///
/// Handshake uses BLAKE2b-256 for transaction hashing, merkle trees,
/// and various protocol-level operations.
///
/// This is a pure-Swift implementation of BLAKE2b (RFC 7693) that
/// replaces the buggy third-party Blake2.swift package.
public enum Blake2bHash {

    /// Compute BLAKE2b with the specified output size (in bytes).
    ///
    /// - Parameters:
    ///   - data: The input data to hash.
    ///   - size: Output hash size in bytes (1...64). Defaults to 32.
    /// - Returns: The hash bytes.
    public static func hash(_ data: [UInt8], size: Int = 32) throws -> [UInt8] {
        var ctx = Blake2bContext(digestSize: size)
        ctx.update(data)
        return ctx.finalize()
    }

    /// Compute BLAKE2b-256 (32-byte output), returning a `Hash256`.
    public static func hash256(_ data: [UInt8]) throws -> Hash256 {
        let bytes = try hash(data, size: 32)
        return Hash256(unchecked: bytes)
    }

    /// Compute keyed BLAKE2b with the specified output size.
    ///
    /// - Parameters:
    ///   - data: The input data to hash.
    ///   - key: The key (1...64 bytes).
    ///   - size: Output hash size in bytes (1...64). Defaults to 32.
    /// - Returns: The hash bytes.
    public static func hash(_ data: [UInt8], key: [UInt8], size: Int = 32) throws -> [UInt8] {
        var ctx = Blake2bContext(digestSize: size, key: key)
        ctx.update(data)
        return ctx.finalize()
    }
}

// MARK: - BLAKE2b Implementation (RFC 7693)

/// Internal BLAKE2b state.
private struct Blake2bContext {
    /// BLAKE2b IV (first 8 fractional digits of sqrt of first 8 primes).
    private static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]

    /// Sigma schedule for 12 rounds.
    private static let sigma: [[Int]] = [
        [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
        [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
        [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
        [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
        [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
        [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
        [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11],
        [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10],
        [ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5],
        [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0],
        [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
        [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
    ]

    /// The chaining state (8 x 64-bit words).
    private var h: [UInt64]

    /// Message block buffer (128 bytes).
    private var buf: [UInt8]

    /// Number of bytes in the buffer.
    private var bufLen: Int

    /// Total bytes compressed (low 64 bits only needed for messages < 2^64 bytes).
    private var t0: UInt64
    private var t1: UInt64

    /// Output digest size.
    private let digestSize: Int

    init(digestSize: Int, key: [UInt8] = []) {
        precondition(digestSize >= 1 && digestSize <= 64)
        precondition(key.count <= 64)

        self.digestSize = digestSize
        self.h = Self.iv
        self.buf = [UInt8](repeating: 0, count: 128)
        self.bufLen = 0
        self.t0 = 0
        self.t1 = 0

        // Parameter block: digest_length | key_length | fanout=1 | depth=1
        h[0] ^= UInt64(digestSize) | (UInt64(key.count) << 8) | (1 << 16) | (1 << 24)

        // If keyed, pad key to block size and process as first block
        if !key.isEmpty {
            var block = [UInt8](repeating: 0, count: 128)
            block.replaceSubrange(0..<key.count, with: key)
            update(block)
        }
    }

    mutating func update(_ data: [UInt8]) {
        var offset = 0
        var remaining = data.count

        while remaining > 0 {
            // If buffer has room and we won't fill it, just append
            if bufLen < 128 && bufLen + remaining > 128 {
                // Fill the buffer
                let fill = 128 - bufLen
                buf.replaceSubrange(bufLen..<128, with: data[offset..<(offset + fill)])
                bufLen = 128
                offset += fill
                remaining -= fill
            }

            if bufLen == 128 && remaining > 0 {
                // Compress the full buffer (not final)
                incrementCounter(128)
                compress(isLast: false)
                bufLen = 0
            }

            if remaining > 128 {
                // Process full blocks directly from data (keeping last partial for finalize)
                while remaining > 128 {
                    buf.replaceSubrange(0..<128, with: data[offset..<(offset + 128)])
                    bufLen = 128
                    incrementCounter(128)
                    compress(isLast: false)
                    bufLen = 0
                    offset += 128
                    remaining -= 128
                }
            }

            // Buffer the remaining bytes
            if remaining > 0 {
                let copyLen = min(remaining, 128 - bufLen)
                buf.replaceSubrange(bufLen..<(bufLen + copyLen), with: data[offset..<(offset + copyLen)])
                bufLen += copyLen
                offset += copyLen
                remaining -= copyLen
            }
        }
    }

    mutating func finalize() -> [UInt8] {
        // Add remaining bytes to counter
        incrementCounter(UInt64(bufLen))

        // Pad buffer with zeros
        for i in bufLen..<128 {
            buf[i] = 0
        }

        // Final compression
        compress(isLast: true)

        // Extract output
        var out = [UInt8](repeating: 0, count: digestSize)
        for i in 0..<digestSize {
            out[i] = UInt8((h[i / 8] >> (8 * (i % 8))) & 0xFF)
        }
        return out
    }

    private mutating func incrementCounter(_ inc: UInt64) {
        t0 = t0 &+ inc
        if t0 < inc { t1 &+= 1 }
    }

    /// The BLAKE2b compression function.
    private mutating func compress(isLast: Bool) {
        // Load message words (16 x 64-bit LE)
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            let offset = i * 8
            m[i] = UInt64(buf[offset])
                | (UInt64(buf[offset + 1]) << 8)
                | (UInt64(buf[offset + 2]) << 16)
                | (UInt64(buf[offset + 3]) << 24)
                | (UInt64(buf[offset + 4]) << 32)
                | (UInt64(buf[offset + 5]) << 40)
                | (UInt64(buf[offset + 6]) << 48)
                | (UInt64(buf[offset + 7]) << 56)
        }

        // Initialize working vector
        var v = [UInt64](repeating: 0, count: 16)
        v[0] = h[0]; v[1] = h[1]; v[2] = h[2]; v[3] = h[3]
        v[4] = h[4]; v[5] = h[5]; v[6] = h[6]; v[7] = h[7]
        v[8] = Self.iv[0]; v[9] = Self.iv[1]; v[10] = Self.iv[2]; v[11] = Self.iv[3]
        v[12] = Self.iv[4]; v[13] = Self.iv[5]; v[14] = Self.iv[6]; v[15] = Self.iv[7]

        v[12] ^= t0
        v[13] ^= t1

        if isLast {
            v[14] = ~v[14]
        }

        // 12 rounds
        for round in 0..<12 {
            let s = Self.sigma[round]

            // Column step
            g(&v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]])
            g(&v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]])
            g(&v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]])
            g(&v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]])

            // Diagonal step
            g(&v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]])
            g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(&v, 2, 7,  8, 13, m[s[12]], m[s[13]])
            g(&v, 3, 4,  9, 14, m[s[14]], m[s[15]])
        }

        // Finalize hash
        for i in 0..<8 {
            h[i] ^= v[i] ^ v[i + 8]
        }
    }

    /// The BLAKE2b G mixing function.
    @inline(__always)
    private func g(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotateRight(32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotateRight(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(63)
    }
}

private extension UInt64 {
    @inline(__always)
    func rotateRight(_ n: Int) -> UInt64 {
        (self >> n) | (self << (64 - n))
    }
}
