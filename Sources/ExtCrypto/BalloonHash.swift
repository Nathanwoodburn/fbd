import Base

/// Balloon Hashing — a memory-hard password hashing / PoW function.
///
/// Uses BLAKE2b-256 for the inner hash function. The hot path uses unsafe
/// pointers and a specialized single-block BLAKE2b to avoid heap allocations
/// across the 48M+ hash calls required at mainnet slot counts.
///
/// The algorithm fills a large buffer with pseudorandom data (expand phase),
/// then mixes the buffer using random neighbor accesses (mix phase),
/// and returns the last slot as the final hash.
///
/// Reference: Boneh, Corrigan-Gibbs, Schechter — "Balloon Hashing: A Memory-Hard
/// Function Providing Provable Protection Against Sequential Attacks" (2016).
public enum BalloonHash {
    /// Number of 32-byte slots for mainnet (16M slots = 512 MB).
    public static let defaultSlots = 16_777_216

    /// Number of mixing rounds.
    public static let defaultRounds = 1

    /// Number of pseudorandom neighbors per slot per round.
    public static let defaultDelta = 1

    /// Error thrown when a BalloonHash computation is cancelled mid-flight.
    public struct Cancelled: Error {}

    /// Compute the Balloon Hash of a password with a salt.
    ///
    /// - Parameter isCancelled: Optional closure checked periodically (~every 65K slots).
    ///   If it returns `true`, the computation aborts early with `BalloonHash.Cancelled`.
    public static func hash(
        password: [UInt8],
        salt: [UInt8],
        slots: Int = defaultSlots,
        rounds: Int = defaultRounds,
        delta: Int = defaultDelta,
        isCancelled: (() -> Bool)? = nil
    ) throws -> [UInt8] {
        let bufSize = slots * 32

        // Allocate scratchpad as raw memory
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        buf.initialize(repeating: 0, count: bufSize)
        defer { buf.deallocate() }

        // Pre-allocate reusable input buffer (max: 8 + password + salt, or 72)
        let maxInputLen = max(8 + password.count + salt.count, 128)
        let inp = UnsafeMutablePointer<UInt8>.allocate(capacity: maxInputLen)
        inp.initialize(repeating: 0, count: maxInputLen)
        defer { inp.deallocate() }

        var counter: UInt64 = 0

        // Phase 1: Expand
        storeU64LE(inp, counter)
        var len = 8
        for b in password { inp[len] = b; len += 1 }
        for b in salt { inp[len] = b; len += 1 }
        precondition(len <= 128, "BalloonHash slot 0 input exceeds single BLAKE2b block (128 bytes). Pre-hash the password.")
        blake2b256_single(inp, len, buf)
        counter += 1

        for i in 1..<slots {
            if i & 0xFFFF == 0, let isCancelled, isCancelled() { throw Cancelled() }
            storeU64LE(inp, counter)
            copy32(buf + (i - 1) * 32, inp + 8)
            blake2b256_single(inp, 40, buf + i * 32)
            counter += 1
        }

        // Phase 2: Mix
        for round in 0..<rounds {
            for i in 0..<slots {
                if i & 0xFFFF == 0, let isCancelled, isCancelled() { throw Cancelled() }
                let off = i * 32

                storeU64LE(inp, counter)
                copy32(buf + off, inp + 8)
                let prevIdx = i == 0 ? slots - 1 : i - 1
                copy32(buf + prevIdx * 32, inp + 40)
                blake2b256_single(inp, 72, buf + off)
                counter += 1

                for j in 0..<delta {
                    storeU64LE(inp, counter)
                    storeU64LE(inp + 8, UInt64(round))
                    storeU64LE(inp + 16, UInt64(i))
                    storeU64LE(inp + 24, UInt64(j))
                    // Hash to get random index — write to a temp area at end of inp
                    let tmpOut = inp + 80
                    blake2b256_single(inp, 32, tmpOut)
                    let idx = Int(loadU64LE(tmpOut) % UInt64(slots))

                    storeU64LE(inp, counter)
                    copy32(buf + off, inp + 8)
                    copy32(buf + idx * 32, inp + 40)
                    blake2b256_single(inp, 72, buf + off)
                    counter += 1
                }
            }
        }

        // Phase 3: Extract
        var result = [UInt8](repeating: 0, count: 32)
        result.withUnsafeMutableBufferPointer { rp in
            rp.baseAddress!.update(from: buf + (slots - 1) * 32, count: 32)
        }
        return result
    }

    /// Compute the Balloon Hash and generate a proof for fast verification.
    ///
    /// This allocates a second 512 MB buffer to save expand-phase values
    /// (overwritten during mix). After computing the hash, it derives
    /// challenge indices from the output and extracts proof samples.
    ///
    /// - Returns: A tuple of (hash, proof).
    public static func hashWithProof(
        password: [UInt8],
        salt: [UInt8],
        slots: Int = defaultSlots,
        rounds: Int = defaultRounds,
        delta: Int = defaultDelta,
        isCancelled: (() -> Bool)? = nil
    ) throws -> (hash: [UInt8], proof: BalloonProof) {
        precondition(rounds == 1 && delta == 1, "Proof generation requires rounds=1, delta=1")

        let bufSize = slots * 32

        // Main scratchpad
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        buf.initialize(repeating: 0, count: bufSize)
        defer { buf.deallocate() }

        // Expand-phase snapshot (saved before mix overwrites it)
        let expandBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        defer { expandBuf.deallocate() }

        let maxInputLen = max(8 + password.count + salt.count, 128)
        let inp = UnsafeMutablePointer<UInt8>.allocate(capacity: maxInputLen)
        inp.initialize(repeating: 0, count: maxInputLen)
        defer { inp.deallocate() }

        var counter: UInt64 = 0

        // Phase 1: Expand
        storeU64LE(inp, counter)
        var len = 8
        for b in password { inp[len] = b; len += 1 }
        for b in salt { inp[len] = b; len += 1 }
        precondition(len <= 128)
        blake2b256_single(inp, len, buf)
        counter += 1

        for i in 1..<slots {
            if i & 0xFFFF == 0, let isCancelled, isCancelled() { throw Cancelled() }
            storeU64LE(inp, counter)
            copy32(buf + (i - 1) * 32, inp + 8)
            blake2b256_single(inp, 40, buf + i * 32)
            counter += 1
        }

        // Save expand-phase values before mix overwrites them
        expandBuf.update(from: buf, count: bufSize)

        // Phase 2: Mix
        for round in 0..<rounds {
            for i in 0..<slots {
                if i & 0xFFFF == 0, let isCancelled, isCancelled() { throw Cancelled() }
                let off = i * 32

                storeU64LE(inp, counter)
                copy32(buf + off, inp + 8)
                let prevIdx = i == 0 ? slots - 1 : i - 1
                copy32(buf + prevIdx * 32, inp + 40)
                blake2b256_single(inp, 72, buf + off)
                counter += 1

                for j in 0..<delta {
                    storeU64LE(inp, counter)
                    storeU64LE(inp + 8, UInt64(round))
                    storeU64LE(inp + 16, UInt64(i))
                    storeU64LE(inp + 24, UInt64(j))
                    let tmpOut = inp + 80
                    blake2b256_single(inp, 32, tmpOut)
                    let idx = Int(loadU64LE(tmpOut) % UInt64(slots))

                    storeU64LE(inp, counter)
                    copy32(buf + off, inp + 8)
                    copy32(buf + idx * 32, inp + 40)
                    blake2b256_single(inp, 72, buf + off)
                    counter += 1
                }
            }
        }

        // Phase 3: Extract
        var result = [UInt8](repeating: 0, count: 32)
        result.withUnsafeMutableBufferPointer { rp in
            rp.baseAddress!.update(from: buf + (slots - 1) * 32, count: 32)
        }

        // Phase 4: Generate proof samples
        let challenges = BalloonProof.challengeIndices(outputHash: result, slots: slots)
        var samples = [BalloonProof.Sample]()
        samples.reserveCapacity(BalloonProof.numSamples)

        for challenge in challenges {
            let i = Int(challenge)

            let expandValue = extractSlot(expandBuf, i)
            let expandPrev: [UInt8]
            if i == 0 {
                expandPrev = [UInt8](repeating: 0, count: 32)
            } else {
                expandPrev = extractSlot(expandBuf, i - 1)
            }

            let mixedValue = extractSlot(buf, i)

            let depPrev: [UInt8]
            if i == 0 {
                depPrev = extractSlot(expandBuf, slots - 1)
            } else {
                depPrev = extractSlot(buf, i - 1)
            }

            // Recompute the random index for this slot
            let deltaCounter = UInt64(slots + i * 2 + 1)
            var ridxInp = [UInt8](repeating: 0, count: 32)
            ridxInp.withUnsafeMutableBufferPointer { bp in
                let p = bp.baseAddress!
                storeU64LE(p, deltaCounter)
                storeU64LE(p + 8, 0)  // round
                storeU64LE(p + 16, UInt64(i))
                storeU64LE(p + 24, 0)  // j
            }
            let ridxHash = BalloonProof.blake2b(ridxInp)
            let ridxRaw: UInt64 = UInt64(ridxHash[0])
                | (UInt64(ridxHash[1]) << 8) | (UInt64(ridxHash[2]) << 16)
                | (UInt64(ridxHash[3]) << 24) | (UInt64(ridxHash[4]) << 32)
                | (UInt64(ridxHash[5]) << 40) | (UInt64(ridxHash[6]) << 48)
                | (UInt64(ridxHash[7]) << 56)
            let randomIdx = Int(ridxRaw % UInt64(slots))

            let depRandom: [UInt8]
            if randomIdx == i {
                // Self-reference: verifier recomputes from primary result, store zeros
                depRandom = [UInt8](repeating: 0, count: 32)
            } else if randomIdx < i {
                depRandom = extractSlot(buf, randomIdx)
            } else {
                depRandom = extractSlot(expandBuf, randomIdx)
            }

            samples.append(BalloonProof.Sample(
                index: UInt32(i),
                expandValue: expandValue,
                expandPrev: expandPrev,
                mixedValue: mixedValue,
                depPrev: depPrev,
                randomIdx: UInt32(randomIdx),
                depRandom: depRandom
            ))
        }

        let proof = BalloonProof(samples: samples)
        return (result, proof)
    }

    /// Extract a 32-byte slot value from a buffer.
    private static func extractSlot(_ buf: UnsafePointer<UInt8>, _ index: Int) -> [UInt8] {
        Array(UnsafeBufferPointer(start: buf + index * 32, count: 32))
    }

    // MARK: - Helpers

    @inline(__always)
    private static func copy32(_ src: UnsafePointer<UInt8>, _ dst: UnsafeMutablePointer<UInt8>) {
        dst.update(from: src, count: 32)
    }

    @inline(__always)
    private static func storeU64LE(_ ptr: UnsafeMutablePointer<UInt8>, _ v: UInt64) {
        ptr[0] = UInt8(truncatingIfNeeded: v)
        ptr[1] = UInt8(truncatingIfNeeded: v &>> 8)
        ptr[2] = UInt8(truncatingIfNeeded: v &>> 16)
        ptr[3] = UInt8(truncatingIfNeeded: v &>> 24)
        ptr[4] = UInt8(truncatingIfNeeded: v &>> 32)
        ptr[5] = UInt8(truncatingIfNeeded: v &>> 40)
        ptr[6] = UInt8(truncatingIfNeeded: v &>> 48)
        ptr[7] = UInt8(truncatingIfNeeded: v &>> 56)
    }

    @inline(__always)
    private static func loadU64LE(_ ptr: UnsafePointer<UInt8>) -> UInt64 {
        UInt64(ptr[0]) | (UInt64(ptr[1]) << 8) | (UInt64(ptr[2]) << 16) | (UInt64(ptr[3]) << 24) |
        (UInt64(ptr[4]) << 32) | (UInt64(ptr[5]) << 40) | (UInt64(ptr[6]) << 48) | (UInt64(ptr[7]) << 56)
    }

    @inline(__always)
    private static func loadU64LE(_ ptr: UnsafePointer<UInt8>, at off: Int) -> UInt64 {
        loadU64LE(ptr + off)
    }

    // MARK: - BLAKE2b-256 (single block, no allocations)

    /// BLAKE2b-256 optimized for BalloonHash: all inputs fit in one 128-byte block.
    /// Uses only stack variables — no heap allocations.
    private static func blake2b256_single(
        _ input: UnsafePointer<UInt8>, _ inputLen: Int,
        _ output: UnsafeMutablePointer<UInt8>
    ) {
        // IV
        let iv0: UInt64 = 0x6a09e667f3bcc908
        let iv1: UInt64 = 0xbb67ae8584caa73b
        let iv2: UInt64 = 0x3c6ef372fe94f82b
        let iv3: UInt64 = 0xa54ff53a5f1d36f1
        let iv4: UInt64 = 0x510e527fade682d1
        let iv5: UInt64 = 0x9b05688c2b3e6c1f
        let iv6: UInt64 = 0x1f83d9abfb41bd6b
        let iv7: UInt64 = 0x5be0cd19137e2179

        // State: h = IV xor parameter block (digest=32, key=0, fanout=1, depth=1)
        var h0 = iv0 ^ 0x01010020
        var h1 = iv1
        var h2 = iv2
        var h3 = iv3
        let h4 = iv4
        let h5 = iv5
        let h6 = iv6
        let h7 = iv7

        // Load message words (zero-padded to 128 bytes)
        var m0:  UInt64 = 0; var m1:  UInt64 = 0; var m2:  UInt64 = 0; var m3:  UInt64 = 0
        var m4:  UInt64 = 0; var m5:  UInt64 = 0; var m6:  UInt64 = 0; var m7:  UInt64 = 0
        var m8:  UInt64 = 0; var m9:  UInt64 = 0; var m10: UInt64 = 0; var m11: UInt64 = 0
        var m12: UInt64 = 0; var m13: UInt64 = 0; var m14: UInt64 = 0; var m15: UInt64 = 0

        // Load full 8-byte words
        let fullWords = inputLen / 8
        if fullWords > 0  { m0  = loadU64LE(input, at: 0) }
        if fullWords > 1  { m1  = loadU64LE(input, at: 8) }
        if fullWords > 2  { m2  = loadU64LE(input, at: 16) }
        if fullWords > 3  { m3  = loadU64LE(input, at: 24) }
        if fullWords > 4  { m4  = loadU64LE(input, at: 32) }
        if fullWords > 5  { m5  = loadU64LE(input, at: 40) }
        if fullWords > 6  { m6  = loadU64LE(input, at: 48) }
        if fullWords > 7  { m7  = loadU64LE(input, at: 56) }
        if fullWords > 8  { m8  = loadU64LE(input, at: 64) }
        if fullWords > 9  { m9  = loadU64LE(input, at: 72) }
        if fullWords > 10 { m10 = loadU64LE(input, at: 80) }
        if fullWords > 11 { m11 = loadU64LE(input, at: 88) }
        if fullWords > 12 { m12 = loadU64LE(input, at: 96) }
        if fullWords > 13 { m13 = loadU64LE(input, at: 104) }
        if fullWords > 14 { m14 = loadU64LE(input, at: 112) }
        if fullWords > 15 { m15 = loadU64LE(input, at: 120) }

        // Handle partial last word
        let partialStart = fullWords * 8
        if partialStart < inputLen {
            var w: UInt64 = 0
            for i in partialStart..<inputLen {
                w |= UInt64(input[i]) << ((i - partialStart) * 8)
            }
            switch fullWords {
            case 0:  m0  = w; case 1:  m1  = w; case 2:  m2  = w; case 3:  m3  = w
            case 4:  m4  = w; case 5:  m5  = w; case 6:  m6  = w; case 7:  m7  = w
            case 8:  m8  = w; case 9:  m9  = w; case 10: m10 = w; case 11: m11 = w
            case 12: m12 = w; case 13: m13 = w; case 14: m14 = w; case 15: m15 = w
            default: break
            }
        }

        // Working vector
        var v0  = h0;  var v1  = h1;  var v2  = h2;  var v3  = h3
        var v4  = h4;  var v5  = h5;  var v6  = h6;  var v7  = h7
        var v8  = iv0; var v9  = iv1; var v10 = iv2; var v11 = iv3
        var v12 = iv4 ^ UInt64(inputLen) // t0
        var v13 = iv5                    // t1 = 0
        var v14 = ~iv6                   // final flag
        var v15 = iv7

        // Message word lookup helper
        @inline(__always) func mw(_ i: Int) -> UInt64 {
            switch i {
            case 0:  return m0;  case 1:  return m1;  case 2:  return m2;  case 3:  return m3
            case 4:  return m4;  case 5:  return m5;  case 6:  return m6;  case 7:  return m7
            case 8:  return m8;  case 9:  return m9;  case 10: return m10; case 11: return m11
            case 12: return m12; case 13: return m13; case 14: return m14; default: return m15
            }
        }

        // G mixing function
        @inline(__always) func G(
            _ a: inout UInt64, _ b: inout UInt64, _ c: inout UInt64, _ d: inout UInt64,
            _ x: UInt64, _ y: UInt64
        ) {
            a = a &+ b &+ x; d = (d ^ a); d = (d &>> 32) | (d &<< 32)
            c = c &+ d;      b = (b ^ c); b = (b &>> 24) | (b &<< 40)
            a = a &+ b &+ y; d = (d ^ a); d = (d &>> 16) | (d &<< 48)
            c = c &+ d;      b = (b ^ c); b = (b &>> 63) | (b &<< 1)
        }

        // Sigma schedule
        let s: [[UInt8]] = [
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

        // 12 rounds
        for r in 0..<12 {
            let sr = s[r]
            G(&v0,  &v4,  &v8,  &v12, mw(Int(sr[ 0])), mw(Int(sr[ 1])))
            G(&v1,  &v5,  &v9,  &v13, mw(Int(sr[ 2])), mw(Int(sr[ 3])))
            G(&v2,  &v6,  &v10, &v14, mw(Int(sr[ 4])), mw(Int(sr[ 5])))
            G(&v3,  &v7,  &v11, &v15, mw(Int(sr[ 6])), mw(Int(sr[ 7])))
            G(&v0,  &v5,  &v10, &v15, mw(Int(sr[ 8])), mw(Int(sr[ 9])))
            G(&v1,  &v6,  &v11, &v12, mw(Int(sr[10])), mw(Int(sr[11])))
            G(&v2,  &v7,  &v8,  &v13, mw(Int(sr[12])), mw(Int(sr[13])))
            G(&v3,  &v4,  &v9,  &v14, mw(Int(sr[14])), mw(Int(sr[15])))
        }

        // Finalize
        h0 ^= v0 ^ v8;  h1 ^= v1 ^ v9;  h2 ^= v2 ^ v10; h3 ^= v3 ^ v11

        // Extract 32 bytes
        storeU64LE(output,      h0)
        storeU64LE(output +  8, h1)
        storeU64LE(output + 16, h2)
        storeU64LE(output + 24, h3)
    }
}
