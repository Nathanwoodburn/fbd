import Base

/// A proof that a BalloonHash computation was performed correctly.
///
/// Contains sampled slot values from the expand and mix phases. A verifier
/// can check these samples in O(numSamples) BLAKE2b calls instead of
/// recomputing the full BalloonHash (which requires ~48M BLAKE2b calls).
///
/// Security: with 32 samples, a cheater who skips 5% of the scratchpad has
/// a <19% chance of passing; skipping 10% drops to <3.4%.
public struct BalloonProof: Equatable, Sendable {
    /// Number of samples per proof.
    public static let numSamples = 32

    /// Per-sample size: index(4) + expandValue(32) + expandPrev(32)
    ///   + mixedValue(32) + depPrev(32) + randomIdx(4) + depRandom(32) = 168 bytes.
    public static let sampleSize = 168

    /// Total serialized proof size.
    public static let serializedSize = numSamples * sampleSize

    public let samples: [Sample]

    public init(samples: [Sample]) {
        precondition(samples.count == Self.numSamples)
        self.samples = samples
    }


    /// A single proof sample at a challenged slot index.
    public struct Sample: Equatable, Sendable {
        /// The challenged slot index.
        public let index: UInt32

        /// Expand-phase value of this slot.
        public let expandValue: [UInt8] // 32 bytes

        /// Expand-phase value of the previous slot (index-1).
        /// For slot 0 this is unused (set to zeros).
        public let expandPrev: [UInt8] // 32 bytes

        /// Final mixed value of this slot.
        public let mixedValue: [UInt8] // 32 bytes

        /// Mixed/expand value of the previous slot used as input to primary mix.
        /// For slot 0: expand[slots-1]. For slot i>0: mixed[i-1].
        public let depPrev: [UInt8] // 32 bytes

        /// The random neighbor index from the delta mix step.
        public let randomIdx: UInt32

        /// Value of buf[randomIdx] at the time of the delta mix.
        /// mixed[randomIdx] if randomIdx < index, expand[randomIdx] if randomIdx > index,
        /// or the primary-mix result if randomIdx == index.
        public let depRandom: [UInt8] // 32 bytes

        public init(index: UInt32, expandValue: [UInt8], expandPrev: [UInt8],
                    mixedValue: [UInt8], depPrev: [UInt8],
                    randomIdx: UInt32, depRandom: [UInt8]) {
            self.index = index
            self.expandValue = expandValue
            self.expandPrev = expandPrev
            self.mixedValue = mixedValue
            self.depPrev = depPrev
            self.randomIdx = randomIdx
            self.depRandom = depRandom
        }
    }

    // MARK: - Challenge derivation

    /// Derive the 32 challenge indices from the BalloonHash output.
    ///
    /// Index 0 is always `slots - 1` (the output slot) to guarantee
    /// the proof binds to the claimed hash. Indices 1..31 are pseudorandom.
    public static func challengeIndices(outputHash: [UInt8], slots: Int) -> [UInt32] {
        var indices = [UInt32]()
        indices.reserveCapacity(numSamples)
        indices.append(UInt32(slots - 1))

        var seed = outputHash
        var used = Set<UInt32>([UInt32(slots - 1)])

        let allSlotsUsed = slots <= numSamples

        while indices.count < numSamples {
            seed = blake2b(seed)
            for offset in stride(from: 0, to: 32, by: 4) where indices.count < numSamples {
                let raw = UInt32(seed[offset])
                    | (UInt32(seed[offset + 1]) << 8)
                    | (UInt32(seed[offset + 2]) << 16)
                    | (UInt32(seed[offset + 3]) << 24)
                let idx = raw % UInt32(slots)
                if allSlotsUsed || used.insert(idx).inserted {
                    indices.append(idx)
                }
            }
        }

        return indices
    }

    // MARK: - Verification

    /// Verify this proof against a claimed BalloonHash output.
    ///
    /// - Parameters:
    ///   - outputHash: The claimed 32-byte BalloonHash result.
    ///   - password: The pre-hashed password (32 bytes).
    ///   - salt: The salt (28 bytes for FBD).
    ///   - slots: Number of BalloonHash slots.
    ///   - rounds: Number of mixing rounds (must be 1).
    ///   - delta: Number of random neighbors per round (must be 1).
    /// - Returns: `true` if the proof is valid.
    public func verify(
        outputHash: [UInt8],
        password: [UInt8],
        salt: [UInt8],
        slots: Int,
        rounds: Int = 1,
        delta: Int = 1
    ) -> Bool {
        guard rounds == 1, delta == 1 else { return false }
        guard samples.count == Self.numSamples else { return false }

        let challenges = Self.challengeIndices(outputHash: outputHash, slots: slots)

        for (si, challenge) in challenges.enumerated() {
            let sample = samples[si]
            guard sample.index == challenge else { return false }
            let i = Int(sample.index)

            // 1. Verify expand-phase value.
            if i == 0 {
                let expected = expandSlot0(password: password, salt: salt)
                guard sample.expandValue == expected else { return false }
            } else {
                let expected = hashSlot(counter: UInt64(i), data: sample.expandPrev, dataLen: 32)
                guard sample.expandValue == expected else { return false }
            }

            // 2. Compute primary mix result.
            let primaryCounter = UInt64(slots + i * 2)
            let primaryResult = hashMix(counter: primaryCounter, a: sample.expandValue, b: sample.depPrev)

            // 3. Verify random index.
            let deltaCounter = UInt64(slots + i * 2 + 1)
            let expectedRandomIdx = computeRandomIndex(counter: deltaCounter, round: 0, slot: i, j: 0, slots: slots)
            guard sample.randomIdx == UInt32(expectedRandomIdx) else { return false }

            // 4. Determine dep_random for the delta mix.
            let depRandom: [UInt8]
            if sample.randomIdx == sample.index {
                depRandom = primaryResult
            } else {
                depRandom = sample.depRandom
            }

            // 5. Compute final mixed value and verify.
            let finalValue = hashMix(counter: deltaCounter, a: primaryResult, b: depRandom)
            guard sample.mixedValue == finalValue else { return false }

            // 6. Output slot must match claimed hash.
            if i == slots - 1 {
                guard sample.mixedValue == outputHash else { return false }
            }
        }

        // Depth-2 cross-validation: when two challenged slots are adjacent
        // (sample[i].index + 1 == sample[j].index), verify that sample[j].expandPrev
        // matches sample[i].expandValue. This catches provers who fabricate
        // independent samples without computing the actual expand chain.
        let sortedSamples = samples.sorted { $0.index < $1.index }
        for k in 0..<(sortedSamples.count - 1) {
            let cur = sortedSamples[k]
            let nxt = sortedSamples[k + 1]
            if cur.index + 1 == nxt.index && nxt.index > 0 {
                guard cur.expandValue == nxt.expandPrev else { return false }
            }
        }

        return true
    }

    // MARK: - Helpers

    /// H(counter=0 || password || salt)
    private func expandSlot0(password: [UInt8], salt: [UInt8]) -> [UInt8] {
        var input = [UInt8](repeating: 0, count: 8 + password.count + salt.count)
        input.replaceSubrange(8..<(8 + password.count), with: password)
        input.replaceSubrange((8 + password.count)..<input.count, with: salt)
        return Self.blake2b(input)
    }

    /// H(counter || data) where data is 32 bytes.
    private func hashSlot(counter: UInt64, data: [UInt8], dataLen: Int) -> [UInt8] {
        var input = [UInt8](repeating: 0, count: 8 + dataLen)
        writeU64LE(&input, 0, counter)
        input.replaceSubrange(8..<(8 + dataLen), with: data[0..<dataLen])
        return Self.blake2b(input)
    }

    /// H(counter || a || b) where a and b are 32 bytes each.
    private func hashMix(counter: UInt64, a: [UInt8], b: [UInt8]) -> [UInt8] {
        var input = [UInt8](repeating: 0, count: 72)
        writeU64LE(&input, 0, counter)
        input.replaceSubrange(8..<40, with: a)
        input.replaceSubrange(40..<72, with: b)
        return Self.blake2b(input)
    }

    /// Compute random neighbor index: H(counter || round || i || j) mod slots.
    private func computeRandomIndex(counter: UInt64, round: Int, slot: Int, j: Int, slots: Int) -> Int {
        var input = [UInt8](repeating: 0, count: 32)
        writeU64LE(&input, 0, counter)
        writeU64LE(&input, 8, UInt64(round))
        writeU64LE(&input, 16, UInt64(slot))
        writeU64LE(&input, 24, UInt64(j))
        let hash = Self.blake2b(input)
        let raw = UInt64(hash[0]) | (UInt64(hash[1]) << 8) | (UInt64(hash[2]) << 16)
            | (UInt64(hash[3]) << 24) | (UInt64(hash[4]) << 32) | (UInt64(hash[5]) << 40)
            | (UInt64(hash[6]) << 48) | (UInt64(hash[7]) << 56)
        return Int(raw % UInt64(slots))
    }

    /// BLAKE2b-256 wrapper that returns [UInt8]. Traps on hash failure (shouldn't happen).
    static func blake2b(_ data: [UInt8]) -> [UInt8] {
        try! Blake2bHash.hash(data, size: 32)
    }

    private func writeU64LE(_ buf: inout [UInt8], _ offset: Int, _ v: UInt64) {
        buf[offset]     = UInt8(truncatingIfNeeded: v)
        buf[offset + 1] = UInt8(truncatingIfNeeded: v >> 8)
        buf[offset + 2] = UInt8(truncatingIfNeeded: v >> 16)
        buf[offset + 3] = UInt8(truncatingIfNeeded: v >> 24)
        buf[offset + 4] = UInt8(truncatingIfNeeded: v >> 32)
        buf[offset + 5] = UInt8(truncatingIfNeeded: v >> 40)
        buf[offset + 6] = UInt8(truncatingIfNeeded: v >> 48)
        buf[offset + 7] = UInt8(truncatingIfNeeded: v >> 56)
    }

    // MARK: - Serialization

    public func serialize() -> [UInt8] {
        var buf = [UInt8]()
        buf.reserveCapacity(Self.serializedSize)
        for s in samples {
            buf.append(contentsOf: u32LE(s.index))
            buf.append(contentsOf: s.expandValue)
            buf.append(contentsOf: s.expandPrev)
            buf.append(contentsOf: s.mixedValue)
            buf.append(contentsOf: s.depPrev)
            buf.append(contentsOf: u32LE(s.randomIdx))
            buf.append(contentsOf: s.depRandom)
        }
        return buf
    }

    public static func deserialize(_ data: [UInt8]) -> BalloonProof? {
        guard data.count == serializedSize else { return nil }
        var samples = [Sample]()
        samples.reserveCapacity(numSamples)
        var off = 0
        for _ in 0..<numSamples {
            let index = readU32LE(data, off); off += 4
            let expandValue = Array(data[off..<off+32]); off += 32
            let expandPrev = Array(data[off..<off+32]); off += 32
            let mixedValue = Array(data[off..<off+32]); off += 32
            let depPrev = Array(data[off..<off+32]); off += 32
            let randomIdx = readU32LE(data, off); off += 4
            let depRandom = Array(data[off..<off+32]); off += 32
            samples.append(Sample(
                index: index, expandValue: expandValue, expandPrev: expandPrev,
                mixedValue: mixedValue, depPrev: depPrev,
                randomIdx: randomIdx, depRandom: depRandom
            ))
        }
        return BalloonProof(samples: samples)
    }

    private func u32LE(_ v: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: v), UInt8(truncatingIfNeeded: v >> 8),
         UInt8(truncatingIfNeeded: v >> 16), UInt8(truncatingIfNeeded: v >> 24)]
    }

    private static func readU32LE(_ data: [UInt8], _ off: Int) -> UInt32 {
        UInt32(data[off]) | (UInt32(data[off+1]) << 8)
            | (UInt32(data[off+2]) << 16) | (UInt32(data[off+3]) << 24)
    }
}
