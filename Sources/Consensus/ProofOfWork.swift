import Base
import ExtCrypto
import Protocol

/// Fistbump Proof-of-Work computation and verification.
///
/// Uses Balloon Hashing (memory-hard, CPU-friendly) instead of BLAKE2b+SHA3+mask.
///
/// ```
/// password = header bytes [0..<232] (everything except nonce area used as salt)
/// salt     = nonce (4 bytes LE) || extraNonce (24 bytes)
/// powHash  = BalloonHash(password, salt)
/// ```
///
/// The mask field is zeroed out and unused (kept for serialization compatibility).
public enum ProofOfWork {

    /// Compute the PoW hash for a block header using Balloon Hashing.
    public static func powHash(
        for header: BlockHeader,
        slots: Int = BalloonHash.defaultSlots,
        rounds: Int = BalloonHash.defaultRounds,
        delta: Int = BalloonHash.defaultDelta,
        isCancelled: (() -> Bool)? = nil
    ) throws -> Hash256 {
        // Hash the header fields to a 32-byte password so that
        // counter(8) + password(32) + salt(28) = 68 bytes fits in a
        // single 128-byte BLAKE2b block inside BalloonHash.
        let rawPassword = buildPassword(header)
        let password = try Blake2bHash.hash(rawPassword, size: 32)
        let salt = buildSalt(header)
        let result = try BalloonHash.hash(password: password, salt: salt, slots: slots, rounds: rounds, delta: delta, isCancelled: isCancelled)
        return Hash256(unchecked: result)
    }

    /// Compute the PoW hash using consensus parameters.
    public static func powHash(for header: BlockHeader, params: ConsensusParams, isCancelled: (() -> Bool)? = nil) throws -> Hash256 {
        try powHash(for: header, slots: params.balloonSlots, rounds: params.balloonRounds, delta: params.balloonDelta, isCancelled: isCancelled)
    }

    /// Compute the PoW hash and generate a proof for fast verification.
    public static func powHashWithProof(
        for header: BlockHeader,
        params: ConsensusParams,
        isCancelled: (() -> Bool)? = nil
    ) throws -> (hash: Hash256, proof: BalloonProof) {
        let rawPassword = buildPassword(header)
        let password = try Blake2bHash.hash(rawPassword, size: 32)
        let salt = buildSalt(header)
        let (result, proof) = try BalloonHash.hashWithProof(
            password: password, salt: salt,
            slots: params.balloonSlots, rounds: params.balloonRounds, delta: params.balloonDelta,
            isCancelled: isCancelled
        )
        return (Hash256(unchecked: result), proof)
    }

    /// Verify a block header using a BalloonProof instead of recomputing the hash.
    ///
    /// Returns the verified hash on success (for use in chain entry creation).
    public static func verifyWithProof(
        header: BlockHeader,
        proof: BalloonProof,
        params: ConsensusParams
    ) throws -> Hash256 {
        let rawPassword = buildPassword(header)
        let password = try Blake2bHash.hash(rawPassword, size: 32)
        let salt = buildSalt(header)

        // The output slot sample (index 0 = last slot) gives us the claimed hash.
        guard let outputSample = proof.samples.first,
              outputSample.index == UInt32(params.balloonSlots - 1) else {
            throw ConsensusError.invalidProof
        }
        let outputHash = outputSample.mixedValue

        guard proof.verify(
            outputHash: outputHash,
            password: password,
            salt: salt,
            slots: params.balloonSlots,
            rounds: params.balloonRounds,
            delta: params.balloonDelta
        ) else {
            throw ConsensusError.invalidProof
        }

        let hash = Hash256(unchecked: outputHash)

        // Check that the hash meets the difficulty target.
        let target = Target256.fromCompact(header.bits)
        guard !target.isZero && target <= params.powLimit else {
            throw ConsensusError.invalidTarget
        }
        let hashNum = Target256(bigEndian: hash.bytes)
        guard hashNum <= target else { throw ConsensusError.insufficientProofOfWork }

        return hash
    }

    /// Verify that a block header meets the PoW target.
    public static func verify(_ header: BlockHeader, params: ConsensusParams = .mainnet) throws -> Bool {
        let target = Target256.fromCompact(header.bits)
        guard !target.isZero else { return false }
        guard target.bitLength <= 256 else { return false }

        let hash = try powHash(for: header, params: params)
        let hashNum = Target256(bigEndian: hash.bytes)
        return hashNum <= target
    }

    // MARK: - Internal

    /// Build the password input: all header fields except nonce and extraNonce.
    /// This is the "slow-changing" part of the header that stays constant
    /// while the miner varies nonce/extraNonce.
    static func buildPassword(_ header: BlockHeader) -> [UInt8] {
        var w = BufferWriter(capacity: 176)
        w.writeBytes(header.prevBlock.bytes)     // 32
        w.writeBytes(header.merkleRoot.bytes)    // 32
        w.writeBytes(header.witnessRoot.bytes)   // 32
        w.writeBytes(header.treeRoot.bytes)      // 32
        w.writeBytes(header.reservedRoot.bytes)  // 32
        w.writeUInt64LE(header.time)             // 8
        w.writeUInt32LE(header.bits)             // 4
        w.writeUInt32LE(header.version)          // 4
        return w.data // 176 bytes
    }

    /// Build the salt input: nonce + extraNonce (28 bytes).
    static func buildSalt(_ header: BlockHeader) -> [UInt8] {
        var w = BufferWriter(capacity: 28)
        w.writeUInt32LE(header.nonce)            // 4
        w.writeBytes(header.extraNonce)          // 24
        return w.data // 28 bytes
    }
}
