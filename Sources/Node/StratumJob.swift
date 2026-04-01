import Mining

/// A Stratum mining job sent to workers.
///
/// Each job corresponds to a block template. Workers vary the nonce and
/// extraNonce2 to search for valid proofs of work.
struct StratumJob: Sendable {
    /// Pool extraNonce prefix size (bytes).
    static let poolExtraNonceSize = 8

    /// Worker extraNonce1 size (bytes).
    static let extraNonce1Size = 4

    /// Miner-controlled extraNonce2 size (bytes).
    /// Total extraNonce (24) = pool(8) + en1(4) + en2(12).
    static let extraNonce2Size = 12

    /// Job identifier (hex string).
    let id: String

    /// The block template from BlockAssembler.
    let template: BlockTemplate

    /// Pool extraNonce prefix (8 bytes, random per job).
    let poolExtraNonce: [UInt8]
}
