import Base
import Protocol
import Consensus

/// Constructs coinbase transactions for new blocks.
///
/// The coinbase transaction is the first transaction in every block.
/// It has a single null input and outputs that pay the block reward
/// plus collected fees to the miner.
public enum CoinbaseBuilder {

    /// Build a coinbase transaction for a block at the given height.
    ///
    /// - Parameters:
    ///   - address: The miner's payout address.
    ///   - height: The block height (used for reward calculation and BIP34 commitment).
    ///   - fees: Total fees collected from included transactions.
    ///   - flags: Optional extra data for the coinbase (e.g., pool identifier).
    /// - Returns: The constructed coinbase transaction.
    public static func build(
        address: Address,
        height: Int,
        fees: Int64,
        flags: [UInt8] = []
    ) -> Transaction {
        let reward = BlockReward.getReward(height: height)
        let (total, overflow) = reward.addingReportingOverflow(fees)
        let totalValue = UInt64(max(0, overflow ? reward : total))

        // Coinbase input: null prevout with height encoded in sequence.
        // The sequence makes each coinbase unique in txHash() (which excludes
        // witness data). Without this, consecutive blocks with identical
        // outputs would share the same txHash, causing wallet coin overwrites.
        let input = Input(prevout: .null, sequence: UInt32(height & 0xFFFF_FFFF))

        // Coinbase output: pay reward + fees to miner address
        let output = Output(value: totalValue, address: address)

        // Witness: BIP34-style height commitment + optional flags
        let heightWitness = heightCommitment(height)
        var witnessItems: [[UInt8]] = [heightWitness]
        if !flags.isEmpty {
            witnessItems.append(flags)
        }
        let witness = Witness(items: witnessItems)

        return Transaction(
            inputs: [input],
            outputs: [output],
            witnesses: [witness]
        )
    }

    /// Decode a block height from a minimal-length little-endian byte array.
    ///
    /// Inverse of `heightCommitment(_:)`. Returns -1 on invalid input.
    public static func decodeHeight(_ bytes: [UInt8]) -> Int {
        guard !bytes.isEmpty else { return -1 }
        var result = 0
        for i in 0..<bytes.count {
            result |= Int(bytes[i]) << (i * 8)
        }
        // If the high bit of the last byte is set, the number is negative (invalid)
        if bytes.last! & 0x80 != 0 { return -1 }
        return result
    }

    /// Encode a block height as a minimal-length little-endian byte array.
    ///
    /// This is used in the coinbase witness to commit to the block height
    /// (similar to Bitcoin's BIP34 requirement).
    public static func heightCommitment(_ height: Int) -> [UInt8] {
        if height == 0 { return [0] }
        var h = height
        var bytes = [UInt8]()
        while h > 0 {
            bytes.append(UInt8(h & 0xFF))
            h >>= 8
        }
        // If the high bit is set, add a zero byte to keep it positive
        if bytes.last! & 0x80 != 0 {
            bytes.append(0)
        }
        return bytes
    }
}
