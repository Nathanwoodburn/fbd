/// Errors that can occur during block template construction and mining.
public enum MiningError: Error, Sendable {
    /// The coinbase output value exceeds the allowed reward + fees.
    case rewardExceeded(allowed: Int64, actual: Int64)

    /// The block weight exceeds the maximum.
    case blockWeightExceeded(weight: Int)

    /// The block sigops exceeds the maximum.
    case blockSigopsExceeded(sigops: Int)

    /// No transactions available in mempool.
    case emptyMempool

    /// The submitted block is invalid.
    case invalidBlock(String)

    /// The address is invalid for coinbase output.
    case invalidAddress(String)
}
