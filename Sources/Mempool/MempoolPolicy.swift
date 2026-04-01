import Base

/// Policy constants for the transaction mempool.
public enum MempoolPolicy {
    /// Maximum mempool size in bytes (100 MB).
    public static let maxSize: Int = 100_000_000

    /// Maximum number of orphan transactions.
    public static let maxOrphans: Int = 100

    /// Maximum number of in-mempool ancestors for a transaction.
    public static let maxAncestors: Int = 50

    /// Transaction expiry time in seconds (72 hours).
    public static let expiryTime: UInt64 = 259_200

    /// Maximum transaction sigops (MAX_BLOCK_SIGOPS / 5).
    public static let maxTxSigops: Int = Constants.maxBlockSigops / 5

    /// Maximum transaction weight (MAX_BLOCK_WEIGHT / 10).
    public static let maxTxWeight: Int = Constants.maxBlockWeight / 10

    /// Minimum relay fee rate in bumps per kilobyte.
    public static let minRelay: Int64 = 1_000

    /// Factor applied to minimum fee to compute "absurd fee" threshold.
    public static let absurdFeeFactor: Int64 = 10_000

    /// Free transaction priority threshold (COIN * 144 / 250).
    public static let freeThreshold: Int64 = Int64(Amount.coinValue) * 144 / 250

    /// Eviction threshold (90% of max size).
    public static var evictionThreshold: Int {
        maxSize * 9 / 10
    }

    /// Compute the minimum fee for a transaction of the given size.
    ///
    /// - Parameters:
    ///   - size: The transaction's virtual size in bytes.
    ///   - rate: The fee rate in bumps per kB (default: `minRelay`).
    /// - Returns: The minimum fee in bumps.
    public static func getMinFee(size: Int, rate: Int64 = minRelay) -> Int64 {
        let fee = rate * Int64(size) / 1000
        return fee == 0 ? rate : fee
    }

    /// Compute the fee rate for a transaction.
    ///
    /// - Parameters:
    ///   - size: The transaction's virtual size.
    ///   - fee: The absolute fee.
    /// - Returns: The fee rate in bumps per kB.
    public static func getRate(size: Int, fee: Int64) -> Int64 {
        guard size > 0 else { return 0 }
        return fee * 1000 / Int64(size)
    }
}
