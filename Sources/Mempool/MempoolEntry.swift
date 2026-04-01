import Base
import Protocol
import Script
import Chain

/// A transaction in the mempool, wrapped with metadata for fee
/// estimation, eviction, and dependency tracking.
public struct MempoolEntry: Sendable {
    /// The transaction.
    public let tx: Transaction

    /// The transaction hash.
    public let hash: Hash256

    /// The chain height when this transaction entered the mempool.
    public let height: Int

    /// The sigops-adjusted virtual size.
    public let size: Int

    /// The sigop count.
    public let sigops: Int

    /// The absolute fee paid by this transaction (bumps).
    public let fee: Int64

    /// The fee including manual prioritization adjustments.
    public var deltaFee: Int64

    /// The unix timestamp when this was added to the mempool.
    public let time: UInt64

    /// The "chain value" — sum of input values from confirmed UTXOs.
    public let value: UInt64

    /// Whether any input comes from a coinbase transaction.
    public let coinbase: Bool

    /// Whether any input references an unconfirmed (in-mempool) transaction.
    public let dependencies: Bool

    /// Cumulative descendant fee (for CPFP-style eviction).
    public var descFee: Int64

    /// Cumulative descendant size.
    public var descSize: Int

    /// Create a mempool entry from a transaction and coin view.
    ///
    /// - Parameters:
    ///   - tx: The transaction.
    ///   - view: The coin view with all inputs resolved.
    ///   - height: The current chain height.
    ///   - time: The current unix timestamp.
    public init(tx: Transaction, view: CoinView, height: Int, time: UInt64) {
        self.tx = tx
        self.hash = tx.txHash()
        self.height = height
        self.time = time

        // Count sigops from witness scripts
        var sigopCount = 0
        for witness in tx.witnesses {
            if witness.items.isEmpty { continue }
            if let witnessScript = witness.items.last, witness.items.count > 2 {
                // P2WSH: count sigops in the witness script
                sigopCount += Script(witnessScript).sigops
            } else {
                // P2WPKH: 1 sigop
                sigopCount += 1
            }
        }
        self.sigops = sigopCount

        // Size: use virtual size
        self.size = max(tx.virtualSize, 1)

        // Compute fee and value from view
        var inputValue: UInt64 = 0
        var hasCoinbase = false
        var hasDeps = false

        for input in tx.inputs {
            if input.isCoinbase { continue }
            if let entry = view.getEntry(input.prevout) {
                inputValue += entry.output.value
                if entry.coinbase { hasCoinbase = true }
                if entry.height < 0 { hasDeps = true }
            }
        }

        var outputValue: UInt64 = 0
        for output in tx.outputs {
            outputValue += output.value
        }

        self.value = inputValue
        self.fee = Int64(inputValue) - Int64(outputValue)
        self.deltaFee = self.fee
        self.coinbase = hasCoinbase
        self.dependencies = hasDeps
        self.descFee = self.fee
        self.descSize = self.size
    }

    /// The fee rate in bumps per kilobyte.
    public var rate: Int64 {
        MempoolPolicy.getRate(size: size, fee: fee)
    }

    /// The delta (prioritized) fee rate.
    public var deltaRate: Int64 {
        MempoolPolicy.getRate(size: size, fee: deltaFee)
    }

    /// The descendant package fee rate.
    public var descRate: Int64 {
        guard descSize > 0 else { return 0 }
        return descFee * 1000 / Int64(descSize)
    }

    /// Whether this transaction qualifies as "free" at the given height.
    public func isFree(at height: Int) -> Bool {
        let priority = getPriority(at: height)
        return priority > MempoolPolicy.freeThreshold
    }

    /// Compute the current priority based on coin age.
    public func getPriority(at height: Int) -> Int64 {
        let delta = max(0, height - self.height)
        let agePriority = Int64(delta) * Int64(value) / Int64(size)
        return agePriority
    }
}
