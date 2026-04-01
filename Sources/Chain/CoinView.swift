import Base
import Protocol

/// An in-memory snapshot of coins (UTXOs) relevant to a block or transaction.
///
/// The CoinView maps transaction hashes to their unspent outputs,
/// tracks coins being spent (via the undo stack), and provides
/// methods for connecting/disconnecting blocks.
public struct CoinView: Sendable {
    /// Map of transaction hash → output index → CoinEntry.
    public var map: [Hash256: [UInt32: CoinEntry]]

    /// Stack of coins that were spent (for undo during disconnect).
    public var undo: [CoinEntry]

    /// Create an empty coin view.
    public init() {
        self.map = [:]
        self.undo = []
    }

    // MARK: - Lookup

    /// Get a coin entry by outpoint.
    public func getEntry(_ outpoint: Outpoint) -> CoinEntry? {
        map[outpoint.hash]?[outpoint.index]
    }

    /// Get the output for an outpoint.
    public func getOutput(_ outpoint: Outpoint) -> Output? {
        getEntry(outpoint)?.output
    }

    /// Check if a coin exists and is unspent.
    public func isUnspent(_ outpoint: Outpoint) -> Bool {
        guard let entry = getEntry(outpoint) else { return false }
        return !entry.spent
    }

    // MARK: - Adding Coins

    /// Add all outputs from a transaction as new coins.
    ///
    /// - Parameters:
    ///   - tx: The transaction whose outputs to add.
    ///   - height: The block height (-1 for unconfirmed).
    public mutating func addTX(_ tx: Transaction, height: Int) {
        let hash = tx.txHash()
        let coinbase = tx.isCoinbase
        var coins = map[hash] ?? [:]

        for (i, output) in tx.outputs.enumerated() {
            let entry = CoinEntry.fromOutput(
                output,
                height: height,
                coinbase: coinbase,
                version: tx.version
            )
            coins[UInt32(i)] = entry
        }

        map[hash] = coins
    }

    /// Add a single coin entry at a specific outpoint.
    public mutating func addEntry(_ outpoint: Outpoint, _ entry: CoinEntry) {
        var coins = map[outpoint.hash] ?? [:]
        coins[outpoint.index] = entry
        map[outpoint.hash] = coins
    }

    // MARK: - Spending Coins

    /// Spend a coin, pushing the old entry onto the undo stack.
    ///
    /// - Parameter outpoint: The outpoint to spend.
    /// - Returns: The spent CoinEntry, or `nil` if not found.
    @discardableResult
    public mutating func spendEntry(_ outpoint: Outpoint) -> CoinEntry? {
        guard var coins = map[outpoint.hash],
              var entry = coins[outpoint.index],
              !entry.spent else {
            return nil
        }

        let original = entry
        entry.spent = true
        coins[outpoint.index] = entry
        map[outpoint.hash] = coins
        undo.append(original)
        return original
    }

    /// Spend all inputs of a transaction, loading from the view.
    ///
    /// Skips coinbase inputs. Returns `false` if any input is missing.
    public mutating func spendInputs(_ tx: Transaction) -> Bool {
        for input in tx.inputs {
            if input.isCoinbase { continue }
            if spendEntry(input.prevout) == nil {
                return false
            }
        }
        return true
    }

    // MARK: - Removing Coins (for disconnect)

    /// Mark all outputs of a transaction as spent (for block disconnect).
    public mutating func removeTX(_ tx: Transaction) {
        let hash = tx.txHash()
        guard var coins = map[hash] else { return }

        for i in 0..<tx.outputs.count {
            if var entry = coins[UInt32(i)] {
                entry.spent = true
                coins[UInt32(i)] = entry
            }
        }

        map[hash] = coins
    }

    // MARK: - Undo

    /// Pop the most recently undone coin from the undo stack.
    public mutating func popUndo() -> CoinEntry? {
        undo.popLast()
    }

    /// Get the total input value for a transaction from this view.
    ///
    /// Returns `nil` if any input is missing from the view.
    public func getInputValue(_ tx: Transaction) -> UInt64? {
        var total: UInt64 = 0
        for input in tx.inputs {
            if input.isCoinbase { continue }
            guard let entry = getEntry(input.prevout), !entry.spent else {
                return nil
            }
            let (newTotal, overflow) = total.addingReportingOverflow(entry.output.value)
            guard !overflow else { return nil }
            total = newTotal
        }
        return total
    }

    /// Get the fee for a transaction (input value - output value).
    ///
    /// Returns `nil` if any input is missing or values overflow.
    public func getFee(_ tx: Transaction) -> Int64? {
        guard let inputValue = getInputValue(tx) else { return nil }
        var outputValue: UInt64 = 0
        for output in tx.outputs {
            let (newOut, overflow) = outputValue.addingReportingOverflow(output.value)
            guard !overflow else { return nil }
            outputValue = newOut
        }
        // Both bounded by maxMoney (~10^15) which fits in Int64
        guard inputValue <= UInt64(Int64.max), outputValue <= UInt64(Int64.max) else { return nil }
        return Int64(inputValue) - Int64(outputValue)
    }

    /// Check whether any coins are present for a given transaction hash.
    public func hasCoins(for txHash: Hash256) -> Bool {
        guard let coins = map[txHash] else { return false }
        return coins.values.contains { !$0.spent }
    }
}
