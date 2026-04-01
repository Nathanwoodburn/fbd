import Foundation

/// Errors that can occur during chain operations.
public enum ChainError: Error, Equatable, Sendable, LocalizedError {
    /// The block's prevBlock hash does not match the expected parent.
    case invalidPrevBlock

    /// The block height does not match expected.
    case invalidHeight

    /// Duplicate block (already in the chain).
    case duplicateBlock

    /// The block extends a chain with less work than the current best.
    case insufficientChainwork

    /// A referenced UTXO was not found.
    case missingCoin(String)

    /// A UTXO was already spent.
    case alreadySpent(String)

    /// The coin does not have enough confirmations (coinbase maturity).
    case immatureCoinbase

    /// The total input value is less than the total output value.
    case inputValueBelowOutput

    /// The claimed fees exceed the actual fees.
    case feeMismatch

    /// The block fails checkpoint validation.
    case checkpointMismatch

    /// Sequence lock requirements not met.
    case sequenceLockNotMet

    /// Generic validation failure.
    case validationFailed(String)

    /// The block's tree root does not match the computed Urkel tree root.
    case invalidTreeRoot(height: Int, expected: String, computed: String)

    public var errorDescription: String? {
        switch self {
        case .invalidPrevBlock: return "Invalid previous block."
        case .invalidHeight: return "Invalid block height."
        case .duplicateBlock: return "Duplicate block."
        case .insufficientChainwork: return "Insufficient chainwork."
        case .missingCoin(let msg): return "Missing coin: \(msg)."
        case .alreadySpent(let msg): return "Already spent: \(msg)."
        case .immatureCoinbase: return "Mining reward has not matured yet."
        case .inputValueBelowOutput: return "Input value is below output value."
        case .feeMismatch: return "Fee mismatch."
        case .checkpointMismatch: return "Checkpoint mismatch."
        case .sequenceLockNotMet: return "Sequence lock not met."
        case .validationFailed(let msg): return "Validation failed: \(msg)."
        case .invalidTreeRoot(let h, let exp, let got): return "Invalid tree root at height \(h) (expected \(exp), got \(got))."
        }
    }
}
