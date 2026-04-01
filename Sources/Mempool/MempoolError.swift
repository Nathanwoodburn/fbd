import Foundation

/// Errors that can occur during mempool operations.
public enum MempoolError: Error, Equatable, Sendable, LocalizedError {
    /// The transaction is already in the mempool.
    case alreadyExists

    /// The transaction conflicts with another mempool transaction (double-spend).
    case doubleSpend

    /// A name in the transaction is already being operated on in the mempool.
    case nameConflict

    /// The transaction fee is below the minimum relay fee.
    case insufficientFee

    /// The transaction fee is absurdly high.
    case absurdFee

    /// The mempool is full and the transaction was evicted.
    case mempoolFull

    /// The transaction has too many in-mempool ancestors.
    case tooManyAncestors

    /// The transaction exceeds the maximum sigops.
    case tooManySigops

    /// The transaction is an orphan (has missing inputs).
    case orphanTransaction

    /// The transaction failed script verification.
    case scriptVerificationFailed(String)

    /// The transaction failed contextual checks.
    case verificationFailed(String)

    /// The transaction is non-standard.
    case nonStandard(String)

    /// The transaction contains an invalid covenant (e.g. delegation + auctionSubdomains).
    case invalidCovenant(String)

    /// The orphan pool is full.
    case orphanPoolFull

    public var errorDescription: String? {
        switch self {
        case .alreadyExists: return "Transaction already exists in the mempool."
        case .doubleSpend: return "Transaction conflicts with an existing one. Wait for it to confirm."
        case .nameConflict: return "Name conflict in mempool."
        case .insufficientFee: return "Transaction fee is too low."
        case .absurdFee: return "Transaction fee is unreasonably high."
        case .mempoolFull: return "Mempool is full."
        case .tooManyAncestors: return "Transaction has too many unconfirmed ancestors."
        case .tooManySigops: return "Transaction exceeds the maximum signature operations."
        case .orphanTransaction: return "Transaction has missing inputs."
        case .scriptVerificationFailed(let msg): return "Script verification failed: \(msg)."
        case .verificationFailed(let msg): return "Verification failed: \(msg)."
        case .nonStandard(let msg): return "Non-standard transaction: \(msg)."
        case .invalidCovenant(let msg): return "Invalid covenant: \(msg)."
        case .orphanPoolFull: return "Orphan pool is full."
        }
    }
}
