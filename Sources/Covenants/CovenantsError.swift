import Foundation

/// Errors that can occur during covenant validation.
public enum CovenantsError: Error, Equatable, Sendable, LocalizedError {
    /// The name is invalid (bad characters, length, etc.).
    case invalidName(String)

    /// The name is blacklisted (reserved special-use domain).
    case blacklistedName(String)

    /// The name hash does not match the expected value.
    case nameHashMismatch

    /// The name has not yet reached its rollout height.
    case nameNotYetAvailable

    /// The name is reserved and can only be claimed with a DNSSEC proof.
    case nameReserved

    /// Invalid covenant state transition.
    case invalidStateTransition(String)

    /// The blind hash does not match during bid reveal.
    case blindMismatch

    /// The auction is not in the expected state.
    case wrongAuctionState(String)

    /// The name has expired.
    case nameExpired

    /// The transfer lockup period has not elapsed.
    case transferLockupNotMet

    /// The covenant item count or format is invalid.
    case malformedCovenant(String)

    /// The value was not preserved across a name operation.
    case valueNotPreserved

    /// The resource data exceeds the maximum size.
    case resourceTooLarge(Int)

    /// A premium name OPEN or BID is missing the required DNSSEC proof.
    case dnssecProofRequired

    /// The DNSSEC proof chain verification failed.
    case dnssecProofInvalid(String)

    /// A REGISTER is missing the required dev fund payment.
    case devFundPaymentInsufficient(String = "")

    /// A REGISTER is missing the required burn payment to null address.
    case burnPaymentInsufficient

    /// The DNSSEC proof binding address does not match the covenant output address.
    case addressBindingMismatch

    /// The bid amount is below the minimum required.
    case bidTooLow(minimum: Int64, actual: Int64)

    /// The renewal fee is below the minimum required.
    case renewalFeeTooLow(minimum: Int64, actual: Int64)

    /// The DNSSEC proof domain TLD is not in the qualifying list.
    case invalidPremiumTLD(String)

    /// A subdomain OPEN references a parent that doesn't exist or isn't registered.
    case parentNameNotFound

    /// A subdomain OPEN references a parent that hasn't enabled subdomains.
    case parentSubdomainsNotAllowed

    /// A subdomain REGISTER is missing the required parent owner payment.
    case parentPaymentInsufficient

    /// Attempted to disable auctionSubdomains after it was enabled.
    case subdomainFlagPermanent

    /// Resource data contains delegation or SUB records which conflict with auctionSubdomains.
    case delegationNotAllowedWithSubdomains

    public var errorDescription: String? {
        switch self {
        case .invalidName(let name): return "Invalid name: \(name)."
        case .blacklistedName(let name): return "Name is not allowed: \(name)."
        case .nameHashMismatch: return "Name hash mismatch."
        case .nameNotYetAvailable: return "This name is not available yet."
        case .nameReserved: return "This name is reserved."
        case .invalidStateTransition(let msg): return "Invalid state transition: \(msg)."
        case .blindMismatch: return "Bid does not match the original blind."
        case .wrongAuctionState(let msg): return "Name is not in the right auction state for this action: \(msg)."
        case .nameExpired: return "This name has expired."
        case .transferLockupNotMet: return "Transfer lockup period has not passed yet."
        case .malformedCovenant(let msg): return "Malformed covenant: \(msg)."
        case .valueNotPreserved: return "Value was not preserved across the name operation."
        case .resourceTooLarge(let size): return "Record data is too large (\(size) bytes, max 512)."
        case .dnssecProofRequired: return "This name requires a DNSSEC proof to open or bid."
        case .dnssecProofInvalid(let msg): return "DNSSEC proof is invalid: \(msg)."
        case .devFundPaymentInsufficient(let detail): return detail.isEmpty ? "Transaction does not include the required dev fund payment." : "Dev fund payment insufficient: \(detail)"
        case .burnPaymentInsufficient: return "Transaction does not include the required burn payment."
        case .addressBindingMismatch: return "DNSSEC proof address does not match the covenant output."
        case .bidTooLow(let minimum, let actual): return "Bid amount is too low (minimum \(minimum), got \(actual))."
        case .renewalFeeTooLow(let minimum, let actual): return "Renewal fee is too low (minimum \(minimum), got \(actual))."
        case .invalidPremiumTLD(let tld): return "Invalid premium TLD: \(tld)."
        case .parentNameNotFound: return "Parent name is not registered."
        case .parentSubdomainsNotAllowed: return "Parent name does not allow subdomain auctions."
        case .parentPaymentInsufficient: return "Transaction does not include the required parent name payment."
        case .subdomainFlagPermanent: return "Cannot disable subdomain auctions once enabled."
        case .delegationNotAllowedWithSubdomains: return "Cannot set delegation records when subdomain auctions are enabled."
        }
    }
}
