import Base
import Protocol

/// Validates covenant state transitions in transactions.
///
/// Checks that covenant types follow the allowed state machine transitions
/// and that covenant data items are structurally valid.
public enum CovenantVerifier {

    /// Allowed output covenant types for each input covenant type.
    ///
    /// This encodes the full Fistbump name state machine.
    private static let allowedTransitions: [CovenantType: Set<CovenantType>] = [
        .none:      [.none, .open, .bid],
        .open:      [.none, .open, .bid],
        .bid:       [.reveal],
        .reveal:    [.register, .redeem],
        .redeem:    [.none, .open, .bid],
        .register:  [.update, .renew, .transfer, .revoke],
        .update:    [.update, .renew, .transfer, .revoke],
        .renew:     [.update, .renew, .transfer, .revoke],
        .transfer:  [.update, .renew, .revoke, .finalize],
        .finalize:  [.update, .renew, .transfer, .revoke],
        .revoke:    [],  // Permanently unspendable
    ]

    /// Check if a covenant state transition is valid.
    ///
    /// - Parameters:
    ///   - from: The input covenant type.
    ///   - to: The output covenant type.
    /// - Returns: `true` if the transition is allowed.
    public static func isValidTransition(from: CovenantType, to: CovenantType) -> Bool {
        guard let allowed = allowedTransitions[from] else { return false }
        return allowed.contains(to)
    }

    /// Perform structural validation on a covenant's items.
    ///
    /// Checks that the covenant has the expected number of items and
    /// that each item has the correct size for its type.
    public static func checkCovenantSanity(_ covenant: Covenant) throws {
        switch covenant.type {
        case .none:
            guard covenant.items.isEmpty else {
                throw CovenantsError.malformedCovenant("NONE must have 0 items")
            }

        case .open:
            // 3 items (regular TLD)
            // 4 items (premium TLD with DNSSEC proof, OR subdomain with parentHash)
            guard covenant.items.count >= 3 && covenant.items.count <= 4 else {
                throw CovenantsError.malformedCovenant("OPEN must have 3-4 items")
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("OPEN nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("OPEN height must be 4 bytes")
            }
            let name = covenant.items[2]
            guard !name.isEmpty, name.count <= NameRules.maxNameSize else {
                throw CovenantsError.malformedCovenant("OPEN name invalid length")
            }

        case .bid:
            // 4 items (regular TLD)
            // 5 items (premium TLD with DNSSEC proof, OR subdomain with parentHash)
            guard covenant.items.count >= 4 && covenant.items.count <= 5 else {
                throw CovenantsError.malformedCovenant("BID must have 4-5 items")
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("BID nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("BID height must be 4 bytes")
            }
            guard covenant.items[3].count == 32 else {
                throw CovenantsError.malformedCovenant("BID blind must be 32 bytes")
            }

        case .reveal:
            guard covenant.items.count == 3 else {
                throw CovenantsError.malformedCovenant("REVEAL must have 3 items")
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("REVEAL nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("REVEAL height must be 4 bytes")
            }
            guard covenant.items[2].count == 32 else {
                throw CovenantsError.malformedCovenant("REVEAL nonce must be 32 bytes")
            }

        case .redeem:
            guard covenant.items.count == 2 else {
                throw CovenantsError.malformedCovenant("REDEEM must have 2 items")
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("REDEEM nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("REDEEM height must be 4 bytes")
            }

        case .register:
            // 4 items (regular) or 5 items (with flags byte)
            guard covenant.items.count == 4 || covenant.items.count == 5 else {
                throw CovenantsError.malformedCovenant("REGISTER must have 4 or 5 items")
            }
            if covenant.items.count == 5 {
                guard covenant.items[4].count == 1 else {
                    throw CovenantsError.malformedCovenant("REGISTER flags must be 1 byte")
                }
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("REGISTER nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("REGISTER height must be 4 bytes")
            }
            guard covenant.items[2].count <= NameRules.maxResourceSize else {
                throw CovenantsError.resourceTooLarge(covenant.items[2].count)
            }
            guard covenant.items[3].count == 32 else {
                throw CovenantsError.malformedCovenant("REGISTER blockHash must be 32 bytes")
            }

        case .update:
            // 3 items (regular) or 4 items (with flags byte)
            guard covenant.items.count == 3 || covenant.items.count == 4 else {
                throw CovenantsError.malformedCovenant("UPDATE must have 3 or 4 items")
            }
            if covenant.items.count == 4 {
                guard covenant.items[3].count == 1 else {
                    throw CovenantsError.malformedCovenant("UPDATE flags must be 1 byte")
                }
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("UPDATE nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("UPDATE height must be 4 bytes")
            }
            guard covenant.items[2].count <= NameRules.maxResourceSize else {
                throw CovenantsError.resourceTooLarge(covenant.items[2].count)
            }

        case .renew:
            guard covenant.items.count == 3 else {
                throw CovenantsError.malformedCovenant("RENEW must have 3 items")
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("RENEW nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("RENEW height must be 4 bytes")
            }
            guard covenant.items[2].count == 32 else {
                throw CovenantsError.malformedCovenant("RENEW blockHash must be 32 bytes")
            }

        case .transfer:
            guard covenant.items.count == 4 else {
                throw CovenantsError.malformedCovenant("TRANSFER must have 4 items")
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("TRANSFER nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("TRANSFER height must be 4 bytes")
            }
            guard covenant.items[2].count == 1 else {
                throw CovenantsError.malformedCovenant("TRANSFER version must be 1 byte")
            }
            let addrHash = covenant.items[3]
            guard addrHash.count >= 2, addrHash.count <= 40 else {
                throw CovenantsError.malformedCovenant("TRANSFER addressHash invalid length")
            }

        case .finalize:
            guard covenant.items.count == 7 else {
                throw CovenantsError.malformedCovenant("FINALIZE must have 7 items")
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("FINALIZE nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("FINALIZE height must be 4 bytes")
            }
            guard covenant.items[3].count == 1 else {
                throw CovenantsError.malformedCovenant("FINALIZE flags must be 1 byte")
            }
            guard covenant.items[4].count == 4 else {
                throw CovenantsError.malformedCovenant("FINALIZE claimed must be 4 bytes")
            }
            guard covenant.items[5].count == 4 else {
                throw CovenantsError.malformedCovenant("FINALIZE renewals must be 4 bytes")
            }
            guard covenant.items[6].count == 32 else {
                throw CovenantsError.malformedCovenant("FINALIZE blockHash must be 32 bytes")
            }

        case .revoke:
            guard covenant.items.count == 2 else {
                throw CovenantsError.malformedCovenant("REVOKE must have 2 items")
            }
            guard covenant.items[0].count == 32 else {
                throw CovenantsError.malformedCovenant("REVOKE nameHash must be 32 bytes")
            }
            guard covenant.items[1].count == 4 else {
                throw CovenantsError.malformedCovenant("REVOKE height must be 4 bytes")
            }

        }
    }
}
