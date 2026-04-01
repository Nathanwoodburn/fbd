import Base
import Protocol

/// Tracks name covenant operations in the mempool.
///
/// Enforces that only one "unique" name operation (OPEN, UPDATE, RENEW,
/// TRANSFER, FINALIZE, REVOKE) per name is in the mempool at a time.
/// Multiple BIDs and REVEALs for the same name are allowed.
public struct ContractState: Sendable {
    /// Set of name hashes currently being operated on (unique ops).
    public var unique: Set<Hash256>

    /// Name hash → set of transaction hashes with OPEN covenants.
    public var opens: [Hash256: Set<Hash256>]

    /// Name hash → set of transaction hashes with BID covenants.
    public var bids: [Hash256: Set<Hash256>]

    /// Name hash → set of transaction hashes with REVEAL covenants.
    public var reveals: [Hash256: Set<Hash256>]

    /// Name hash → set of transaction hashes with other covenants (UPDATE, etc.).
    public var updates: [Hash256: Set<Hash256>]

    public init() {
        self.unique = []
        self.opens = [:]
        self.bids = [:]
        self.reveals = [:]
        self.updates = [:]
    }

    /// Check if any name in the transaction is already being operated on.
    public func hasNames(_ tx: Transaction) -> Bool {
        for output in tx.outputs {
            guard output.covenant.type.isName else { continue }
            guard output.covenant.items.count >= 1,
                  output.covenant.items[0].count == 32 else { continue }
            let nameHash = Hash256(unchecked: output.covenant.items[0])

            switch output.covenant.type {
            case .open, .register, .update, .renew, .transfer, .finalize, .revoke:
                if unique.contains(nameHash) { return true }
            case .bid, .reveal, .redeem:
                break
            default:
                break
            }
        }
        return false
    }

    /// Track a transaction's covenant operations.
    public mutating func track(_ tx: Transaction, txHash: Hash256) {
        for output in tx.outputs {
            guard output.covenant.type.isName else { continue }
            guard output.covenant.items.count >= 1,
                  output.covenant.items[0].count == 32 else { continue }
            let nameHash = Hash256(unchecked: output.covenant.items[0])

            switch output.covenant.type {
            case .open:
                opens[nameHash, default: []].insert(txHash)
                unique.insert(nameHash)
            case .bid:
                bids[nameHash, default: []].insert(txHash)
            case .reveal:
                reveals[nameHash, default: []].insert(txHash)
            case .redeem:
                bids[nameHash, default: []].insert(txHash)
            case .register, .update, .renew, .transfer, .finalize, .revoke:
                updates[nameHash, default: []].insert(txHash)
                unique.insert(nameHash)
            default:
                break
            }
        }
    }

    /// Untrack a transaction's covenant operations.
    public mutating func untrack(_ tx: Transaction, txHash: Hash256) {
        for output in tx.outputs {
            guard output.covenant.type.isName else { continue }
            guard output.covenant.items.count >= 1,
                  output.covenant.items[0].count == 32 else { continue }
            let nameHash = Hash256(unchecked: output.covenant.items[0])

            switch output.covenant.type {
            case .open:
                opens[nameHash]?.remove(txHash)
                if opens[nameHash]?.isEmpty == true {
                    opens.removeValue(forKey: nameHash)
                    unique.remove(nameHash)
                }
            case .bid:
                bids[nameHash]?.remove(txHash)
                if bids[nameHash]?.isEmpty == true { bids.removeValue(forKey: nameHash) }
            case .reveal:
                reveals[nameHash]?.remove(txHash)
                if reveals[nameHash]?.isEmpty == true { reveals.removeValue(forKey: nameHash) }
            case .redeem:
                bids[nameHash]?.remove(txHash)
                if bids[nameHash]?.isEmpty == true { bids.removeValue(forKey: nameHash) }
            case .register, .update, .renew, .transfer, .finalize, .revoke:
                updates[nameHash]?.remove(txHash)
                if updates[nameHash]?.isEmpty == true {
                    updates.removeValue(forKey: nameHash)
                    unique.remove(nameHash)
                }
            default:
                break
            }
        }
    }

    /// Get all transaction hashes that reference a specific name.
    public func txsForName(_ nameHash: Hash256) -> Set<Hash256> {
        var result = Set<Hash256>()
        if let s = opens[nameHash] { result.formUnion(s) }
        if let s = bids[nameHash] { result.formUnion(s) }
        if let s = reveals[nameHash] { result.formUnion(s) }
        if let s = updates[nameHash] { result.formUnion(s) }
        return result
    }
}
