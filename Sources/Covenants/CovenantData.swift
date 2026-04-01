import Base
import Protocol

/// Typed accessors for covenant item data.
///
/// Each covenant type carries specific data items in a defined order.
/// This enum provides safe, typed extraction from the raw `[[UInt8]]` items.
public enum CovenantData {

    /// Extract the 32-byte name hash from item 0 (present in all name covenants).
    public static func nameHash(from covenant: Covenant) throws -> NameHash {
        guard !covenant.items.isEmpty, covenant.items[0].count == 32 else {
            throw CovenantsError.malformedCovenant("missing or invalid nameHash")
        }
        return NameHash(unchecked: covenant.items[0])
    }

    /// Extract the height (UInt32 LE) from item 1.
    public static func height(from covenant: Covenant) throws -> Int {
        guard covenant.items.count >= 2, covenant.items[1].count == 4 else {
            throw CovenantsError.malformedCovenant("missing or invalid height")
        }
        var reader = BufferReader(covenant.items[1])
        return Int(try reader.readUInt32LE())
    }

    /// Extract the raw name bytes from item 2 (OPEN, BID, FINALIZE).
    public static func rawName(from covenant: Covenant) throws -> [UInt8] {
        guard covenant.items.count >= 3 else {
            throw CovenantsError.malformedCovenant("missing rawName")
        }
        return covenant.items[2]
    }

    /// Extract the 32-byte blind hash from item 3 (BID).
    public static func blindHash(from covenant: Covenant) throws -> [UInt8] {
        guard covenant.items.count >= 4, covenant.items[3].count == 32 else {
            throw CovenantsError.malformedCovenant("missing or invalid blind hash")
        }
        return covenant.items[3]
    }

    /// Extract the 32-byte nonce from item 2 (REVEAL).
    public static func nonce(from covenant: Covenant) throws -> BidNonce {
        guard covenant.items.count >= 3, covenant.items[2].count == 32 else {
            throw CovenantsError.malformedCovenant("missing or invalid nonce")
        }
        return BidNonce(unchecked: covenant.items[2])
    }

    /// Extract the resource data from item 2 (REGISTER, UPDATE).
    public static func resource(from covenant: Covenant, itemIndex: Int = 2) throws -> [UInt8] {
        guard covenant.items.count > itemIndex else {
            throw CovenantsError.malformedCovenant("missing resource data")
        }
        return covenant.items[itemIndex]
    }

    /// Extract the 32-byte block hash from the specified item.
    public static func blockHash(from covenant: Covenant, itemIndex: Int) throws -> [UInt8] {
        guard covenant.items.count > itemIndex, covenant.items[itemIndex].count == 32 else {
            throw CovenantsError.malformedCovenant("missing or invalid block hash")
        }
        return covenant.items[itemIndex]
    }

    /// Extract the address version from item 2 (TRANSFER).
    public static func addressVersion(from covenant: Covenant) throws -> UInt8 {
        guard covenant.items.count >= 3, covenant.items[2].count == 1 else {
            throw CovenantsError.malformedCovenant("missing or invalid address version")
        }
        return covenant.items[2][0]
    }

    /// Extract the address hash from item 3 (TRANSFER).
    public static func addressHash(from covenant: Covenant) throws -> [UInt8] {
        guard covenant.items.count >= 4 else {
            throw CovenantsError.malformedCovenant("missing address hash")
        }
        let hash = covenant.items[3]
        guard hash.count >= 2, hash.count <= 40 else {
            throw CovenantsError.malformedCovenant("invalid address hash length")
        }
        return hash
    }

    // MARK: - Covenant Builders

    /// Build an OPEN covenant.
    public static func makeOpen(nameHash: NameHash, name: [UInt8]) -> Covenant {
        Covenant(type: .open, items: [
            nameHash.bytes,
            uint32LE(0),
            name,
        ])
    }

    /// Build a premium OPEN covenant with DNSSEC proof (4 items).
    public static func makePremiumOpen(nameHash: NameHash, name: [UInt8], dnssecProof: [UInt8]) -> Covenant {
        Covenant(type: .open, items: [
            nameHash.bytes,
            uint32LE(0),
            name,
            dnssecProof,
        ])
    }

    /// Build a BID covenant.
    public static func makeBid(nameHash: NameHash, startHeight: Int, name: [UInt8], blind: [UInt8]) -> Covenant {
        Covenant(type: .bid, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            name,
            blind,
        ])
    }

    /// Build a premium BID covenant with DNSSEC proof (5 items).
    public static func makePremiumBid(nameHash: NameHash, startHeight: Int, name: [UInt8], blind: [UInt8], dnssecProof: [UInt8]) -> Covenant {
        Covenant(type: .bid, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            name,
            blind,
            dnssecProof,
        ])
    }

    /// Build a REVEAL covenant.
    public static func makeReveal(nameHash: NameHash, startHeight: Int, nonce: BidNonce) -> Covenant {
        Covenant(type: .reveal, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            nonce.bytes,
        ])
    }

    /// Build a REDEEM covenant.
    public static func makeRedeem(nameHash: NameHash, startHeight: Int) -> Covenant {
        Covenant(type: .redeem, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
        ])
    }

    /// Build a REGISTER covenant.
    public static func makeRegister(nameHash: NameHash, startHeight: Int, resource: [UInt8], blockHash: [UInt8], flags: UInt8? = nil) -> Covenant {
        var items: [[UInt8]] = [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            resource,
            blockHash,
        ]
        if let f = flags {
            items.append([f])
        }
        return Covenant(type: .register, items: items)
    }

    /// Extract flags from a REGISTER covenant (item 4, optional).
    public static func registerFlags(from covenant: Covenant) -> UInt8? {
        guard covenant.type == .register, covenant.items.count >= 5,
              covenant.items[4].count == 1 else { return nil }
        return covenant.items[4][0]
    }

    /// Build an UPDATE covenant.
    public static func makeUpdate(nameHash: NameHash, startHeight: Int, resource: [UInt8]) -> Covenant {
        Covenant(type: .update, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            resource,
        ])
    }

    /// Build a RENEW covenant.
    public static func makeRenew(nameHash: NameHash, startHeight: Int, blockHash: [UInt8]) -> Covenant {
        Covenant(type: .renew, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            blockHash,
        ])
    }

    /// Build a TRANSFER covenant.
    public static func makeTransfer(nameHash: NameHash, startHeight: Int, version: UInt8, addressHash: [UInt8]) -> Covenant {
        Covenant(type: .transfer, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            [version],
            addressHash,
        ])
    }

    /// Build a FINALIZE covenant.
    public static func makeFinalize(
        nameHash: NameHash, startHeight: Int, name: [UInt8], flags: UInt8,
        claimed: Int, renewals: Int, blockHash: [UInt8]
    ) -> Covenant {
        Covenant(type: .finalize, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            name,
            [flags],
            uint32LE(UInt32(claimed)),
            uint32LE(UInt32(renewals)),
            blockHash,
        ])
    }

    /// Build a REVOKE covenant.
    public static func makeRevoke(nameHash: NameHash, startHeight: Int) -> Covenant {
        Covenant(type: .revoke, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
        ])
    }

    // MARK: - Subdomain Helpers

    /// Extract the 32-byte parent hash from an OPEN covenant (item 3 for subdomains).
    /// Returns nil if this is a regular TLD OPEN (no parent hash).
    public static func parentHash(fromOpen covenant: Covenant) -> NameHash? {
        // OPEN items: [nameHash, height, rawName, parentHash?, dnssecProof?]
        // A subdomain OPEN has parentHash at item 3 (32 bytes).
        // A premium TLD OPEN has dnssecProof at item 3 (variable length, != 32).
        guard covenant.items.count >= 4 else { return nil }
        let item3 = covenant.items[3]
        // Distinguish parentHash (always 32 bytes) from DNSSEC proof (variable)
        if item3.count == 32 {
            // Verify this is actually a subdomain by checking if the raw name has a dot
            let rawName = covenant.items[2]
            if rawName.contains(0x2E) {
                return NameHash(unchecked: item3)
            }
        }
        return nil
    }

    /// Extract the 32-byte parent hash from a BID covenant (item 4 for subdomains).
    /// Returns nil if this is a regular TLD BID.
    public static func parentHash(fromBid covenant: Covenant) -> NameHash? {
        // BID items: [nameHash, height, rawName, blind, parentHash?, dnssecProof?]
        guard covenant.items.count >= 5 else { return nil }
        let item4 = covenant.items[4]
        if item4.count == 32 {
            let rawName = covenant.items[2]
            if rawName.contains(0x2E) {
                return NameHash(unchecked: item4)
            }
        }
        return nil
    }

    /// Extract the flags byte from an UPDATE covenant (item 3, optional).
    public static func flags(from covenant: Covenant) -> UInt8? {
        guard covenant.items.count >= 4, covenant.items[3].count == 1 else { return nil }
        return covenant.items[3][0]
    }

    /// Build a subdomain OPEN covenant (with parent hash).
    public static func makeSubdomainOpen(nameHash: NameHash, name: [UInt8], parentHash: NameHash) -> Covenant {
        Covenant(type: .open, items: [
            nameHash.bytes,
            uint32LE(0),
            name,
            parentHash.bytes,
        ])
    }

    /// Build a subdomain BID covenant (with parent hash).
    public static func makeSubdomainBid(nameHash: NameHash, startHeight: Int, name: [UInt8], blind: [UInt8], parentHash: NameHash) -> Covenant {
        Covenant(type: .bid, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            name,
            blind,
            parentHash.bytes,
        ])
    }

    /// Build an UPDATE covenant with flags.
    public static func makeUpdate(nameHash: NameHash, startHeight: Int, resource: [UInt8], flags: UInt8) -> Covenant {
        Covenant(type: .update, items: [
            nameHash.bytes,
            uint32LE(UInt32(startHeight)),
            resource,
            [flags],
        ])
    }

    // MARK: - Helpers

    private static func uint32LE(_ val: UInt32) -> [UInt8] {
        var w = BufferWriter(capacity: 4)
        w.writeUInt32LE(val)
        return w.data
    }
}
