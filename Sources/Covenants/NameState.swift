import Base

/// The current state of a name auction.
public enum AuctionState: UInt8, Sendable {
    /// The name has been opened but the opening period hasn't ended.
    case opening = 0
    /// Bidding is active.
    case bidding = 1
    /// Reveal period is active.
    case reveal = 2
    /// The auction is closed; name is registered (or can be).
    case closed = 3
    /// The name has been revoked.
    case revoked = 4
}

/// The mutable state of a Fistbump name, stored in the Urkel trie.
///
/// Tracks the full lifecycle: opening, bidding, reveal, registration,
/// renewal, transfer, and revocation.
public struct NameState: Equatable, Sendable {
    /// The raw name bytes (ASCII, 1-63 bytes).
    public var name: [UInt8]

    /// The SHA3-256 hash of the name (32 bytes).
    public var nameHash: NameHash

    /// The block height at which the auction started (OPEN).
    public var height: Int

    /// The block height of the most recent renewal.
    public var renewal: Int

    /// The outpoint (txid + index) of the current owner's UTXO.
    public var owner: Outpoint?

    /// The winning bid value (in bumps).
    public var value: Int64

    /// The highest bid value seen during the auction.
    public var highest: Int64

    /// The DNS resource data.
    public var data: [UInt8]

    /// The block height at which a transfer was initiated (0 = none).
    public var transfer: Int

    /// The block height at which the name was revoked (0 = not revoked).
    public var revoked: Int

    /// The number of times the name has been renewed.
    public var renewals: Int

    /// Whether the name has been registered.
    public var registered: Bool

    /// Whether the name has expired.
    public var expired: Bool

    /// Name flags (bitmask). Bit 0 = auctionSubdomains.
    public var flags: UInt8

    /// Parent name hash for subdomains. Zero for TLDs.
    public var parentHash: NameHash

    /// Whether this name allows subdomains to be registered under it.
    public var auctionSubdomains: Bool {
        get { flags & 1 != 0 }
        set {
            if newValue { flags |= 1 } else { flags &= ~1 }
        }
    }

    /// An outpoint (transaction hash + output index).
    public struct Outpoint: Equatable, Sendable {
        public let hash: [UInt8]
        public let index: Int

        public init(hash: [UInt8], index: Int) {
            self.hash = hash
            self.index = index
        }
    }

    /// Create a new empty name state.
    public init(nameHash: NameHash = .zero, name: [UInt8] = []) {
        self.name = name
        self.nameHash = nameHash
        self.height = 0
        self.renewal = 0
        self.owner = nil
        self.value = 0
        self.highest = 0
        self.data = []
        self.transfer = 0
        self.revoked = 0
        self.renewals = 0
        self.registered = false
        self.expired = false
        self.flags = 0
        self.parentHash = .zero
    }

    /// Determine the auction state at a given block height.
    public func state(at height: Int, params: NameParams) -> AuctionState {
        if revoked != 0 {
            return .revoked
        }

        // Genesis-registered names: registered before auction could complete
        if registered {
            let revealEnd = self.height + params.openPeriod + params.biddingPeriod + params.revealPeriod
            if height < revealEnd {
                return .closed
            }
        }

        let openEnd = self.height + params.openPeriod
        if height < openEnd {
            return .opening
        }

        let bidEnd = openEnd + params.biddingPeriod
        if height < bidEnd {
            return .bidding
        }

        let revealEnd = bidEnd + params.revealPeriod
        if height < revealEnd {
            return .reveal
        }

        return .closed
    }

    /// The block height at which the register deadline expires.
    /// After this height, unregistered names expire and become available again.
    public func registerDeadlineHeight(params: NameParams) -> Int {
        let openEnd = self.height + params.openPeriod
        let bidEnd = openEnd + params.biddingPeriod
        let revealEnd = bidEnd + params.revealPeriod
        return revealEnd + params.registerDeadline
    }

    /// Check whether the name has expired at a given height.
    public func isExpired(at height: Int, params: NameParams) -> Bool {
        // Genesis-registered names never expire
        if registered && self.height == 0 && value == 0 {
            return false
        }

        if revoked != 0 {
            return height >= revoked + params.auctionMaturity
        }

        // Can only expire once we reach the closed state
        guard state(at: height, params: params) == .closed else { return false }

        // If we haven't been renewed in time, start over
        if height >= renewal + params.renewalWindow {
            return true
        }

        // If nobody revealed their bids, start over
        if owner == nil {
            return true
        }

        // If the winner hasn't registered by the deadline, start over
        if !registered && height > registerDeadlineHeight(params: params) {
            return true
        }

        return false
    }

    /// Compute the block height at which this name expires (or expired).
    /// Returns nil for genesis-registered names (never expire) or names with no owner and no deadline.
    public func expirationHeight(params: NameParams) -> Int? {
        // Genesis names never expire
        if registered && self.height == 0 && value == 0 {
            return nil
        }
        if revoked != 0 {
            return revoked + params.auctionMaturity
        }
        if registered {
            // Registered: expires if not renewed within the renewal window
            return renewal + params.renewalWindow
        }
        if owner != nil {
            // Won but not registered: expires at registration deadline
            return registerDeadlineHeight(params: params)
        }
        // No owner (nobody revealed): expires at end of reveal period
        let openEnd = self.height + params.openPeriod
        let bidEnd = openEnd + params.biddingPeriod
        let revealEnd = bidEnd + params.revealPeriod
        return revealEnd
    }

    /// If the name is expired, reset it and mark as expired.
    ///
    /// Matches hsd's `maybeExpire()`: resets the name state but preserves
    /// the data (for non-revoked names).
    @discardableResult
    public mutating func maybeExpire(at height: Int, params: NameParams) -> Bool {
        guard isExpired(at: height, params: params) else { return false }

        // Preserve data, flags, and subdomain linkage through reset
        let savedData = data
        let savedFlags = flags
        let savedParentHash = parentHash

        // Reset all fields
        self.height = height
        self.renewal = height
        self.owner = nil
        self.value = 0
        self.highest = 0
        self.data = []
        self.transfer = 0
        self.revoked = 0
        self.renewals = 0
        self.registered = false
        self.expired = false
        self.flags = 0

        // Mark as expired and restore preserved fields
        self.expired = true
        self.data = savedData
        self.flags = savedFlags
        self.parentHash = savedParentHash


        return true
    }

    /// Check whether the name is in the transfer lockup period.
    public func isTransferLocked(at height: Int, params: NameParams) -> Bool {
        guard transfer != 0 else { return false }
        return height < transfer + params.transferLockup
    }

    // MARK: - Serialization

    /// Serialize this name state to bytes for storage in the Urkel trie.
    public func serialize() -> [UInt8] {
        var out = [UInt8]()

        // Name
        out.append(UInt8(name.count))
        out.append(contentsOf: name)

        // Data
        out.append(UInt8(data.count & 0xFF))
        out.append(UInt8(data.count >> 8))
        out.append(contentsOf: data)

        // Height and renewal (u32 LE)
        appendUInt32LE(&out, UInt32(height))
        appendUInt32LE(&out, UInt32(renewal))

        // Bitfield
        var field: UInt8 = 0
        if owner != nil      { field |= 1 << 0 }
        if value != 0         { field |= 1 << 1 }
        if highest != 0       { field |= 1 << 2 }
        if transfer != 0      { field |= 1 << 3 }
        if revoked != 0       { field |= 1 << 4 }
        if renewals != 0      { field |= 1 << 5 }
        if registered         { field |= 1 << 6 }
        if expired            { field |= 1 << 7 }
        out.append(field)

        // Conditional fields
        if let o = owner {
            out.append(contentsOf: o.hash)
            appendVarint(&out, UInt64(o.index))
        }
        if value != 0 { appendVarint(&out, UInt64(value)) }
        if highest != 0 { appendVarint(&out, UInt64(highest)) }
        if transfer != 0 { appendUInt32LE(&out, UInt32(transfer)) }
        if revoked != 0 { appendUInt32LE(&out, UInt32(revoked)) }
        if renewals != 0 { appendVarint(&out, UInt64(renewals)) }

        // Extended fields (v2): flags and parentHash
        // Only written when non-default to keep TLD serialization compact.
        // When present, always write the parentHash length byte so future
        // fields can be appended unambiguously after the parentHash section.
        let hasParent = parentHash != .zero
        if flags != 0 || hasParent {
            out.append(flags)
            out.append(UInt8(hasParent ? parentHash.bytes.count : 0))
            if hasParent {
                out.append(contentsOf: parentHash.bytes)
            }
        }

        return out
    }

    /// Deserialize a name state from bytes.
    public static func deserialize(from data: [UInt8]) throws -> NameState {
        var pos = 0
        var ns = NameState()

        guard pos < data.count else { throw CovenantsError.malformedCovenant("empty data") }

        // Name
        let nameLen = Int(data[pos]); pos += 1
        guard pos + nameLen <= data.count else { throw CovenantsError.malformedCovenant("name truncated") }
        ns.name = Array(data[pos..<pos + nameLen]); pos += nameLen

        // Data
        guard pos + 2 <= data.count else { throw CovenantsError.malformedCovenant("data length truncated") }
        let dataLen = Int(data[pos]) | Int(data[pos + 1]) << 8; pos += 2
        guard pos + dataLen <= data.count else { throw CovenantsError.malformedCovenant("data truncated") }
        ns.data = Array(data[pos..<pos + dataLen]); pos += dataLen

        // Height and renewal
        guard pos + 8 <= data.count else { throw CovenantsError.malformedCovenant("height truncated") }
        ns.height = Int(readUInt32LE(data, pos)); pos += 4
        ns.renewal = Int(readUInt32LE(data, pos)); pos += 4

        // Bitfield
        guard pos < data.count else { throw CovenantsError.malformedCovenant("field truncated") }
        let field = data[pos]; pos += 1

        // Conditional fields
        if field & (1 << 0) != 0 {
            guard pos + 32 <= data.count else { throw CovenantsError.malformedCovenant("owner hash truncated") }
            let hash = Array(data[pos..<pos + 32]); pos += 32
            let (index, consumed) = try readVarint(data, pos)
            pos += consumed
            ns.owner = Outpoint(hash: hash, index: Int(index))
        }
        if field & (1 << 1) != 0 {
            let (v, c) = try readVarint(data, pos); pos += c
            ns.value = Int64(v)
        }
        if field & (1 << 2) != 0 {
            let (v, c) = try readVarint(data, pos); pos += c
            ns.highest = Int64(v)
        }
        if field & (1 << 3) != 0 {
            guard pos + 4 <= data.count else { throw CovenantsError.malformedCovenant("transfer truncated") }
            ns.transfer = Int(readUInt32LE(data, pos)); pos += 4
        }
        if field & (1 << 4) != 0 {
            guard pos + 4 <= data.count else { throw CovenantsError.malformedCovenant("revoked truncated") }
            ns.revoked = Int(readUInt32LE(data, pos)); pos += 4
        }
        if field & (1 << 5) != 0 {
            let (v, c) = try readVarint(data, pos); pos += c
            ns.renewals = Int(v)
        }
        ns.registered = field & (1 << 6) != 0
        ns.expired = field & (1 << 7) != 0

        // Extended fields (v2): flags and parentHash
        if pos < data.count {
            ns.flags = data[pos]; pos += 1
            if pos < data.count {
                let phLen = Int(data[pos]); pos += 1
                guard pos + phLen <= data.count else {
                    throw CovenantsError.malformedCovenant("parentHash truncated")
                }
                let phBytes = Array(data[pos..<pos + phLen]); pos += phLen
                if phLen == 32 {
                    ns.parentHash = NameHash(unchecked: phBytes)
                }
            }
        }

        return ns
    }

    // MARK: - Helpers

    private func appendUInt32LE(_ out: inout [UInt8], _ val: UInt32) {
        out.append(UInt8(val & 0xFF))
        out.append(UInt8((val >> 8) & 0xFF))
        out.append(UInt8((val >> 16) & 0xFF))
        out.append(UInt8((val >> 24) & 0xFF))
    }

    /// Append a Bitcoin CompactSize varint (matches hsd's bufio.writeVarint).
    private func appendVarint(_ out: inout [UInt8], _ val: UInt64) {
        if val < 0xFD {
            out.append(UInt8(val))
        } else if val <= 0xFFFF {
            out.append(0xFD)
            out.append(UInt8(val & 0xFF))
            out.append(UInt8((val >> 8) & 0xFF))
        } else if val <= 0xFFFFFFFF {
            out.append(0xFE)
            out.append(UInt8(val & 0xFF))
            out.append(UInt8((val >> 8) & 0xFF))
            out.append(UInt8((val >> 16) & 0xFF))
            out.append(UInt8((val >> 24) & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8(val & 0xFF))
            out.append(UInt8((val >> 8) & 0xFF))
            out.append(UInt8((val >> 16) & 0xFF))
            out.append(UInt8((val >> 24) & 0xFF))
            out.append(UInt8((val >> 32) & 0xFF))
            out.append(UInt8((val >> 40) & 0xFF))
            out.append(UInt8((val >> 48) & 0xFF))
            out.append(UInt8((val >> 56) & 0xFF))
        }
    }

    private static func readUInt32LE(_ data: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(data[offset])
        | UInt32(data[offset + 1]) << 8
        | UInt32(data[offset + 2]) << 16
        | UInt32(data[offset + 3]) << 24
    }

    /// Read a Bitcoin CompactSize varint (matches hsd's bufio.readVarint).
    private static func readVarint(_ data: [UInt8], _ offset: Int) throws -> (UInt64, Int) {
        guard offset < data.count else {
            throw CovenantsError.malformedCovenant("varint truncated")
        }
        let first = data[offset]
        if first < 0xFD {
            return (UInt64(first), 1)
        } else if first == 0xFD {
            guard offset + 3 <= data.count else {
                throw CovenantsError.malformedCovenant("varint truncated")
            }
            let val = UInt64(data[offset + 1]) | UInt64(data[offset + 2]) << 8
            return (val, 3)
        } else if first == 0xFE {
            guard offset + 5 <= data.count else {
                throw CovenantsError.malformedCovenant("varint truncated")
            }
            let val = UInt64(data[offset + 1])
                | UInt64(data[offset + 2]) << 8
                | UInt64(data[offset + 3]) << 16
                | UInt64(data[offset + 4]) << 24
            return (val, 5)
        } else {
            guard offset + 9 <= data.count else {
                throw CovenantsError.malformedCovenant("varint truncated")
            }
            let val = UInt64(data[offset + 1])
                | UInt64(data[offset + 2]) << 8
                | UInt64(data[offset + 3]) << 16
                | UInt64(data[offset + 4]) << 24
                | UInt64(data[offset + 5]) << 32
                | UInt64(data[offset + 6]) << 40
                | UInt64(data[offset + 7]) << 48
                | UInt64(data[offset + 8]) << 56
            return (val, 9)
        }
    }
}
