/// The type of a Fistbump name covenant operation.
///
/// Covenants encode the name auction state machine transitions.
/// Every transaction output carries a covenant (defaulting to `none`
/// for standard value transfers).
public enum CovenantType: UInt8, Sendable, CaseIterable {
    /// No covenant — standard value transfer.
    case none       = 0
    /// Open a name auction.
    case open       = 1
    /// Place a blind bid on a name.
    case bid        = 2
    /// Reveal a previously placed bid.
    case reveal     = 3
    /// Redeem a losing bid (reclaim coins).
    case redeem     = 4
    /// Register/win a name after the auction reveal period.
    case register   = 5
    /// Update a name's resource data (DNS records).
    case update     = 6
    /// Renew name ownership before expiry.
    case renew      = 7
    /// Initiate a name transfer to a new address.
    case transfer   = 8
    /// Finalize a pending name transfer.
    case finalize   = 9
    /// Revoke a name permanently (burn it).
    case revoke     = 10

    /// Whether this covenant type is name-related (not `none`).
    public var isName: Bool {
        self != .none
    }

    /// Whether this covenant output is linked to a name (REVEAL through REVOKE).
    ///
    /// Linked outputs must chain through a name's UTXO history.
    public var isLinked: Bool {
        rawValue >= CovenantType.reveal.rawValue && rawValue <= CovenantType.revoke.rawValue
    }

    /// Whether this covenant type allows dust-level values.
    public var isDustworthy: Bool {
        self == .none || self == .bid
    }

    /// Whether coins in this covenant are non-spendable (locked).
    public var isNonspendable: Bool {
        switch self {
        case .none, .open, .redeem:
            return false
        default:
            return true
        }
    }

    /// Whether this covenant permanently burns the output.
    public var isUnspendable: Bool {
        self == .revoke
    }

    /// Uppercase name for RPC/display (e.g. "OPEN", "BID").
    public var name: String {
        String(describing: self).uppercased()
    }
}
