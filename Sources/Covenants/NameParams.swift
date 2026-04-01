import Base
import Consensus

/// Network-specific name auction timing parameters.
///
/// All values are in blocks unless otherwise noted.
public struct NameParams: Sendable {
    /// Block height at which name auctions begin.
    public let auctionStart: Int

    /// Blocks between rollout waves (1 day of blocks).
    public let rolloutInterval: Int

    /// Tree commit interval (blocks between tree root updates).
    public let treeInterval: Int

    /// Number of blocks in the bidding period.
    public let biddingPeriod: Int

    /// Number of blocks in the reveal period.
    public let revealPeriod: Int

    /// Transfer lockup in blocks before FINALIZE is allowed.
    public let transferLockup: Int

    /// Renewal window in blocks (must renew within this period).
    public let renewalWindow: Int

    /// Renewal period (minimum blocks between renewals).
    public let renewalPeriod: Int

    /// Renewal maturity (blocks after registration before first renewal).
    public let renewalMaturity: Int

    /// Auction maturity (blocks after revoke before name can be re-auctioned).
    public let auctionMaturity: Int

    /// Whether name rollout is disabled (regtest).
    public let noRollout: Bool

    /// Number of blocks in the open period (between OPEN and bidding start).
    public let openPeriod: Int

    /// Number of blocks after the reveal period ends during which the winner
    /// must submit a REGISTER transaction. If the deadline passes without
    /// registration the name expires and becomes available again.
    public let registerDeadline: Int

    /// Renewal fee as a percentage (0–100) of the original registration value.
    /// The fee is paid to the dev fund address on each RENEW transaction.
    public let renewalFeePercent: Int

    /// Minimum bid numerator for premium TLD auctions (reward × num / den).
    public let premiumTldMinBidNumerator: Int64

    /// Minimum bid denominator for premium TLD auctions.
    public let premiumTldMinBidDenominator: Int64

    /// Minimum bid numerator for non-premium TLD auctions (reward × num / den).
    public let tldMinBidNumerator: Int64

    /// Minimum bid denominator for non-premium TLD auctions.
    public let tldMinBidDenominator: Int64

    /// Minimum bid numerator for sub-TLD auctions (reward × num / den).
    public let subMinBidNumerator: Int64

    /// Minimum bid denominator for sub-TLD auctions.
    public let subMinBidDenominator: Int64

    /// Registration fee burn percentage (0–100).
    /// This portion of the registration value is burned (unspendable).
    /// The remainder goes to the dev fund.
    public let registrationBurnPercent: Int

    /// Whether premium names require DNSSEC proof of ICANN domain ownership.
    public let requireDNSSEC: Bool

    /// Grace period in seconds for RRSIG temporal validity checks.
    /// Allows proofs slightly before inception or after expiration.
    public let dnssecGracePeriod: UInt32

    /// Qualifying ICANN TLDs for premium name DNSSEC proofs.
    public static let qualifyingTLDs: Set<String> = [
        "com", "net", "org", "gov", "io", "app", "dev", "xyz"
    ]

    /// Compute the minimum bid for a name at a given block height.
    ///
    /// Three tiers: premium TLDs (short names requiring DNSSEC), regular TLDs,
    /// and sub-TLD names. All halve with the block reward.
    public func minimumBid(atHeight height: Int, name: String, halvingInterval: Int = Constants.halvingInterval) -> Int64 {
        let numerator: Int64
        let denominator: Int64
        if NameRules.isSubdomain(name) {
            numerator = subMinBidNumerator; denominator = subMinBidDenominator
        } else if NameRules.isPremium(name) {
            numerator = premiumTldMinBidNumerator; denominator = premiumTldMinBidDenominator
        } else {
            numerator = tldMinBidNumerator; denominator = tldMinBidDenominator
        }
        guard denominator != 0 else { return 0 }
        let reward = BlockReward.getReward(height: height, halvingInterval: halvingInterval)
        return Int64(reward) * numerator / denominator
    }

    /// Compute the minimum bid from raw name bytes at a given block height.
    public func minimumBid(atHeight height: Int, rawName: [UInt8], halvingInterval: Int = Constants.halvingInterval) -> Int64 {
        let numerator: Int64
        let denominator: Int64
        if NameRules.isSubdomain(rawName: rawName) {
            numerator = subMinBidNumerator; denominator = subMinBidDenominator
        } else if NameRules.isPremium(rawName: rawName) {
            numerator = premiumTldMinBidNumerator; denominator = premiumTldMinBidDenominator
        } else {
            numerator = tldMinBidNumerator; denominator = tldMinBidDenominator
        }
        guard denominator != 0 else { return 0 }
        let reward = BlockReward.getReward(height: height, halvingInterval: halvingInterval)
        return Int64(reward) * numerator / denominator
    }

    /// Get the name parameters for a given network type.
    public static func params(for network: NetworkType) -> NameParams {
        switch network {
        case .main:    return .mainnet
        case .testnet: return .testnet
        case .regtest, .simnet: return .regtest
        }
    }

    // MARK: - Presets

    /// Mainnet name parameters (2-min blocks).
    ///
    /// Auction cycle (7 days total = 5,040 blocks):
    ///   Open:     1 hour  =    30 blocks
    ///   Bid:      3 days  = 2,160 blocks
    ///   Reveal:   1 day   =   720 blocks
    ///   Register: 71 hrs  = 2,130 blocks
    ///
    /// Rollout: 60 days, 720 blocks/day (1 batch per day).
    public static let mainnet = NameParams(
        auctionStart: 10_080,
        rolloutInterval: 720,
        treeInterval: 30,
        biddingPeriod: 2_160,
        revealPeriod: 720,
        transferLockup: 360,
        renewalWindow: 262_800,
        renewalPeriod: 131_040,
        renewalMaturity: 21_600,
        auctionMaturity: 5_040,

        noRollout: false,
        openPeriod: 30,
        registerDeadline: 2_130,
        renewalFeePercent: 1,
        premiumTldMinBidNumerator: 100, premiumTldMinBidDenominator: 1,
        tldMinBidNumerator: 20, tldMinBidDenominator: 1,
        subMinBidNumerator: 1, subMinBidDenominator: 5,
        registrationBurnPercent: 50,
        requireDNSSEC: true,
        dnssecGracePeriod: 3_600
    )

    /// Testnet name parameters (24x faster: 1 hour = 1 mainnet day, 100x lower min bids).
    public static let testnet = NameParams(
        auctionStart: 420,        // 10,080 / 24
        rolloutInterval: 30,      // 720 / 24
        treeInterval: 30,
        biddingPeriod: 90,        // 2,160 / 24
        revealPeriod: 30,         // 720 / 24
        transferLockup: 15,       // 360 / 24
        renewalWindow: 10_950,    // 262,800 / 24
        renewalPeriod: 5_460,     // 131,040 / 24
        renewalMaturity: 900,     // 21,600 / 24
        auctionMaturity: 210,     // 5,040 / 24

        noRollout: false,
        openPeriod: 1,            // 30 / 24 → 1 block minimum
        registerDeadline: 89,     // 2,130 / 24
        renewalFeePercent: 1,
        premiumTldMinBidNumerator: 1, premiumTldMinBidDenominator: 1,     // 100x lower
        tldMinBidNumerator: 1, tldMinBidDenominator: 5,                 // 100x lower
        subMinBidNumerator: 1, subMinBidDenominator: 500,               // 100x lower
        registrationBurnPercent: 50,
        requireDNSSEC: true,
        dnssecGracePeriod: 3_600
    )

    /// Regtest name parameters (relaxed for testing).
    public static let regtest = NameParams(
        auctionStart: 0,
        rolloutInterval: 2,
        treeInterval: 5,
        biddingPeriod: 10,
        revealPeriod: 20,
        transferLockup: 5,
        renewalWindow: 200,
        renewalPeriod: 50,
        renewalMaturity: 10,
        auctionMaturity: 50,

        noRollout: true,
        openPeriod: 6,
        registerDeadline: 20,
        renewalFeePercent: 1,
        premiumTldMinBidNumerator: 0, premiumTldMinBidDenominator: 1,
        tldMinBidNumerator: 0, tldMinBidDenominator: 1,
        subMinBidNumerator: 0, subMinBidDenominator: 1,
        registrationBurnPercent: 50,
        requireDNSSEC: false,
        dnssecGracePeriod: 86_400
    )
}
