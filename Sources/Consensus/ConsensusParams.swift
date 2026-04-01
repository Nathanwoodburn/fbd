import Base

/// Network-specific consensus parameters.
public struct ConsensusParams: Sendable {
    /// Target block interval in seconds.
    public let targetSpacing: Int

    /// Number of blocks in the difficulty adjustment window.
    public let targetWindow: Int

    /// Halving interval in blocks.
    public let halvingInterval: Int

    /// Coinbase maturity (confirmations before spendable).
    public let coinbaseMaturity: Int

    /// Minimum difficulty target (easiest difficulty).
    public let powLimit: Target256

    /// Genesis block compact bits.
    public let powBits: UInt32

    /// Whether difficulty retargeting is disabled (regtest).
    public let noRetargeting: Bool

    /// Maximum allowed future block time offset (seconds).
    public let maxFutureBlockTime: Int

    /// Number of blocks for median time past calculation.
    public let medianTimeSpan: Int

    /// Maximum number of name opens per block.
    public let maxBlockOpens: Int

    /// Maximum number of name updates per block.
    public let maxBlockUpdates: Int

    /// Maximum number of name renewals per block.
    public let maxBlockRenewals: Int

    /// Height up to which script verification is skipped during initial sync.
    /// Set to 0 to disable (verify everything).
    public let assumeValidHeight: Int

    /// Number of blocks in a BIP9 miner signaling window.
    public let minerWindow: Int

    /// Number of signaling blocks required for activation within a window.
    public let activationThreshold: Int

    /// BIP9 soft fork deployments for this network.
    public let deployments: [Deployment]

    /// Number of 32-byte slots for BalloonHash PoW (controls memory usage).
    /// Mainnet/testnet: 16777216 (512 MB), regtest/simnet: 4 (trivial) for fast tests.
    public let balloonSlots: Int

    /// Number of BalloonHash mixing rounds.
    /// Fewer rounds with a larger scratchpad keeps total work balanced.
    public let balloonRounds: Int

    /// Number of pseudorandom neighbors per slot per mixing round.
    public let balloonDelta: Int

    /// Dev fund address hash (20-byte BLAKE2b-160) for premium name registration fees.
    public let devFundAddress: [UInt8]

    /// Dev fund address version (0 for P2WPKH).
    public let devFundVersion: UInt8

    /// Minimum clamped timespan for retarget (targetWindow / 4 * targetSpacing).
    public var minActualTimespan: Int { targetWindow / 4 * targetSpacing }

    /// Maximum clamped timespan for retarget (targetWindow * 4 * targetSpacing).
    public var maxActualTimespan: Int { targetWindow * 4 * targetSpacing }

    /// Target timespan for the adjustment window.
    public var targetTimespan: Int { targetWindow * targetSpacing }

    // MARK: - Standard Deployments

    /// Test dummy deployment (used in tests).
    public static let testDummyDeployment = Deployment(
        name: "testdummy", bit: 28,
        startTime: 1_199_145_601,
        timeout: 1_230_767_999
    )

    /// All standard deployments (FBD has no FBD-specific deployments).
    public static let standardDeployments: [Deployment] = [
        testDummyDeployment,
    ]

    // MARK: - Presets

    /// Mainnet consensus parameters.
    public static let mainnet = ConsensusParams(
        targetSpacing: 120,
        targetWindow: 72,
        halvingInterval: 1_051_200,
        coinbaseMaturity: 100,
        powLimit: Target256.fromCompact(0x200fffff),
        powBits: 0x200fffff,
        noRetargeting: false,
        maxFutureBlockTime: 2 * 60 * 60,
        medianTimeSpan: 11,
        maxBlockOpens: 300,
        maxBlockUpdates: 600,
        maxBlockRenewals: 600,
        assumeValidHeight: 0,
        minerWindow: 2016,
        activationThreshold: 1916,
        deployments: standardDeployments,
        balloonSlots: 16_777_216,
        balloonRounds: 1,
        balloonDelta: 1,
        // Dev fund address: fb1qqfsfc6x3zrvgddt59m77a3sryjzrgpc5pafqzg
        // Fallback used until _devfund.fistbump WALLET record is set on-chain.
        devFundAddress: [
            0x02, 0x60, 0x9c, 0x68, 0xd1, 0x10, 0xd8, 0x86, 0xb5, 0x74,
            0x2e, 0xfd, 0xee, 0xc6, 0x03, 0x24, 0x84, 0x34, 0x07, 0x14
        ],
        devFundVersion: 0
    )

    /// Testnet consensus parameters.
    public static let testnet = ConsensusParams(
        targetSpacing: 120,
        targetWindow: 72,
        halvingInterval: 1_051_200,
        coinbaseMaturity: 5,
        powLimit: Target256.fromCompact(0x200fffff),
        powBits: 0x200fffff,
        noRetargeting: false,
        maxFutureBlockTime: 2 * 60 * 60,
        medianTimeSpan: 11,
        maxBlockOpens: 300,
        maxBlockUpdates: 600,
        maxBlockRenewals: 600,
        assumeValidHeight: 0,
        minerWindow: 2016,
        activationThreshold: 1512,
        deployments: standardDeployments,
        balloonSlots: 16_777_216,
        balloonRounds: 1,
        balloonDelta: 1,
        // Dev fund address: ft1qqfsfc6x3zrvgddt59m77a3sryjzrgpc5ud68sa
        devFundAddress: [
            0x02, 0x60, 0x9c, 0x68, 0xd1, 0x10, 0xd8, 0x86, 0xb5, 0x74,
            0x2e, 0xfd, 0xee, 0xc6, 0x03, 0x24, 0x84, 0x34, 0x07, 0x14
        ],
        devFundVersion: 0
    )

    /// Regtest consensus parameters (no retargeting, easy PoW).
    public static let regtest = ConsensusParams(
        targetSpacing: 120,
        targetWindow: 72,
        halvingInterval: 1_051_200,
        coinbaseMaturity: 2,
        powLimit: Target256.fromCompact(0x207fffff),
        powBits: 0x207fffff,
        noRetargeting: true,
        maxFutureBlockTime: 2 * 60 * 60,
        medianTimeSpan: 11,
        maxBlockOpens: 300,
        maxBlockUpdates: 600,
        maxBlockRenewals: 600,
        assumeValidHeight: 0,
        minerWindow: 144,
        activationThreshold: 108,
        deployments: standardDeployments,
        balloonSlots: 4,
        balloonRounds: 1,
        balloonDelta: 1,
        // Regtest dev fund: all zeros (any address works for testing)
        devFundAddress: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14
        ],
        devFundVersion: 0
    )

    /// Simnet consensus parameters (same as regtest but different BIP9 thresholds).
    public static let simnet = ConsensusParams(
        targetSpacing: 120,
        targetWindow: 72,
        halvingInterval: 1_051_200,
        coinbaseMaturity: 2,
        powLimit: Target256.fromCompact(0x207fffff),
        powBits: 0x207fffff,
        noRetargeting: true,
        maxFutureBlockTime: 2 * 60 * 60,
        medianTimeSpan: 11,
        maxBlockOpens: 300,
        maxBlockUpdates: 600,
        maxBlockRenewals: 600,
        assumeValidHeight: 0,
        minerWindow: 144,
        activationThreshold: 75,
        deployments: standardDeployments,
        balloonSlots: 4,
        balloonRounds: 1,
        balloonDelta: 1,
        devFundAddress: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14
        ],
        devFundVersion: 0
    )

    /// Get the consensus parameters for a given network type.
    public static func params(for network: NetworkType) -> ConsensusParams {
        switch network {
        case .main:    return .mainnet
        case .testnet: return .testnet
        case .regtest: return .regtest
        case .simnet:  return .simnet
        }
    }
}
