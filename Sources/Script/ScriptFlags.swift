/// Script verification flags for controlling interpreter behavior.
///
/// Handshake uses a simplified flag set compared to Bitcoin since
/// all transactions are witness-native.
public struct ScriptFlags: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// No flags.
    public static let none = ScriptFlags([])

    /// Require minimal data pushes (BIP 62 rule 3).
    public static let verifyMinimalData = ScriptFlags(rawValue: 1 << 1)

    /// Discourage use of upgradable NOP opcodes.
    public static let verifyDiscourageUpgradableNops = ScriptFlags(rawValue: 1 << 2)

    /// Discourage use of unknown witness program versions.
    public static let verifyDiscourageUpgradableWitnessProgram = ScriptFlags(rawValue: 1 << 3)

    /// Require minimal encoding for OP_IF/OP_NOTIF arguments.
    public static let verifyMinimalIf = ScriptFlags(rawValue: 1 << 4)

    /// Require empty signature on failed CHECKSIG/CHECKMULTISIG.
    public static let verifyNullFail = ScriptFlags(rawValue: 1 << 5)

    /// Mandatory flags: always enforced for consensus.
    public static let mandatory: ScriptFlags = [
        .verifyMinimalData,
        .verifyMinimalIf,
        .verifyNullFail,
    ]

    /// Standard flags: enforced for mempool acceptance.
    public static let standard: ScriptFlags = [
        .verifyMinimalData,
        .verifyMinimalIf,
        .verifyNullFail,
        .verifyDiscourageUpgradableNops,
        .verifyDiscourageUpgradableWitnessProgram,
    ]
}
