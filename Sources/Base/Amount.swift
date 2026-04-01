/// An FBC amount in bumps (the base unit).
///
/// 1 FBC = 1,000,000 bumps. Amounts are stored as `Int64` to match
/// the wire format and to naturally express negative values in fee calculations.
public struct Amount: Hashable, Comparable, Sendable {
    /// The raw value in bumps.
    public let bumps: Int64

    /// Number of bumps per FBC coin.
    public static let coinValue: Int64 = 1_000_000

    /// Maximum total supply in bumps (~1.05 billion FBC).
    public static let maxMoney: Int64 = 1_051_200_000 * coinValue

    /// Zero amount.
    public static let zero = Amount(unchecked: 0)

    /// Create an amount from raw bumps.
    ///
    /// - Throws: `BaseError.invalidAmount` if outside valid range.
    public init(_ bumps: Int64) throws {
        guard bumps >= 0, bumps <= Amount.maxMoney else {
            throw BaseError.invalidAmount(bumps)
        }
        self.bumps = bumps
    }

    /// Internal initializer that skips validation (for known-good values).
    init(unchecked bumps: Int64) {
        self.bumps = bumps
    }

    /// Create an amount from whole FBC coins.
    public static func coins(_ fbc: Int64) throws -> Amount {
        try Amount(fbc * coinValue)
    }

    /// The value expressed in FBC (may lose precision for sub-coin amounts).
    public var fbc: Double {
        Double(bumps) / Double(Amount.coinValue)
    }

    // MARK: - Comparable

    public static func < (lhs: Amount, rhs: Amount) -> Bool {
        lhs.bumps < rhs.bumps
    }

    // MARK: - Arithmetic

    /// Add two amounts. Result is unchecked (caller must validate).
    public static func + (lhs: Amount, rhs: Amount) -> Amount {
        Amount(unchecked: lhs.bumps + rhs.bumps)
    }

    /// Subtract two amounts. Result is unchecked (may be negative for fees).
    public static func - (lhs: Amount, rhs: Amount) -> Amount {
        Amount(unchecked: lhs.bumps - rhs.bumps)
    }
}

extension Amount: CustomStringConvertible {
    public var description: String {
        "\(bumps) bumps"
    }
}
