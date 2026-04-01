import Base

/// Block reward calculation with halving schedule.
public enum BlockReward {
    /// Maximum number of halvings before reward reaches zero.
    public static let maxHalvings = 52

    /// Compute the block subsidy (in bumps) for a given height.
    ///
    /// The reward starts at 500 FBC and halves every 1,051,200 blocks.
    /// After 52 halvings, the reward is zero.
    public static func getReward(height: Int, halvingInterval: Int = Constants.halvingInterval) -> Int64 {
        let halvings = height / halvingInterval
        guard halvings < maxHalvings else { return 0 }
        return Constants.baseReward >> halvings
    }

    /// Compute the total supply from mining up to (but not including) a given height.
    public static func totalMined(upTo height: Int, halvingInterval: Int = Constants.halvingInterval) -> Int64 {
        var total: Int64 = 0
        var h = 0
        var halving = 0

        while h < height && halving < maxHalvings {
            let reward = Constants.baseReward >> halving
            let nextHalving = (halving + 1) * halvingInterval
            let blocksInEra = min(height, nextHalving) - h
            total += reward * Int64(blocksInEra)
            h += blocksInEra
            halving += 1
        }
        return total
    }
}
