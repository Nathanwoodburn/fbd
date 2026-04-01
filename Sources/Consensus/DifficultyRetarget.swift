/// Fistbump difficulty adjustment algorithm.
///
/// Uses a work-based retargeting approach over a configurable window
/// (72 blocks on mainnet). The algorithm estimates the network hashrate
/// from the actual chainwork and elapsed time, then derives a new target.
///
/// Key differences from Bitcoin:
/// - Uses chainwork (not just timestamps) for retargeting
/// - Median-of-3 block selection at window endpoints to resist timestamp manipulation
/// - Retargets every block (not every 2016 blocks)
/// - 1/4x to 4x clamping on actual timespan
///
/// Security: the target is clamped to powLimit, and actualTimespan is bounded
/// by [minActualTimespan, maxActualTimespan] to prevent extreme difficulty swings.
public enum DifficultyRetarget {

    /// Information about a block needed for difficulty calculation.
    public struct BlockInfo {
        /// The block timestamp.
        public let time: UInt64
        /// The cumulative chainwork up to and including this block.
        public let chainwork: Target256

        public init(time: UInt64, chainwork: Target256) {
            self.time = time
            self.chainwork = chainwork
        }
    }

    /// Compute the new target (as compact nBits) for the next block.
    ///
    /// - Parameters:
    ///   - first: The "suitable block" at the start of the window (median-of-3 selected).
    ///   - last: The "suitable block" at the end of the window (median-of-3 selected).
    ///   - params: Consensus parameters.
    /// - Returns: The compact target (nBits) for the next block.
    public static func retarget(first: BlockInfo, last: BlockInfo, params: ConsensusParams) -> UInt32 {
        // Total work over the window, scaled by target spacing
        let workDiff = last.chainwork - first.chainwork
        let work = workDiff.multiplied(by: UInt64(params.targetSpacing))

        // Actual elapsed time, clamped
        var actualTimespan = Int64(last.time) - Int64(first.time)
        let minTime = Int64(params.minActualTimespan)
        let maxTime = Int64(params.maxActualTimespan)
        actualTimespan = max(actualTimespan, minTime)
        actualTimespan = min(actualTimespan, maxTime)

        // Estimated hashrate = work / actualTimespan
        let (hashrate, _) = work.dividedBy(UInt64(actualTimespan))

        if hashrate.isZero {
            return params.powBits
        }

        // target = floor(2^256 / hashrate) - 1  (matches hsd's MAX_CHAINWORK.div(work).isubn(1))
        let target = hashrate.inversePow2_256() - .one

        if target > params.powLimit {
            return params.powBits
        }

        return target.toCompact()
    }

    /// Select the "suitable block" from three consecutive blocks by median timestamp.
    ///
    /// This picks the block with the median time from `(prev, prev-1, prev-2)`,
    /// which resists timestamp manipulation.
    public static func getSuitableBlock(
        _ block: BlockInfo,
        _ parent: BlockInfo,
        _ grandparent: BlockInfo
    ) -> BlockInfo {
        var x = grandparent
        var y = parent
        var z = block
        // Sort by time (bubble sort to get median)
        if x.time > z.time { swap(&x, &z) }
        if x.time > y.time { swap(&x, &y) }
        if y.time > z.time { swap(&y, &z) }
        return y // median
    }

    /// Compute the work (number of hashes) for a given compact target.
    ///
    /// `work = floor(2^256 / (target + 1))`
    public static func targetToWork(_ bits: UInt32) -> Target256 {
        let target = Target256.fromCompact(bits)
        if target.isZero { return .zero }
        let targetPlusOne = target + .one
        return targetPlusOne.inversePow2_256()
    }
}
