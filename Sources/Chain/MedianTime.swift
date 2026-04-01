/// Median time past calculation.
///
/// Computes the median of the timestamps of the previous N blocks
/// (default 11). This is used to enforce that block timestamps
/// are monotonically increasing in a manipulation-resistant way.
public enum MedianTime {
    /// Default number of blocks to consider for median time past.
    public static let defaultSpan = 11

    /// Compute the median time past from a list of timestamps.
    ///
    /// The timestamps should be from the most recent blocks in
    /// reverse chronological order (newest first). At most `span`
    /// timestamps are considered.
    ///
    /// - Parameters:
    ///   - timestamps: Block timestamps (newest first).
    ///   - span: Number of timestamps to consider (default 11).
    /// - Returns: The median timestamp value.
    public static func compute(_ timestamps: [UInt64], span: Int = defaultSpan) -> UInt64 {
        guard !timestamps.isEmpty else { return 0 }

        let count = min(timestamps.count, span)
        let relevant = Array(timestamps.prefix(count))
        let sorted = relevant.sorted()

        // Return the middle element
        return sorted[count / 2]
    }

    /// Compute the median time past from an array of chain entries'
    /// timestamps (newest first).
    ///
    /// This is the standard Bitcoin/Fistbump MTP calculation:
    /// collect the previous 11 timestamps, sort, return the middle.
    public static func fromTimestamps(_ times: [UInt64]) -> UInt64 {
        compute(times, span: defaultSpan)
    }
}
