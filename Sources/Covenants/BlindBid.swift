import ExtCrypto

/// Blind bid operations for Fistbump name auctions.
///
/// During the bidding phase, users submit a blind hash that commits
/// to their bid value without revealing it. During the reveal phase,
/// the nonce is disclosed and the blind is verified.
public enum BlindBid {
    /// Compute the blind hash for a bid.
    ///
    /// `BLAKE2b-256( UInt64LE(value) || nonce[32] )`
    ///
    /// - Parameters:
    ///   - value: The bid value in bumps.
    ///   - nonce: A 32-byte random nonce.
    /// - Returns: The 32-byte blind hash.
    public static func blind(value: UInt64, nonce: BidNonce) throws -> [UInt8] {
        var data = [UInt8](repeating: 0, count: 40)
        // Write value as UInt64 little-endian
        data[0] = UInt8(value & 0xFF)
        data[1] = UInt8((value >> 8) & 0xFF)
        data[2] = UInt8((value >> 16) & 0xFF)
        data[3] = UInt8((value >> 24) & 0xFF)
        data[4] = UInt8((value >> 32) & 0xFF)
        data[5] = UInt8((value >> 40) & 0xFF)
        data[6] = UInt8((value >> 48) & 0xFF)
        data[7] = UInt8((value >> 56) & 0xFF)
        // Append nonce
        let nonceBytes = nonce.bytes
        for i in 0..<32 {
            data[8 + i] = nonceBytes[i]
        }
        return try Blake2bHash.hash(data, size: 32)
    }

    /// Verify that a reveal matches a previously submitted blind.
    ///
    /// - Parameters:
    ///   - blind: The 32-byte blind hash from the BID covenant.
    ///   - value: The revealed bid value.
    ///   - nonce: The revealed 32-byte nonce.
    /// - Returns: `true` if the blind matches.
    public static func verify(blind: [UInt8], value: UInt64, nonce: BidNonce) throws -> Bool {
        let computed = try Self.blind(value: value, nonce: nonce)
        return computed == blind
    }
}
