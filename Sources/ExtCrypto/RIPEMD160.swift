import Base

/// RIPEMD-160 hash function (needed for OP_HASH160 = RIPEMD160(SHA256(x))).
public enum RIPEMD160 {
    /// Compute the RIPEMD-160 hash (20 bytes) of the input data.
    public static func hash(_ data: [UInt8]) -> [UInt8] {
        var h0: UInt32 = 0x67452301
        var h1: UInt32 = 0xEFCDAB89
        var h2: UInt32 = 0x98BADCFE
        var h3: UInt32 = 0x10325476
        var h4: UInt32 = 0xC3D2E1F0

        // Pre-processing: pad to 512-bit blocks
        let bitLen = UInt64(data.count) * 8
        var msg = data
        msg.append(0x80)
        while msg.count % 64 != 56 {
            msg.append(0x00)
        }
        for i in 0..<8 {
            msg.append(UInt8((bitLen >> (i * 8)) & 0xFF))
        }

        // Process each 512-bit block
        var offset = 0
        while offset < msg.count {
            var x = [UInt32](repeating: 0, count: 16)
            for i in 0..<16 {
                let j = offset + i * 4
                x[i] = UInt32(msg[j])
                    | (UInt32(msg[j + 1]) << 8)
                    | (UInt32(msg[j + 2]) << 16)
                    | (UInt32(msg[j + 3]) << 24)
            }

            var al = h0, bl = h1, cl = h2, dl = h3, el = h4
            var ar = h0, br = h1, cr = h2, dr = h3, er = h4

            for j in 0..<80 {
                var fl: UInt32, fr: UInt32, kl: UInt32, kr: UInt32

                switch j {
                case 0..<16:
                    fl = bl ^ cl ^ dl
                    fr = br ^ (cr | ~dr)
                    kl = 0x00000000; kr = 0x50A28BE6
                case 16..<32:
                    fl = (bl & cl) | (~bl & dl)
                    fr = (br & dr) | (cr & ~dr)
                    kl = 0x5A827999; kr = 0x5C4DD124
                case 32..<48:
                    fl = (bl | ~cl) ^ dl
                    fr = (br | ~cr) ^ dr
                    kl = 0x6ED9EBA1; kr = 0x6D703EF3
                case 48..<64:
                    fl = (bl & dl) | (cl & ~dl)
                    fr = (br & cr) | (~br & dr)
                    kl = 0x8F1BBCDC; kr = 0x7A6D76E9
                default:
                    fl = bl ^ (cl | ~dl)
                    fr = br ^ cr ^ dr
                    kl = 0xA953FD4E; kr = 0x00000000
                }

                let tl = rotl(al &+ fl &+ x[rl[j]] &+ kl, sl[j]) &+ el
                al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl

                let tr = rotl(ar &+ fr &+ x[rr[j]] &+ kr, sr[j]) &+ er
                ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr
            }

            let t = h1 &+ cl &+ dr
            h1 = h2 &+ dl &+ er
            h2 = h3 &+ el &+ ar
            h3 = h4 &+ al &+ br
            h4 = h0 &+ bl &+ cr
            h0 = t

            offset += 64
        }

        var result = [UInt8](repeating: 0, count: 20)
        for (i, h) in [h0, h1, h2, h3, h4].enumerated() {
            result[i * 4 + 0] = UInt8(h & 0xFF)
            result[i * 4 + 1] = UInt8((h >> 8) & 0xFF)
            result[i * 4 + 2] = UInt8((h >> 16) & 0xFF)
            result[i * 4 + 3] = UInt8((h >> 24) & 0xFF)
        }
        return result
    }

    /// Compute HASH160 = RIPEMD160(SHA256(data)), returning a Hash160.
    public static func hash160(_ data: [UInt8]) -> Hash160 {
        let sha = SHA256Hash.hash(data)
        let ripe = hash(sha.bytes)
        return Hash160(unchecked: ripe)
    }

    // MARK: - Internal

    private static func rotl(_ x: UInt32, _ n: Int) -> UInt32 {
        (x << n) | (x >> (32 - n))
    }

    // Message word selection: left rounds
    private static let rl: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]

    // Message word selection: right rounds
    private static let rr: [Int] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]

    // Shift amounts: left rounds
    private static let sl: [Int] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]

    // Shift amounts: right rounds
    private static let sr: [Int] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]
}
