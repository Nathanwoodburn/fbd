import Base
import ExtCrypto

/// Name validation, hashing, and rollout rules.
public enum NameRules {

    /// Maximum label length in bytes (each part between dots).
    public static let maxLabelSize = 63

    /// Maximum total name length in bytes (DNS limit).
    public static let maxNameSize = 253

    /// Maximum UTF-8 byte length for premium names (requires DNSSEC proof).
    public static let premiumNameMaxLength = 6

    /// Check if a name is premium (TLD short enough to require DNSSEC proof).
    /// Only TLDs can be premium — SLDs are never premium.
    public static func isPremium(_ name: String) -> Bool {
        guard !isSubdomain(name) else { return false }
        let len = Array(name.utf8).count
        return len >= 1 && len <= premiumNameMaxLength
    }

    /// Check if raw name bytes qualify as premium.
    /// Only TLDs can be premium — SLDs are never premium.
    public static func isPremium(rawName: [UInt8]) -> Bool {
        guard !isSubdomain(rawName: rawName) else { return false }
        return rawName.count >= 1 && rawName.count <= premiumNameMaxLength
    }

    /// Maximum resource data size in bytes.
    public static let maxResourceSize = 512

    // Character type table (ASCII 0-127).
    // 0 = invalid, 1 = digit, 2 = uppercase (rejected), 3 = lowercase, 4 = hyphen, 5 = dot
    private static let charset: [UInt8] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0-15
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16-31
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5, 0, // 32-47 (45='-', 46='.')
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 48-63 (48-57='0'-'9')
        0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 64-79 (65-90='A'-'Z')
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, // 80-95 (95='_' now invalid)
        0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 96-111 (97-122='a'-'z')
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, // 112-127
    ]

    /// Names that are permanently blacklisted (IANA special-use + Tor).
    public static let blacklist: Set<String> = [
        "example", "invalid", "local", "localhost", "onion", "test"
    ]

    /// Validate a Fistbump name (TLD or subdomain).
    ///
    /// Rules:
    /// - 1-253 bytes total, ASCII only
    /// - Each label (part between dots) must be 1-63 bytes
    /// - Lowercase letters, digits, hyphens
    /// - Dots allowed as label separators for subdomains
    /// - Hyphens and dots cannot be first or last character
    /// - No consecutive dots, no dot-adjacent hyphens
    /// - TLD part (last label) must not be in the blacklist
    public static func verifyName(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard !bytes.isEmpty, bytes.count <= maxNameSize else { return false }

        var prevDot = true // treat start of string like after a dot to catch leading separators
        var labelLen = 0
        for (i, byte) in bytes.enumerated() {
            guard byte < 128 else { return false }
            let type = charset[Int(byte)]
            switch type {
            case 0: return false          // Invalid
            case 1: prevDot = false; labelLen += 1  // Digit OK
            case 2: return false          // Uppercase rejected
            case 3: prevDot = false; labelLen += 1  // Lowercase OK
            case 4:                       // Hyphen
                if i == 0 || i == bytes.count - 1 { return false }
                prevDot = false; labelLen += 1
            case 5:                       // Dot (subdomain separator)
                if i == 0 || i == bytes.count - 1 { return false }
                if prevDot { return false } // consecutive dots or leading dot
                if labelLen > maxLabelSize { return false }
                prevDot = true; labelLen = 0
            default: return false
            }
        }

        // Check final label length
        if labelLen > maxLabelSize { return false }

        // TLD (last label) must not be blacklisted
        let tld = tldLabel(name)
        return !blacklist.contains(tld)
    }

    /// Whether a name is a subdomain (contains at least one dot).
    public static func isSubdomain(_ name: String) -> Bool {
        name.contains(".")
    }

    /// Whether raw name bytes represent a subdomain.
    public static func isSubdomain(rawName: [UInt8]) -> Bool {
        rawName.contains(0x2E) // '.'
    }

    /// Extract the TLD label (rightmost component) from a name.
    /// "shop.co.uk" → "uk", "alice" → "alice"
    public static func tldLabel(_ name: String) -> String {
        if let dotIdx = name.lastIndex(of: ".") {
            return String(name[name.index(after: dotIdx)...])
        }
        return name
    }

    /// Extract the direct parent name from a subdomain.
    /// "shop.co.uk" → "co.uk", "co.uk" → "uk"
    /// Returns nil if the name is a TLD (no dots).
    public static func parentName(_ name: String) -> String? {
        guard let dotIdx = name.firstIndex(of: ".") else { return nil }
        return String(name[name.index(after: dotIdx)...])
    }

    /// Extract the direct parent name from raw name bytes.
    public static func parentName(rawName: [UInt8]) -> [UInt8]? {
        guard let dotIdx = rawName.firstIndex(of: 0x2E) else { return nil }
        return Array(rawName[(dotIdx + 1)...])
    }

    /// Collect all ancestor name hashes for a subdomain, from direct parent up to the TLD.
    /// "shop.co.uk" → [hash("co.uk"), hash("uk")]
    public static func ancestorHashes(_ name: String) -> [NameHash] {
        var ancestors: [NameHash] = []
        var current = name
        while let parent = parentName(current) {
            ancestors.append(hashName(parent))
            current = parent
        }
        return ancestors
    }

    /// Count the depth of a name (number of dots). TLD = 0, "co.uk" = 1, "shop.co.uk" = 2.
    public static func depth(_ name: String) -> Int {
        name.filter { $0 == "." }.count
    }

    /// Check if a name is an ICANN reserved TLD.
    ///
    /// ICANN reserved names require DNSSEC proof to open/bid (same as premium names)
    /// and revert to reserved status on expiration.
    public static func isICANNReserved(_ name: String) -> Bool {
        ICANNReserved.tlds.contains(name)
    }

    /// Check if a name requires DNSSEC proof (premium or ICANN reserved).
    public static func requiresDNSSEC(_ name: String) -> Bool {
        isPremium(name) || isICANNReserved(name)
    }

    /// Check if raw name bytes require DNSSEC proof.
    public static func requiresDNSSEC(rawName: [UInt8]) -> Bool {
        if isPremium(rawName: rawName) { return true }
        guard let name = String(bytes: rawName, encoding: .utf8) else { return false }
        return isICANNReserved(name)
    }

    // MARK: - Resource Validation

    /// Check if resource data contains delegation or subdomain records that
    /// conflict with on-chain subdomain auctions.
    ///
    /// When `auctionSubdomains` is enabled, delegation records are forbidden because
    /// the on-chain name system handles subdomain resolution — external nameservers
    /// would conflict with child subdomain names. SUB records are also forbidden
    /// because they could shadow subdomains purchased through auctions.
    ///
    /// Allowed: A, AAAA, TXT, CNAME, MX, TLSA, CAA (root name records).
    /// Blocked: DS(0), NS(1), GLUE4(2), GLUE6(3), SYNTH4(4), SYNTH6(5), SUB(13).
    public static func containsDelegationRecords(_ data: [UInt8]) -> Bool {
        guard !data.isEmpty else { return false }
        var pos = 0
        guard data[pos] == 0 else { return false } // version
        pos += 1

        while pos < data.count {
            let recordType = data[pos]; pos += 1

            // Record types 0-5 are delegation: DS, NS, GLUE4, GLUE6, SYNTH4, SYNTH6
            // Record type 13 is SUB: would shadow auctioned subdomains
            if recordType <= 5 || recordType == 13 { return true }

            // Skip past non-delegation record data to find the next record
            switch recordType {
            case 6: // TXT: count(1) + count*(len(1) + data(N))
                guard pos < data.count else { return true }
                let count = Int(data[pos]); pos += 1
                for _ in 0..<count {
                    guard pos < data.count else { return true }
                    let len = Int(data[pos]); pos += 1
                    pos += len
                }
            case 7:  pos += 4   // A: 4 bytes
            case 8:  pos += 16  // AAAA: 16 bytes
            case 9:              // CNAME: DNS name
                pos = skipDNSName(data, pos)
                guard pos <= data.count else { return true }
            case 10:             // MX: preference(2) + DNS name
                pos += 2
                pos = skipDNSName(data, pos)
                guard pos <= data.count else { return true }
            case 11:             // TLSA: port(2 BE) + proto(1) + usage(1) + selector(1) + matchingType(1) + certLen(2 BE) + cert(N)
                guard pos + 8 <= data.count else { return true }
                let certLen = Int(data[pos + 6]) << 8 | Int(data[pos + 7])
                pos += 8 + certLen
            case 12:             // CAA: flags(1) + tagLen(1) + tag(N) + valueLen(2 BE) + value(N)
                guard pos + 2 <= data.count else { return true }
                let tagLen = Int(data[pos + 1])
                pos += 2 + tagLen
                guard pos + 2 <= data.count else { return true }
                let valueLen = Int(data[pos]) << 8 | Int(data[pos + 1])
                pos += 2 + valueLen
            case 14:             // WALLET: len(1) + address(N)
                guard pos < data.count else { return true }
                let len = Int(data[pos]); pos += 1
                pos += len
            default:
                return true // Unknown record type — conservatively treat as delegation
            }
        }
        return false
    }

    /// Skip past a DNS-encoded name in resource data. Returns new position.
    /// Returns `data.count + 1` on malformed data to signal an error.
    private static func skipDNSName(_ data: [UInt8], _ start: Int) -> Int {
        var pos = start
        while pos < data.count {
            let c = data[pos]
            if c == 0 { return pos + 1 }          // end of name
            if c & 0xC0 == 0xC0 { return pos + 2 } // compression pointer
            let labelEnd = pos + 1 + Int(c)
            guard labelEnd <= data.count else { return data.count + 1 } // malformed label
            pos = labelEnd
        }
        return pos
    }

    /// Human-readable reason a name requires DNSSEC proof.
    public static func dnssecReason(_ name: String) -> String {
        if isICANNReserved(name) { return "ICANN reserved name" }
        if isPremium(name) { return "premium name" }
        return "restricted name"
    }

    /// Compute the SHA3-256 hash of a name (used as the trie key).
    public static func hashName(_ name: String) -> NameHash {
        let bytes = Array(name.utf8)
        return NameHash(SHA3Hash.sha3_256(bytes))
    }

    /// Determine the rollout height and day for a name hash.
    ///
    /// Names are rolled out over 60 days. A name cannot be opened
    /// before its rollout height.
    ///
    /// - Parameters:
    ///   - nameHash: The SHA3-256 hash of the name (32 bytes).
    ///   - params: Name parameters.
    /// - Returns: The (height, day) tuple.
    public static func getRollout(nameHash: NameHash, params: NameParams) -> (height: Int, day: Int) {
        if params.noRollout {
            return (0, 0)
        }
        let day = modBuffer(nameHash.bytes, 60)
        let height = params.auctionStart + day * params.rolloutInterval
        return (height, day)
    }

    /// Compute `buffer mod n` by treating the buffer as a big-endian integer.
    ///
    /// Uses iterative modular arithmetic to avoid overflow.
    private static func modBuffer(_ data: [UInt8], _ n: Int) -> Int {
        var result = 0
        for byte in data {
            result = (result * 256 + Int(byte)) % n
        }
        return result
    }

    /// Check if a name is available for opening at a given height.
    ///
    /// This checks the rollout schedule but NOT reserved name status.
    /// Premium, ICANN reserved, and subdomain names bypass the rollout schedule.
    public static func isAvailable(nameHash: NameHash, height: Int, params: NameParams, rawName: [UInt8]? = nil) -> Bool {
        if params.noRollout { return true }
        if let rawName = rawName {
            // Premium and ICANN reserved names bypass rollout
            if requiresDNSSEC(rawName: rawName) { return true }
            // Subdomains bypass rollout (only TLDs are rolled out)
            if isSubdomain(rawName: rawName) { return true }
        }
        let (rolloutHeight, _) = getRollout(nameHash: nameHash, params: params)
        return height >= rolloutHeight
    }
}
