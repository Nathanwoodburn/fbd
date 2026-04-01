/// DNS record types (RFC 1035 and extensions).
public enum DNSType: UInt16, Sendable {
    case a      = 1
    case ns     = 2
    case cname  = 5
    case soa    = 6
    case mx     = 15
    case txt    = 16
    case aaaa   = 28
    case opt    = 41
    case ds     = 43
    case rrsig  = 46
    case nsec   = 47
    case dnskey = 48
    case tlsa   = 52
    case caa    = 257
}

/// DNS class codes.
public enum DNSClass: UInt16, Sendable {
    /// Internet.
    case `in` = 1
}

/// DNS operation codes (query type).
public enum DNSOpcode: UInt8, Sendable {
    case query  = 0
    case iquery = 1
    case status = 2
    case notify = 4
    case update = 5
}

/// DNS response codes.
public enum DNSRcode: UInt8, Sendable {
    case noerror  = 0
    case formerr  = 1
    case servfail = 2
    case nxdomain = 3
    case notimp   = 4
    case refused  = 5
}

/// FBD-specific on-chain resource record type identifiers.
///
/// These are NOT DNS record types — they identify the format of
/// records stored in the blockchain's resource data blob.
public enum RecordType: UInt8, Sendable, CaseIterable {
    /// DNSSEC Delegation Signer.
    case ds     = 0
    /// Nameserver (external, no glue).
    case ns     = 1
    /// Nameserver with IPv4 glue address.
    case glue4  = 2
    /// Nameserver with IPv6 glue address.
    case glue6  = 3
    /// Synthetic nameserver from IPv4 address.
    case synth4 = 4
    /// Synthetic nameserver from IPv6 address.
    case synth6 = 5
    /// Text record.
    case txt    = 6
    /// IPv4 address record.
    case a      = 7
    /// IPv6 address record.
    case aaaa   = 8
    /// Canonical name (alias).
    case cname  = 9
    /// Mail exchange.
    case mx     = 10
    /// TLSA certificate association.
    case tlsa   = 11
    /// Certification Authority Authorization.
    case caa    = 12
    /// Inline subdomain records.
    case sub    = 13
    /// Fistbump wallet address (for sending FBC to a name).
    case wallet = 14
}

/// DNS-related constants.
public enum DNSConstants {
    /// Default TTL for FBD name records (~6 hours, one tree interval).
    public static let defaultTTL: UInt32 = 21_600

    /// TTL for root zone NS records (~6 days).
    public static let nsTTL: UInt32 = 518_400

    /// TTL for root SOA record (1 day).
    public static let soaTTL: UInt32 = 86_400

    /// Maximum DNS message size for UDP.
    public static let maxUDPSize: Int = 512

    /// Maximum DNS message size with EDNS.
    public static let maxEDNSSize: Int = 4096

    /// Maximum label length in bytes.
    public static let maxLabelLength: Int = 63

    /// Maximum domain name length in bytes.
    public static let maxNameLength: Int = 255

    /// DNS header size in bytes.
    public static let headerSize: Int = 12

    /// SOA record parameters.
    public static let soaRefresh: UInt32 = 1800
    public static let soaRetry: UInt32 = 900
    public static let soaExpire: UInt32 = 604_800
    public static let soaMinTTL: UInt32 = 21_600
}
