/// All P2P message types in the Fistbump wire protocol.
///
/// Unlike Bitcoin which uses 12-byte ASCII command strings,
/// Fistbump uses a single-byte numeric type ID.
public enum PacketType: UInt8, Sendable, CaseIterable {
    case version      = 0
    case verack       = 1
    case ping         = 2
    case pong         = 3
    case getaddr      = 4
    case addr         = 5
    case inv          = 6
    case getdata      = 7
    case notfound     = 8
    case getblocks    = 9
    case getheaders   = 10
    case headers      = 11
    case sendheaders  = 12
    case block        = 13
    case tx           = 14
    case reject       = 15
    case mempool      = 16
    case filterload   = 17
    case filteradd    = 18
    case filterclear  = 19
    case merkleblock  = 20
    case feefilter    = 21
    case sendcmpct    = 22
    case cmpctblock   = 23
    case getblocktxn  = 24
    case blocktxn     = 25
    case getproof     = 26
    case proof        = 27
    case unknown      = 28
    case `internal`   = 29
    case data         = 30
}
