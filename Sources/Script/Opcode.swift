/// Bitcoin-derived opcodes used in Handshake scripts.
public enum Opcode: UInt8, Sendable, CaseIterable {
    // MARK: - Push value

    /// Push empty byte array (false).
    case OP_0           = 0x00

    // Data push: 0x01-0x4b push N bytes directly (handled as raw values, not enum cases)

    /// Next byte is the number of bytes to push.
    case OP_PUSHDATA1   = 0x4c
    /// Next 2 bytes (LE) are the number of bytes to push.
    case OP_PUSHDATA2   = 0x4d
    /// Next 4 bytes (LE) are the number of bytes to push.
    case OP_PUSHDATA4   = 0x4e

    /// Push -1.
    case OP_1NEGATE     = 0x4f

    /// Reserved (transaction invalid if executed).
    case OP_RESERVED    = 0x50

    /// Push 1 (true).
    case OP_1           = 0x51
    case OP_2           = 0x52
    case OP_3           = 0x53
    case OP_4           = 0x54
    case OP_5           = 0x55
    case OP_6           = 0x56
    case OP_7           = 0x57
    case OP_8           = 0x58
    case OP_9           = 0x59
    case OP_10          = 0x5a
    case OP_11          = 0x5b
    case OP_12          = 0x5c
    case OP_13          = 0x5d
    case OP_14          = 0x5e
    case OP_15          = 0x5f
    case OP_16          = 0x60

    // MARK: - Flow control

    case OP_NOP         = 0x61
    case OP_VER         = 0x62
    case OP_IF          = 0x63
    case OP_NOTIF       = 0x64
    case OP_VERIF       = 0x65
    case OP_VERNOTIF    = 0x66
    case OP_ELSE        = 0x67
    case OP_ENDIF       = 0x68
    case OP_VERIFY      = 0x69
    case OP_RETURN      = 0x6a

    // MARK: - Stack operations

    case OP_TOALTSTACK      = 0x6b
    case OP_FROMALTSTACK    = 0x6c
    case OP_2DROP           = 0x6d
    case OP_2DUP            = 0x6e
    case OP_3DUP            = 0x6f
    case OP_2OVER           = 0x70
    case OP_2ROT            = 0x71
    case OP_2SWAP           = 0x72
    case OP_IFDUP           = 0x73
    case OP_DEPTH           = 0x74
    case OP_DROP            = 0x75
    case OP_DUP             = 0x76
    case OP_NIP             = 0x77
    case OP_OVER            = 0x78
    case OP_PICK            = 0x79
    case OP_ROLL            = 0x7a
    case OP_ROT             = 0x7b
    case OP_SWAP            = 0x7c
    case OP_TUCK            = 0x7d

    // MARK: - Splice operations (disabled)

    case OP_CAT             = 0x7e
    case OP_SUBSTR          = 0x7f
    case OP_LEFT            = 0x80
    case OP_RIGHT           = 0x81
    case OP_SIZE            = 0x82

    // MARK: - Bitwise logic

    case OP_INVERT          = 0x83
    case OP_AND             = 0x84
    case OP_OR              = 0x85
    case OP_XOR             = 0x86
    case OP_EQUAL           = 0x87
    case OP_EQUALVERIFY     = 0x88
    case OP_RESERVED1       = 0x89
    case OP_RESERVED2       = 0x8a

    // MARK: - Arithmetic

    case OP_1ADD            = 0x8b
    case OP_1SUB            = 0x8c
    case OP_2MUL            = 0x8d
    case OP_2DIV            = 0x8e
    case OP_NEGATE          = 0x8f
    case OP_ABS             = 0x90
    case OP_NOT             = 0x91
    case OP_0NOTEQUAL       = 0x92
    case OP_ADD             = 0x93
    case OP_SUB             = 0x94
    case OP_MUL             = 0x95
    case OP_DIV             = 0x96
    case OP_MOD             = 0x97
    case OP_LSHIFT          = 0x98
    case OP_RSHIFT          = 0x99
    case OP_BOOLAND         = 0x9a
    case OP_BOOLOR          = 0x9b
    case OP_NUMEQUAL        = 0x9c
    case OP_NUMEQUALVERIFY  = 0x9d
    case OP_NUMNOTEQUAL     = 0x9e
    case OP_LESSTHAN        = 0x9f
    case OP_GREATERTHAN     = 0xa0
    case OP_LESSTHANOREQUAL = 0xa1
    case OP_GREATERTHANOREQUAL = 0xa2
    case OP_MIN             = 0xa3
    case OP_MAX             = 0xa4
    case OP_WITHIN          = 0xa5

    // MARK: - Crypto

    case OP_RIPEMD160       = 0xa6
    case OP_SHA1            = 0xa7
    case OP_SHA256          = 0xa8
    case OP_HASH160         = 0xa9
    case OP_HASH256         = 0xaa
    case OP_CODESEPARATOR   = 0xab
    case OP_CHECKSIG        = 0xac
    case OP_CHECKSIGVERIFY  = 0xad
    case OP_CHECKMULTISIG   = 0xae
    case OP_CHECKMULTISIGVERIFY = 0xaf

    // MARK: - Expansion

    case OP_NOP1            = 0xb0
    case OP_CHECKLOCKTIMEVERIFY = 0xb1
    case OP_CHECKSEQUENCEVERIFY = 0xb2
    case OP_NOP4            = 0xb3
    case OP_NOP5            = 0xb4
    case OP_NOP6            = 0xb5
    case OP_NOP7            = 0xb6
    case OP_NOP8            = 0xb7
    case OP_NOP9            = 0xb8
    case OP_NOP10           = 0xb9

    // MARK: - Handshake-specific hash opcodes

    /// BLAKE2b-160 (Handshake's equivalent of Bitcoin's OP_HASH160).
    case OP_BLAKE160        = 0xc0
    /// BLAKE2b-256.
    case OP_BLAKE256        = 0xc1
    /// SHA3-256 (Handshake's equivalent of Bitcoin's OP_HASH256).
    case OP_SHA3            = 0xc2
    /// Keccak-256 (pre-FIPS, different domain suffix from SHA3-256).
    case OP_KECCAK          = 0xc3

    // MARK: - Handshake covenant inspection

    /// Push the covenant type of the output at `index`.
    case OP_TYPE            = 0xd0

    // MARK: - Special

    /// Explicitly invalid opcode (always fails when executed).
    case OP_INVALIDOPCODE   = 0xff

    /// Whether this opcode is disabled (always invalid if encountered).
    public var isDisabled: Bool {
        switch self {
        case .OP_CAT, .OP_SUBSTR, .OP_LEFT, .OP_RIGHT,
             .OP_INVERT, .OP_AND, .OP_OR, .OP_XOR,
             .OP_2MUL, .OP_2DIV, .OP_MUL, .OP_DIV, .OP_MOD,
             .OP_LSHIFT, .OP_RSHIFT:
            return true
        default:
            return false
        }
    }

    /// Whether this is a "small integer" push (OP_0 through OP_16).
    public var isSmallInt: Bool {
        self == .OP_0 || (rawValue >= Opcode.OP_1.rawValue && rawValue <= Opcode.OP_16.rawValue)
    }

    /// The small integer value for OP_0 through OP_16, or nil.
    public var smallIntValue: Int? {
        if self == .OP_0 { return 0 }
        if rawValue >= Opcode.OP_1.rawValue && rawValue <= Opcode.OP_16.rawValue {
            return Int(rawValue) - Int(Opcode.OP_1.rawValue) + 1
        }
        return nil
    }
}

/// Check if a raw byte is a direct data push (0x01-0x4b).
public func isDirectPush(_ byte: UInt8) -> Bool {
    byte >= 0x01 && byte <= 0x4b
}
