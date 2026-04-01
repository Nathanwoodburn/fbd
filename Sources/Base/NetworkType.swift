/// The Fistbump network type.
///
/// Each network has distinct parameters (magic bytes, port, genesis block, etc.)
/// to prevent cross-network contamination.
public enum NetworkType: String, Sendable, CaseIterable {
    /// The production mainnet.
    case main

    /// The public testnet.
    case testnet

    /// Local regression testing network (deterministic mining).
    case regtest

    /// Simulation network (similar to regtest, used by btcd-family tools).
    case simnet

    /// The default P2P port for this network.
    /// Mainnet spells "FBUMP" (3-2-8-6-7) on a T9 keypad.
    public var defaultPort: UInt16 {
        switch self {
        case .main:    return 32867
        case .testnet: return 42867
        case .regtest: return 52867
        case .simnet:  return 62867
        }
    }

    /// The network magic bytes (first 4 bytes of every message).
    public var magic: UInt32 {
        switch self {
        case .main:    return 0xfb_d0_fb_d0
        case .testnet: return 0xfb_d1_fb_d1
        case .regtest: return 0xfb_d2_fb_d2
        case .simnet:  return 0xfb_d3_fb_d3
        }
    }

    /// The default Brontide (encrypted P2P) port.
    public var brontidePort: UInt16 {
        switch self {
        case .main:    return 32868
        case .testnet: return 42868
        case .regtest: return 52868
        case .simnet:  return 62868
        }
    }

    /// The default RPC port.
    public var rpcPort: UInt16 {
        switch self {
        case .main:    return 32869
        case .testnet: return 42869
        case .regtest: return 52869
        case .simnet:  return 62869
        }
    }

    /// The default authoritative DNS port.
    public var nsPort: UInt16 {
        switch self {
        case .main:    return 32870
        case .testnet: return 42870
        case .regtest: return 52870
        case .simnet:  return 62870
        }
    }

    /// The default Stratum mining pool port.
    public var stratumPort: UInt16 {
        switch self {
        case .main:    return 32871
        case .testnet: return 42871
        case .regtest: return 52871
        case .simnet:  return 62871
        }
    }

    /// DNS seeds for peer discovery.
    public var seeds: [String] {
        switch self {
        case .main:    return ["seed.fbd.dev"]
        case .testnet: return ["seed.fbd.dev"]
        case .regtest: return []
        case .simnet:  return []
        }
    }

    /// The Bech32 human-readable part for addresses.
    public var addressHRP: String {
        switch self {
        case .main:    return "fb"
        case .testnet: return "ft"
        case .regtest: return "fr"
        case .simnet:  return "fs"
        }
    }

    /// Human-readable network name for logging.
    public var displayName: String {
        rawValue
    }
}
