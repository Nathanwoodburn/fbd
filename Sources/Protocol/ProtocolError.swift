import Foundation

/// Errors thrown by Protocol operations.
public enum ProtocolError: Error, Sendable, LocalizedError {
    /// An unknown covenant type byte was encountered.
    case unknownCovenantType(UInt8)

    /// Too many items in a covenant or witness stack.
    case tooManyItems(Int)

    /// An address version is out of range (must be 0...31).
    case invalidAddressVersion(UInt8)

    /// An address hash length is out of range (must be 2...40).
    case invalidAddressHashLength(UInt8)

    /// An unknown inventory item type was encountered.
    case unknownInvType(UInt32)

    /// A Bech32 address string was invalid or had wrong HRP.
    case invalidBech32Address

    public var errorDescription: String? {
        switch self {
        case .unknownCovenantType(let t): return "Unknown covenant type: \(t)."
        case .tooManyItems(let n): return "Too many items: \(n)."
        case .invalidAddressVersion(let v): return "Invalid address version: \(v)."
        case .invalidAddressHashLength(let l): return "Invalid address hash length: \(l)."
        case .unknownInvType(let t): return "Unknown inventory type: \(t)."
        case .invalidBech32Address: return "Invalid address. Check the format and try again."
        }
    }
}
