import Foundation

/// Errors that can occur during node operation.
public enum NodeError: Error, Sendable, LocalizedError {
    /// A configuration error.
    case configurationError(String)

    /// A startup error.
    case startupFailed(String)

    /// The node is not in the expected state for this operation.
    case invalidState(String)

    /// A subsystem reported an error.
    case subsystemError(String)

    /// The data directory could not be accessed or created.
    case dataDirectoryError(String)

    /// An index flag mismatch between config and on-disk state.
    case indexMismatch(String)

    public var errorDescription: String? {
        switch self {
        case .configurationError(let msg): return msg
        case .startupFailed(let msg): return msg
        case .invalidState(let msg): return msg
        case .subsystemError(let msg): return msg
        case .dataDirectoryError(let msg): return msg
        case .indexMismatch(let msg): return msg
        }
    }
}
