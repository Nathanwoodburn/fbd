import Base

/// A BIP9-style soft fork deployment definition.
///
/// Each deployment uses a specific version bit for signaling and has
/// a start time and timeout (both as median-time-past).
public struct Deployment: Sendable {
    /// Deployment name (e.g., "segwit").
    public let name: String

    /// The version bit used for signaling (0-28).
    public let bit: Int

    /// Earliest median-time-past when the deployment can activate.
    public let startTime: UInt64

    /// The median-time-past at which the deployment times out (fails).
    public let timeout: UInt64

    public init(name: String, bit: Int, startTime: UInt64, timeout: UInt64) {
        self.name = name
        self.bit = bit
        self.startTime = startTime
        self.timeout = timeout
    }
}

/// BIP9 threshold states for a deployment.
public enum ThresholdState: UInt8, Sendable {
    case defined  = 0
    case started  = 1
    case lockedIn = 2
    case active   = 3
    case failed   = 4

    public var statusString: String {
        switch self {
        case .defined:  return "defined"
        case .started:  return "started"
        case .lockedIn: return "locked_in"
        case .active:   return "active"
        case .failed:   return "failed"
        }
    }
}

/// Aggregated soft fork activation state for a specific block.
///
/// FBD currently has no active soft fork deployments.
public struct DeploymentState: Sendable {
    public init() {}
}
