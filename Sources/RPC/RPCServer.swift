import Base

/// Configuration for the RPC server.
public struct RPCConfig: Sendable {
    /// The host to bind to.
    public let host: String

    /// The port to listen on.
    public let port: Int

    /// The API key for authentication (nil = no auth on localhost).
    public let apiKey: String?

    /// Whether authentication is disabled.
    public let noAuth: Bool

    public init(
        host: String = "127.0.0.1",
        port: Int = 32869,
        apiKey: String? = nil,
        noAuth: Bool = false
    ) {
        self.host = host
        self.port = port
        self.apiKey = apiKey
        self.noAuth = noAuth
    }
}

/// HTTP Basic Auth credential validation for RPC.
public enum RPCAuth {
    /// Validate HTTP Basic Auth credentials against the API key.
    ///
    /// - Parameters:
    ///   - username: The provided username (ignored per FBD convention).
    ///   - password: The provided password (should be the API key).
    ///   - apiKey: The expected API key.
    /// - Returns: Whether the credentials are valid.
    public static func validate(username: String, password: String, apiKey: String) -> Bool {
        // Constant-time comparison to prevent timing attacks.
        // Compare UTF-8 byte lengths (not Unicode scalar counts) to avoid
        // mismatches when multi-byte characters are present.
        let passBytes = Array(password.utf8)
        let keyBytes = Array(apiKey.utf8)
        guard passBytes.count == keyBytes.count else { return false }
        var result: UInt8 = 0
        for i in 0..<passBytes.count {
            result |= passBytes[i] ^ keyBytes[i]
        }
        return result == 0
    }

    /// Check if a host address is localhost.
    public static func isLocalhost(_ host: String) -> Bool {
        host == "127.0.0.1" || host == "::1" || host == "localhost"
    }
}
