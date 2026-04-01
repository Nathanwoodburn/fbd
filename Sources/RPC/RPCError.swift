/// Errors for the JSON-RPC server.
public enum RPCError: Error, Sendable {
    // Standard JSON-RPC 2.0 error codes

    /// Invalid JSON was received (-32700).
    case parseError(String)

    /// The JSON sent is not a valid Request object (-32600).
    case invalidRequest(String)

    /// The method does not exist or is not available (-32601).
    case methodNotFound(String)

    /// Invalid method parameter(s) (-32602).
    case invalidParams(String, data: JSONValue? = nil)

    /// Internal JSON-RPC error (-32603).
    case internalError(String, data: JSONValue? = nil)

    // Application-specific error codes

    /// The requested resource was not found (-1).
    case notFound(String)

    /// The operation is not supported or disabled (-2).
    case notSupported(String)

    /// The JSON-RPC error code.
    public var code: Int {
        switch self {
        case .parseError:     return -32700
        case .invalidRequest: return -32600
        case .methodNotFound: return -32601
        case .invalidParams:  return -32602
        case .internalError:  return -32603
        case .notFound:       return -1
        case .notSupported:   return -2
        }
    }

    /// The error message.
    public var message: String {
        switch self {
        case .parseError(let msg):          return msg
        case .invalidRequest(let msg):      return msg
        case .methodNotFound(let msg):      return msg
        case .invalidParams(let msg, _):    return msg
        case .internalError(let msg, _):    return msg
        case .notFound(let msg):            return msg
        case .notSupported(let msg):        return msg
        }
    }

    /// Optional structured data for the error.
    public var data: JSONValue? {
        switch self {
        case .invalidParams(_, let data): return data
        case .internalError(_, let data): return data
        default: return nil
        }
    }
}
