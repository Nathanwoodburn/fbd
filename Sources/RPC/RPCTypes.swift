import Base

/// A JSON value representation for RPC request/response serialization.
///
/// This avoids pulling in Foundation's JSONSerialization for a simple
/// JSON-RPC protocol. Values can be constructed directly and encoded
/// to/from UTF-8 bytes.
public enum JSONValue: Sendable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([(String, JSONValue)])

    /// Access as string, or nil.
    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    /// Access as integer, or nil.
    public var intValue: Int64? {
        if case .int(let n) = self { return n }
        return nil
    }

    /// Access as double, or nil. Also converts .int to Double.
    public var doubleValue: Double? {
        switch self {
        case .double(let d): return d
        case .int(let n): return Double(n)
        default: return nil
        }
    }

    /// Access as boolean, or nil.
    public var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    /// Access as array, or nil.
    public var arrayValue: [JSONValue]? {
        if case .array(let arr) = self { return arr }
        return nil
    }

    /// Access as object (key-value pairs), or nil.
    public var objectValue: [(String, JSONValue)]? {
        if case .object(let obj) = self { return obj }
        return nil
    }

    /// Look up a key in an object.
    public subscript(key: String) -> JSONValue? {
        guard case .object(let pairs) = self else { return nil }
        return pairs.first(where: { $0.0 == key })?.1
    }

    /// Look up an index in an array.
    public subscript(index: Int) -> JSONValue? {
        guard case .array(let arr) = self, index >= 0, index < arr.count else { return nil }
        return arr[index]
    }
}

/// A JSON-RPC 2.0 request.
public struct RPCRequest: Equatable, Sendable {
    /// The method name.
    public let method: String

    /// The positional parameters.
    public let params: [JSONValue]

    /// Optional wallet name (sent via separate "wallet" field, not in params).
    public let wallet: String?

    /// The request ID (for correlating responses).
    public let id: JSONValue

    public init(method: String, params: [JSONValue] = [], wallet: String? = nil, id: JSONValue = .null) {
        self.method = method
        self.params = params
        self.wallet = wallet
        self.id = id
    }
}

// MARK: - Parameter Extraction Helpers

extension RPCRequest {
    /// Get a required string parameter by index.
    public func requireString(_ index: Int = 0, _ name: String) throws -> String {
        guard params.count > index, let v = params[index].stringValue, !v.isEmpty else {
            throw RPCError.invalidParams("expected \(name)")
        }
        return v
    }

    /// Get a required integer parameter by index.
    public func requireInt(_ index: Int = 0, _ name: String) throws -> Int64 {
        guard params.count > index, let v = params[index].intValue else {
            throw RPCError.invalidParams("expected \(name)")
        }
        return v
    }

    /// Get an optional string parameter (nil if missing or empty).
    public func optionalString(_ index: Int) -> String? {
        guard params.count > index, let v = params[index].stringValue, !v.isEmpty else { return nil }
        return v
    }

    /// Get an optional integer parameter (nil if missing).
    public func optionalInt(_ index: Int) -> Int64? {
        guard params.count > index else { return nil }
        return params[index].intValue
    }

    /// Get an optional double parameter (nil if missing).
    public func optionalDouble(_ index: Int) -> Double? {
        guard params.count > index else { return nil }
        return params[index].doubleValue
    }

    /// Get an optional bool parameter with a default.
    public func optionalBool(_ index: Int, default defaultValue: Bool) -> Bool {
        guard params.count > index, let v = params[index].boolValue else { return defaultValue }
        return v
    }
}

/// A JSON-RPC 2.0 response.
public struct RPCResponse: Equatable, Sendable {
    /// The result (if successful).
    public let result: JSONValue?

    /// The error (if failed).
    public let error: RPCErrorObject?

    /// The request ID.
    public let id: JSONValue

    /// Create a success response.
    public static func success(_ result: JSONValue, id: JSONValue) -> RPCResponse {
        RPCResponse(result: result, error: nil, id: id)
    }

    /// Create an error response.
    public static func failure(_ error: RPCError, id: JSONValue) -> RPCResponse {
        RPCResponse(
            result: nil,
            error: RPCErrorObject(code: error.code, message: error.message, data: error.data),
            id: id
        )
    }
}

/// The error object in a JSON-RPC response.
public struct RPCErrorObject: Equatable, Sendable {
    /// The error code.
    public let code: Int

    /// The error message.
    public let message: String

    /// Optional structured data.
    public let data: JSONValue?

    public init(code: Int, message: String, data: JSONValue? = nil) {
        self.code = code
        self.message = message
        self.data = data
    }
}

// MARK: - JSONValue Equatable

extension JSONValue: Equatable {
    public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null): return true
        case (.bool(let a), .bool(let b)): return a == b
        case (.int(let a), .int(let b)): return a == b
        case (.double(let a), .double(let b)): return a == b
        case (.string(let a), .string(let b)): return a == b
        case (.array(let a), .array(let b)): return a == b
        case (.object(let a), .object(let b)):
            guard a.count == b.count else { return false }
            for (pair1, pair2) in zip(a, b) {
                if pair1.0 != pair2.0 || pair1.1 != pair2.1 { return false }
            }
            return true
        default: return false
        }
    }
}
