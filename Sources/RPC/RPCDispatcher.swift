/// RPC method dispatch engine.
///
/// Routes incoming JSON-RPC requests to registered handler functions
/// by method name. Handles parameter validation and error wrapping.
public final class RPCDispatcher: Sendable {

    /// A method handler that takes a request and returns a result.
    public typealias Handler = @Sendable (RPCRequest) throws -> JSONValue

    /// Registered method handlers.
    private let handlers: [String: Handler]

    public init(handlers: [String: Handler]) {
        self.handlers = handlers
    }

    /// Dispatch a single RPC request.
    ///
    /// - Parameter request: The parsed RPC request.
    /// - Returns: The RPC response.
    public func dispatch(_ request: RPCRequest) -> RPCResponse {
        guard let handler = handlers[request.method] else {
            return .failure(
                .methodNotFound("Method not found: \(request.method)"),
                id: request.id
            )
        }

        do {
            let result = try handler(request)
            return .success(result, id: request.id)
        } catch let error as RPCError {
            return .failure(error, id: request.id)
        } catch {
            return .failure(
                .internalError(error.localizedDescription),
                id: request.id
            )
        }
    }

    /// Dispatch a raw JSON string (single request or batch).
    ///
    /// - Parameter json: The raw JSON-RPC request string.
    /// - Returns: The JSON-encoded response string.
    public func handleRaw(_ json: String) -> String {
        // Try to parse as batch (array) first
        do {
            let value = try JSONParser.parse(json)

            if case .array(let items) = value {
                // Batch request
                guard items.count <= 100 else {
                    return JSONEncoder.encode(RPCResponse.failure(
                        .invalidRequest("batch request too large (max 100)"),
                        id: .null
                    ))
                }
                var responses = [String]()
                for item in items {
                    let response = dispatchValue(item)
                    responses.append(JSONEncoder.encode(response))
                }
                return "[" + responses.joined(separator: ",") + "]"
            }

            // Single request
            let response = dispatchValue(value)
            return JSONEncoder.encode(response)
        } catch {
            let response = RPCResponse.failure(
                .parseError("Parse error: \(error)"),
                id: .null
            )
            return JSONEncoder.encode(response)
        }
    }

    /// Dispatch a single parsed JSON value as an RPC request.
    private func dispatchValue(_ value: JSONValue) -> RPCResponse {
        guard case .object(let pairs) = value else {
            return .failure(.invalidRequest("Request must be a JSON object"), id: .null)
        }

        let dict = Dictionary(pairs, uniquingKeysWith: { _, last in last })

        guard let methodVal = dict["method"], case .string(let method) = methodVal else {
            return .failure(.invalidRequest("Missing 'method' field"), id: .null)
        }

        let params: [JSONValue]
        if let paramsVal = dict["params"], case .array(let arr) = paramsVal {
            params = arr
        } else {
            params = []
        }

        let wallet: String?
        if let walletVal = dict["wallet"], case .string(let w) = walletVal {
            wallet = w
        } else {
            wallet = nil
        }

        let id = dict["id"] ?? .null
        let request = RPCRequest(method: method, params: params, wallet: wallet, id: id)
        return dispatch(request)
    }

    /// Get the list of registered method names.
    public var methods: [String] {
        Array(handlers.keys).sorted()
    }
}
