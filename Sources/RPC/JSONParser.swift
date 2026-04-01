/// Minimal JSON parser for RPC requests.
///
/// Parses UTF-8 JSON into `JSONValue` trees without depending on Foundation.
public enum JSONParser {

    /// Maximum nesting depth for JSON arrays/objects.
    private static let maxDepth = 128

    /// Parse a JSON string into a JSONValue.
    ///
    /// - Parameter json: A valid JSON string.
    /// - Returns: The parsed JSON value.
    /// - Throws: `RPCError.parseError` if the JSON is malformed.
    public static func parse(_ json: String) throws -> JSONValue {
        var index = json.startIndex
        let result = try parseValue(json, &index, depth: 0)
        skipWhitespace(json, &index)
        return result
    }

    /// Parse a JSON-RPC request from a JSON string.
    public static func parseRequest(_ json: String) throws -> RPCRequest {
        let value = try parse(json)
        guard case .object(let pairs) = value else {
            throw RPCError.invalidRequest("Request must be a JSON object")
        }

        let dict = Dictionary(pairs, uniquingKeysWith: { _, last in last })

        guard let methodVal = dict["method"], case .string(let method) = methodVal else {
            throw RPCError.invalidRequest("Missing or invalid 'method' field")
        }

        let params: [JSONValue]
        if let paramsVal = dict["params"] {
            if case .array(let arr) = paramsVal {
                params = arr
            } else {
                params = []
            }
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

        return RPCRequest(method: method, params: params, wallet: wallet, id: id)
    }

    // MARK: - Internal

    private static func parseValue(_ json: String, _ index: inout String.Index, depth: Int) throws -> JSONValue {
        guard depth <= maxDepth else {
            throw RPCError.parseError("JSON nesting too deep")
        }

        skipWhitespace(json, &index)
        guard index < json.endIndex else {
            throw RPCError.parseError("Unexpected end of JSON")
        }

        switch json[index] {
        case "\"": return try parseString(json, &index)
        case "{":  return try parseObject(json, &index, depth: depth + 1)
        case "[":  return try parseArray(json, &index, depth: depth + 1)
        case "t", "f": return try parseBool(json, &index)
        case "n": return try parseNull(json, &index)
        default:   return try parseNumber(json, &index)
        }
    }

    private static func parseString(_ json: String, _ index: inout String.Index) throws -> JSONValue {
        guard json[index] == "\"" else {
            throw RPCError.parseError("Expected string")
        }
        json.formIndex(after: &index)
        var result = ""

        while index < json.endIndex {
            let ch = json[index]
            if ch == "\"" {
                json.formIndex(after: &index)
                return .string(result)
            }
            if ch == "\\" {
                json.formIndex(after: &index)
                guard index < json.endIndex else {
                    throw RPCError.parseError("Unterminated escape")
                }
                switch json[index] {
                case "\"": result.append("\"")
                case "\\": result.append("\\")
                case "/":  result.append("/")
                case "n":  result.append("\n")
                case "r":  result.append("\r")
                case "t":  result.append("\t")
                case "u":
                    // Parse 4 hex digits
                    json.formIndex(after: &index)
                    var hex = ""
                    for _ in 0..<4 {
                        guard index < json.endIndex else {
                            throw RPCError.parseError("Unterminated unicode escape")
                        }
                        hex.append(json[index])
                        json.formIndex(after: &index)
                    }
                    if let code = UInt32(hex, radix: 16), let scalar = Unicode.Scalar(code) {
                        result.append(Character(scalar))
                    }
                    continue
                default:
                    result.append(json[index])
                }
            } else {
                result.append(ch)
            }
            json.formIndex(after: &index)
        }
        throw RPCError.parseError("Unterminated string")
    }

    private static func parseNumber(_ json: String, _ index: inout String.Index) throws -> JSONValue {
        let start = index
        var hasDecimal = false

        if index < json.endIndex && json[index] == "-" {
            json.formIndex(after: &index)
        }

        while index < json.endIndex {
            let ch = json[index]
            if ch == "." || ch == "e" || ch == "E" {
                hasDecimal = true
                json.formIndex(after: &index)
                // Handle exponent sign
                if index < json.endIndex && (json[index] == "+" || json[index] == "-") {
                    json.formIndex(after: &index)
                }
            } else if ch >= "0" && ch <= "9" {
                json.formIndex(after: &index)
            } else {
                break
            }
        }

        let numStr = String(json[start..<index])

        if hasDecimal {
            if let d = Double(numStr) {
                return .double(d)
            }
        } else {
            if let n = Int64(numStr) {
                return .int(n)
            }
        }

        throw RPCError.parseError("Invalid number: \(numStr)")
    }

    private static func parseBool(_ json: String, _ index: inout String.Index) throws -> JSONValue {
        if json[index...].hasPrefix("true") {
            json.formIndex(&index, offsetBy: 4)
            return .bool(true)
        }
        if json[index...].hasPrefix("false") {
            json.formIndex(&index, offsetBy: 5)
            return .bool(false)
        }
        throw RPCError.parseError("Invalid boolean")
    }

    private static func parseNull(_ json: String, _ index: inout String.Index) throws -> JSONValue {
        if json[index...].hasPrefix("null") {
            json.formIndex(&index, offsetBy: 4)
            return .null
        }
        throw RPCError.parseError("Invalid null")
    }

    private static func parseArray(_ json: String, _ index: inout String.Index, depth: Int) throws -> JSONValue {
        guard json[index] == "[" else {
            throw RPCError.parseError("Expected array")
        }
        json.formIndex(after: &index)
        skipWhitespace(json, &index)

        var items = [JSONValue]()

        if index < json.endIndex && json[index] == "]" {
            json.formIndex(after: &index)
            return .array(items)
        }

        while true {
            let item = try parseValue(json, &index, depth: depth)
            items.append(item)
            skipWhitespace(json, &index)

            guard index < json.endIndex else {
                throw RPCError.parseError("Unterminated array")
            }

            if json[index] == "]" {
                json.formIndex(after: &index)
                return .array(items)
            }

            guard json[index] == "," else {
                throw RPCError.parseError("Expected ',' or ']' in array")
            }
            json.formIndex(after: &index)
        }
    }

    private static func parseObject(_ json: String, _ index: inout String.Index, depth: Int) throws -> JSONValue {
        guard json[index] == "{" else {
            throw RPCError.parseError("Expected object")
        }
        json.formIndex(after: &index)
        skipWhitespace(json, &index)

        var pairs = [(String, JSONValue)]()

        if index < json.endIndex && json[index] == "}" {
            json.formIndex(after: &index)
            return .object(pairs)
        }

        while true {
            skipWhitespace(json, &index)
            let keyValue = try parseString(json, &index)
            guard case .string(let key) = keyValue else {
                throw RPCError.parseError("Object key must be a string")
            }

            skipWhitespace(json, &index)
            guard index < json.endIndex && json[index] == ":" else {
                throw RPCError.parseError("Expected ':' after object key")
            }
            json.formIndex(after: &index)

            let val = try parseValue(json, &index, depth: depth)
            pairs.append((key, val))

            skipWhitespace(json, &index)
            guard index < json.endIndex else {
                throw RPCError.parseError("Unterminated object")
            }

            if json[index] == "}" {
                json.formIndex(after: &index)
                return .object(pairs)
            }

            guard json[index] == "," else {
                throw RPCError.parseError("Expected ',' or '}' in object")
            }
            json.formIndex(after: &index)
        }
    }

    private static func skipWhitespace(_ json: String, _ index: inout String.Index) {
        while index < json.endIndex {
            switch json[index] {
            case " ", "\t", "\n", "\r":
                json.formIndex(after: &index)
            default:
                return
            }
        }
    }
}
