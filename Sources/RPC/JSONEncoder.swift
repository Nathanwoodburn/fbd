import Foundation

/// Minimal JSON encoding for RPC responses.
public enum JSONEncoder {

    /// Encode a JSON value to a UTF-8 string.
    public static func encode(_ value: JSONValue) -> String {
        var output = ""
        write(value, to: &output)
        return output
    }

    /// Encode an RPC response to a JSON string.
    public static func encode(_ response: RPCResponse) -> String {
        var pairs: [(String, JSONValue)] = []

        if let result = response.result {
            pairs.append(("result", result))
            pairs.append(("error", .null))
        } else if let error = response.error {
            pairs.append(("result", .null))
            var errorPairs: [(String, JSONValue)] = [
                ("message", .string(error.message)),
                ("code", .int(Int64(error.code))),
            ]
            if let data = error.data {
                errorPairs.append(("data", data))
            }
            pairs.append(("error", .object(errorPairs)))
        } else {
            pairs.append(("result", .null))
            pairs.append(("error", .null))
        }

        pairs.append(("id", response.id))
        return encode(.object(pairs))
    }

    /// Encode an RPC request to a JSON string.
    public static func encode(_ request: RPCRequest) -> String {
        let obj: JSONValue = .object([
            ("method", .string(request.method)),
            ("params", .array(request.params)),
            ("id", request.id),
        ])
        return encode(obj)
    }

    /// Encode a JSON value to a pretty-printed UTF-8 string with 2-space indentation.
    public static func prettyEncode(_ value: JSONValue) -> String {
        var output = ""
        writePretty(value, to: &output, indent: 0)
        output += "\n"
        return output
    }

    // MARK: - Internal

    private static func write(_ value: JSONValue, to output: inout String) {
        switch value {
        case .null:
            output += "null"

        case .bool(let b):
            output += b ? "true" : "false"

        case .int(let n):
            output += String(n)

        case .double(let d):
            if d.isNaN || d.isInfinite {
                output += "null"
            } else if d == d.rounded(.towardZero) && abs(d) < 1e15 {
                // Whole number — emit as integer to avoid trailing .0
                output += String(Int64(d))
            } else {
                // Use %.15g for clean output without IEEE 754 noise
                output += String(format: "%.15g", d)
            }

        case .string(let s):
            output += "\""
            for ch in s {
                switch ch {
                case "\"": output += "\\\""
                case "\\": output += "\\\\"
                case "\n": output += "\\n"
                case "\r": output += "\\r"
                case "\t": output += "\\t"
                default:
                    if ch.asciiValue != nil && ch.asciiValue! < 0x20 {
                        output += String(format: "\\u%04x", ch.asciiValue!)
                    } else {
                        output.append(ch)
                    }
                }
            }
            output += "\""

        case .array(let items):
            output += "["
            for (i, item) in items.enumerated() {
                if i > 0 { output += "," }
                write(item, to: &output)
            }
            output += "]"

        case .object(let pairs):
            output += "{"
            for (i, (key, val)) in pairs.enumerated() {
                if i > 0 { output += "," }
                write(.string(key), to: &output)
                output += ":"
                write(val, to: &output)
            }
            output += "}"
        }
    }

    private static let indentUnit = "  "

    private static func writePretty(_ value: JSONValue, to output: inout String, indent: Int) {
        switch value {
        case .array(let items):
            if items.isEmpty {
                output += "[]"
                return
            }
            output += "[\n"
            for (i, item) in items.enumerated() {
                output += String(repeating: indentUnit, count: indent + 1)
                writePretty(item, to: &output, indent: indent + 1)
                if i < items.count - 1 { output += "," }
                output += "\n"
            }
            output += String(repeating: indentUnit, count: indent)
            output += "]"

        case .object(let pairs):
            if pairs.isEmpty {
                output += "{}"
                return
            }
            output += "{\n"
            for (i, (key, val)) in pairs.enumerated() {
                output += String(repeating: indentUnit, count: indent + 1)
                write(.string(key), to: &output)
                output += ": "
                writePretty(val, to: &output, indent: indent + 1)
                if i < pairs.count - 1 { output += "," }
                output += "\n"
            }
            output += String(repeating: indentUnit, count: indent)
            output += "}"

        default:
            write(value, to: &output)
        }
    }
}
