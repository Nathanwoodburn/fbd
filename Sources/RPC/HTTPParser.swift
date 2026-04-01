/// Minimal HTTP/1.1 request parser and response formatter.
///
/// Only supports what we need for JSON-RPC: POST requests with Content-Length.

/// A parsed HTTP request.
public struct HTTPRequest: Sendable {
    public let method: String
    public let uri: String
    public let headers: [(name: String, value: String)]
    public let body: [UInt8]

    public init(method: String, uri: String, headers: [(name: String, value: String)], body: [UInt8]) {
        self.method = method
        self.uri = uri
        self.headers = headers
        self.body = body
    }

    /// Get the first header value matching the given name (case-insensitive).
    public func header(_ name: String) -> String? {
        let lower = name.lowercased()
        return headers.first(where: { $0.name.lowercased() == lower })?.value
    }
}

/// HTTP request parser for reading from a byte stream.
public enum HTTPParser {

    /// Maximum allowed request body size (1 MB).
    public static let maxBodySize = 1_048_576

    /// Parse an HTTP request from accumulated bytes.
    /// Returns (request, bytesConsumed) or nil if not enough data yet.
    /// Returns nil if Content-Length exceeds maxBodySize.
    public static func parse(_ data: [UInt8]) -> (HTTPRequest, Int)? {
        // Find the end of headers (\r\n\r\n)
        guard let headerEnd = findHeaderEnd(data) else { return nil }

        let headerBytes = Array(data[0..<headerEnd])
        guard let headerStr = String(bytes: headerBytes, encoding: .utf8) else { return nil }

        let lines = headerStr.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let requestLine = lines.first else { return nil }

        // Parse request line: "METHOD URI HTTP/x.x"
        let parts = requestLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return nil }
        let method = String(parts[0])
        let uri = String(parts[1])

        // Parse headers
        var headers: [(name: String, value: String)] = []
        for line in lines.dropFirst() {
            guard let colonIdx = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colonIdx]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
            headers.append((name: name, value: value))
        }

        // Get content length
        let contentLength: Int
        if let clHeader = headers.first(where: { $0.name.lowercased() == "content-length" }),
           let cl = Int(clHeader.value) {
            guard cl >= 0, cl <= maxBodySize else { return nil }
            contentLength = cl
        } else {
            contentLength = 0
        }

        // headerEnd + 4 for \r\n\r\n
        let bodyStart = headerEnd + 4
        let totalNeeded = bodyStart + contentLength
        guard data.count >= totalNeeded else { return nil }

        let body = Array(data[bodyStart..<totalNeeded])

        return (HTTPRequest(method: method, uri: uri, headers: headers, body: body), totalNeeded)
    }

    /// Find the position of the first \r\n\r\n sequence.
    private static func findHeaderEnd(_ data: [UInt8]) -> Int? {
        guard data.count >= 4 else { return nil }
        for i in 0...(data.count - 4) {
            if data[i] == 0x0D && data[i+1] == 0x0A &&
               data[i+2] == 0x0D && data[i+3] == 0x0A {
                return i
            }
        }
        return nil
    }
}

/// HTTP response formatter.
public enum HTTPResponse {

    /// Format a complete HTTP response with the given status code and body.
    public static func format(status: Int, statusText: String = "OK", body: String, contentType: String = "application/json") -> [UInt8] {
        let bodyBytes = Array(body.utf8)
        var response = "HTTP/1.1 \(status) \(statusText)\r\n"
        response += "Content-Type: \(contentType)\r\n"
        response += "Content-Length: \(bodyBytes.count)\r\n"
        response += "Connection: keep-alive\r\n"
        response += "\r\n"
        return Array(response.utf8) + bodyBytes
    }

    /// Common status codes.
    public static func ok(body: String) -> [UInt8] {
        format(status: 200, statusText: "OK", body: body)
    }

    public static func badRequest(body: String) -> [UInt8] {
        format(status: 400, statusText: "Bad Request", body: body)
    }

    public static func unauthorized(body: String) -> [UInt8] {
        format(status: 401, statusText: "Unauthorized", body: body)
    }

    public static func methodNotAllowed(body: String) -> [UInt8] {
        format(status: 405, statusText: "Method Not Allowed", body: body)
    }
}
