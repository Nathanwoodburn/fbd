import XCTest
import Logging
@testable import RPC

final class RPCHTTPHandlerTests: XCTestCase {

    // MARK: - Helpers

    private func makeConfig(noAuth: Bool = true, apiKey: String? = nil) -> RPCConfig {
        RPCConfig(
            host: "127.0.0.1",
            port: 32869,
            apiKey: apiKey,
            noAuth: noAuth
        )
    }

    private func makeDispatcher() -> RPCDispatcher {
        RPCDispatcher(handlers: [
            "getblockcount": { (_: RPCRequest) in .int(0) },
            "echo": { (req: RPCRequest) in req.params.first ?? .null },
        ])
    }

    private func buildHTTPRequest(
        method: String = "POST",
        body: String,
        headers: [(String, String)] = []
    ) -> HTTPRequest {
        var allHeaders: [(name: String, value: String)] = [
            (name: "Content-Type", value: "application/json"),
            (name: "Content-Length", value: "\(body.utf8.count)"),
        ]
        for (name, value) in headers {
            allHeaders.append((name: name, value: value))
        }
        return HTTPRequest(
            method: method,
            uri: "/",
            headers: allHeaders,
            body: Array(body.utf8)
        )
    }

    private func parseHTTPResponse(_ data: [UInt8]) -> (status: Int, body: String) {
        guard let str = String(bytes: data, encoding: .utf8) else {
            return (500, "")
        }
        // Parse status line
        let lines = str.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let statusLine = lines.first else { return (500, "") }
        let parts = statusLine.split(separator: " ", maxSplits: 2)
        let status = parts.count >= 2 ? Int(parts[1]) ?? 500 : 500

        // Find body (after \r\n\r\n)
        if let range = str.range(of: "\r\n\r\n") {
            return (status, String(str[range.upperBound...]))
        }
        return (status, "")
    }

    // MARK: - Tests

    func testValidJSONRPCRequest() throws {
        let config = makeConfig()
        let dispatcher = makeDispatcher()
        var logger = Logger(label: "test")
        logger.logLevel = .critical

        let request = buildHTTPRequest(body: #"{"method":"getblockcount","params":[],"id":1}"#)
        let responseBytes = RPCNetworkServer.handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)
        let (status, body) = parseHTTPResponse(responseBytes)

        XCTAssertEqual(status, 200)
        XCTAssertTrue(body.contains("\"result\""))
        XCTAssertTrue(body.contains("0"))
    }

    func testMethodNotAllowed() throws {
        let config = makeConfig()
        let dispatcher = makeDispatcher()
        var logger = Logger(label: "test")
        logger.logLevel = .critical

        let request = buildHTTPRequest(method: "GET", body: "")
        let responseBytes = RPCNetworkServer.handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)
        let (status, _) = parseHTTPResponse(responseBytes)

        XCTAssertEqual(status, 405)
    }

    func testAuthRequired_NoHeader() throws {
        let config = makeConfig(noAuth: false, apiKey: "secret123")
        let dispatcher = makeDispatcher()
        var logger = Logger(label: "test")
        logger.logLevel = .critical

        let request = buildHTTPRequest(body: #"{"method":"getblockcount","params":[],"id":1}"#)
        let responseBytes = RPCNetworkServer.handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)
        let (status, _) = parseHTTPResponse(responseBytes)

        XCTAssertEqual(status, 401)
    }

    func testAuthRequired_WrongCredentials() throws {
        let config = makeConfig(noAuth: false, apiKey: "secret123")
        let dispatcher = makeDispatcher()
        var logger = Logger(label: "test")
        logger.logLevel = .critical

        // "wrong:creds" in base64 = "d3Jvbmc6Y3JlZHM="
        let request = buildHTTPRequest(
            body: #"{"method":"getblockcount","params":[],"id":1}"#,
            headers: [("Authorization", "Basic d3Jvbmc6Y3JlZHM=")]
        )
        let responseBytes = RPCNetworkServer.handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)
        let (status, _) = parseHTTPResponse(responseBytes)

        XCTAssertEqual(status, 401)
    }

    func testAuthRequired_ValidCredentials() throws {
        let config = makeConfig(noAuth: false, apiKey: "secret123")
        let dispatcher = makeDispatcher()
        var logger = Logger(label: "test")
        logger.logLevel = .critical

        // "x:secret123" — RPCAuth checks password against apiKey
        let encoded = encodeBase64("x:secret123")
        let request = buildHTTPRequest(
            body: #"{"method":"getblockcount","params":[],"id":1}"#,
            headers: [("Authorization", "Basic \(encoded)")]
        )
        let responseBytes = RPCNetworkServer.handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)
        let (status, body) = parseHTTPResponse(responseBytes)

        XCTAssertEqual(status, 200)
        XCTAssertTrue(body.contains("\"result\""))
    }

    func testMalformedJSON() throws {
        let config = makeConfig()
        let dispatcher = makeDispatcher()
        var logger = Logger(label: "test")
        logger.logLevel = .critical

        let request = buildHTTPRequest(body: "{not valid json")
        let responseBytes = RPCNetworkServer.handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)
        let (status, body) = parseHTTPResponse(responseBytes)

        // handleRaw returns a parse error response with 200 status
        XCTAssertEqual(status, 200)
        XCTAssertTrue(body.contains("error") || body.contains("-32700"))
    }

    func testUnknownMethod() throws {
        let config = makeConfig()
        let dispatcher = makeDispatcher()
        var logger = Logger(label: "test")
        logger.logLevel = .critical

        let request = buildHTTPRequest(body: #"{"method":"nonexistent","params":[],"id":1}"#)
        let responseBytes = RPCNetworkServer.handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)
        let (status, body) = parseHTTPResponse(responseBytes)

        XCTAssertEqual(status, 200)
        XCTAssertTrue(body.contains("error") || body.contains("-32601"))
    }

    func testResponseContentType() throws {
        let config = makeConfig()
        let dispatcher = makeDispatcher()
        var logger = Logger(label: "test")
        logger.logLevel = .critical

        let request = buildHTTPRequest(body: #"{"method":"getblockcount","params":[],"id":1}"#)
        let responseBytes = RPCNetworkServer.handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)

        // Verify response has Content-Type header
        let str = String(bytes: responseBytes, encoding: .utf8) ?? ""
        XCTAssertTrue(str.contains("Content-Type: application/json"))
    }

    // MARK: - HTTP Parser Tests

    func testHTTPParserBasic() throws {
        let request = "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
        let data = Array(request.utf8)
        guard let (parsed, consumed) = HTTPParser.parse(data) else {
            XCTFail("Failed to parse")
            return
        }
        XCTAssertEqual(consumed, data.count)
        XCTAssertEqual(parsed.method, "POST")
        XCTAssertEqual(parsed.uri, "/")
        XCTAssertEqual(parsed.body, Array("hello".utf8))
    }

    func testHTTPParserIncomplete() throws {
        let request = "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nhello"
        let data = Array(request.utf8)
        let result = HTTPParser.parse(data)
        XCTAssertNil(result, "Should return nil for incomplete request")
    }

    // MARK: - Base64 helper

    /// Simple base64 encoder for test use only.
    private func encodeBase64(_ string: String) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        let bytes = Array(string.utf8)
        var result = ""
        var i = 0
        while i < bytes.count {
            let b0 = bytes[i]
            let b1 = i + 1 < bytes.count ? bytes[i + 1] : 0
            let b2 = i + 2 < bytes.count ? bytes[i + 2] : 0
            let remaining = bytes.count - i

            result.append(alphabet[Int(b0 >> 2)])
            result.append(alphabet[Int((b0 & 0x03) << 4 | b1 >> 4)])
            result.append(remaining > 1 ? alphabet[Int((b1 & 0x0F) << 2 | b2 >> 6)] : Character("="))
            result.append(remaining > 2 ? alphabet[Int(b2 & 0x3F)] : Character("="))
            i += 3
        }
        return result
    }
}
