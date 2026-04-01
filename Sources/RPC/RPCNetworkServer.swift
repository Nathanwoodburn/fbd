import Base
import Foundation
import Logging

/// HTTP server that serves JSON-RPC requests.
///
/// Binds a TCP socket and handles HTTP requests directly (no NIO).
/// Each connection runs in its own Task, parsing HTTP, checking auth,
/// dispatching to RPCDispatcher, and writing the response.
public final class RPCNetworkServer: Sendable {
    private let config: RPCConfig
    private let dispatcher: RPCDispatcher
    private let logger: Logger

    /// Callback for WebSocket upgrade requests. Receives the stream to own.
    public let onWebSocket: @Sendable (SocketStream) async -> Void

    /// Callback for SSE (Server-Sent Events) connections. Receives the stream and URI.
    public let onSSE: @Sendable (SocketStream, String) async -> Void

    nonisolated(unsafe) private var listener: TCPListener?

    /// Maximum concurrent RPC connections.
    private static let maxConnections = 128
    private static let connectionLock = NSLock()
    nonisolated(unsafe) private static var activeConnections = 0

    public init(
        config: RPCConfig,
        dispatcher: RPCDispatcher,
        logger: Logger,
        onWebSocket: @escaping @Sendable (SocketStream) async -> Void = { stream in await stream.close() },
        onSSE: @escaping @Sendable (SocketStream, String) async -> Void = { stream, _ in await stream.close() }
    ) {
        self.config = config
        self.dispatcher = dispatcher
        self.logger = logger
        self.onWebSocket = onWebSocket
        self.onSSE = onSSE
    }

    /// Start the HTTP server.
    public func start() throws {
        let tcp = try TCPListener(host: config.host, port: config.port)
        self.listener = tcp

        let config = self.config
        let dispatcher = self.dispatcher
        let logger = self.logger
        let onWebSocket = self.onWebSocket
        let onSSE = self.onSSE

        tcp.accept { stream, ip, port in
            // Reject connections above the limit to prevent resource exhaustion
            Self.connectionLock.lock()
            guard Self.activeConnections < Self.maxConnections else {
                Self.connectionLock.unlock()
                await stream.close()
                return
            }
            Self.activeConnections += 1
            Self.connectionLock.unlock()

            defer {
                Self.connectionLock.lock()
                Self.activeConnections -= 1
                Self.connectionLock.unlock()
            }

            await Self.handleConnection(
                stream: stream,
                config: config,
                dispatcher: dispatcher,
                logger: logger,
                onWebSocket: onWebSocket,
                onSSE: onSSE
            )
        }
    }

    /// Shut down the server.
    public func shutdown() {
        listener?.shutdown()
        listener = nil
    }

    // MARK: - Connection Handler

    private static func handleConnection(
        stream: SocketStream,
        config: RPCConfig,
        dispatcher: RPCDispatcher,
        logger: Logger,
        onWebSocket: @Sendable (SocketStream) async -> Void,
        onSSE: @Sendable (SocketStream, String) async -> Void
    ) async {
        var accumulator = AccumulationBuffer()

        // Process requests in a loop (HTTP keep-alive)
        while true {
            // Read data
            do {
                let data = try await stream.read()
                guard !data.isEmpty else { break } // EOF
                accumulator.append(data)
            } catch {
                break
            }

            // Reject connections that exceed the body size limit
            if accumulator.readableBytes > HTTPParser.maxBodySize + 8192 {
                let response = HTTPResponse.badRequest(body: "{\"error\":\"request too large\"}")
                try? await stream.write(response)
                await stream.close()
                return
            }

            // Try to parse complete HTTP requests
            while true {
                // Peek at all readable bytes
                let available = accumulator.readableBytes
                guard available > 0 else { break }
                guard let bytes = accumulator.peek(available) else { break }

                guard let (request, consumed) = HTTPParser.parse(bytes) else { break }
                _ = accumulator.consume(consumed)
                accumulator.compact()

                // Auth check — applies to all request types (POST, WebSocket, SSE)
                if !config.noAuth {
                    guard let apiKey = config.apiKey, !apiKey.isEmpty else {
                        let resp = HTTPResponse.unauthorized(body: "{\"error\":\"Unauthorized\"}")
                        try? await stream.write(resp)
                        await stream.close()
                        return
                    }
                    if !checkAuth(request: request, apiKey: apiKey) {
                        let resp = HTTPResponse.unauthorized(body: "{\"error\":\"Unauthorized\"}")
                        try? await stream.write(resp)
                        await stream.close()
                        return
                    }
                }

                // Check for WebSocket upgrade
                if let acceptKey = WebSocket.acceptKey(for: request) {
                    let upgradeResponse = WebSocket.upgradeResponse(acceptKey: acceptKey)
                    do {
                        try await stream.write(upgradeResponse)
                    } catch {
                        await stream.close()
                        return
                    }
                    logger.debug("WebSocket upgrade", source: "RPC")
                    // Hand off to WebSocket handler — it owns the stream now
                    await onWebSocket(stream)
                    return
                }

                // Check for SSE (Server-Sent Events) request: GET /events
                if request.method == "GET" && request.uri.hasPrefix("/events") {
                    let sseHeaders = "HTTP/1.1 200 OK\r\n" +
                        "Content-Type: text/event-stream\r\n" +
                        "Cache-Control: no-cache\r\n" +
                        "Connection: keep-alive\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "\r\n"
                    do {
                        try await stream.write(Array(sseHeaders.utf8))
                    } catch {
                        await stream.close()
                        return
                    }
                    logger.debug("SSE stream", source: "RPC")
                    await onSSE(stream, request.uri)
                    return
                }

                // Run synchronous RPC dispatch on GCD to avoid blocking
                // the cooperative thread pool.
                let response = await withCheckedContinuation { cont in
                    DispatchQueue.global(qos: .userInitiated).async {
                        let result = handleRequest(request, config: config, dispatcher: dispatcher, logger: logger)
                        cont.resume(returning: result)
                    }
                }

                do {
                    try await stream.write(response)
                } catch {
                    await stream.close()
                    return
                }
            }
        }

        await stream.close()
    }

    // MARK: - Request Handler

    /// Process a single HTTP request and return the response bytes.
    static func handleRequest(
        _ request: HTTPRequest,
        config: RPCConfig,
        dispatcher: RPCDispatcher,
        logger: Logger
    ) -> [UInt8] {
        // Only accept POST (non-WebSocket GET is rejected)
        guard request.method == "POST" else {
            return HTTPResponse.methodNotAllowed(body: "{\"error\":\"Method not allowed\"}")
        }

        // Check auth
        if !config.noAuth {
            guard let apiKey = config.apiKey, !apiKey.isEmpty else {
                return HTTPResponse.unauthorized(body: "{\"error\":\"Unauthorized\"}")
            }

            if !checkAuth(request: request, apiKey: apiKey) {
                return HTTPResponse.unauthorized(body: "{\"error\":\"Unauthorized\"}")
            }
        }

        // Extract JSON body and dispatch
        let json: String
        if !request.body.isEmpty {
            json = String(bytes: request.body, encoding: .utf8) ?? ""
        } else {
            json = ""
        }

        // Log RPC call with method name and source
        let source = request.header("User-Agent").map {
            $0.contains("fbdctl") ? "fbdctl" : "http"
        } ?? "http"
        if let methodName = extractMethod(from: json) {
            logger.debug("\(methodName) (\(source))")
        }

        let responseJSON = dispatcher.handleRaw(json)
        return HTTPResponse.ok(body: responseJSON)
    }

    // MARK: - Auth

    private static func checkAuth(request: HTTPRequest, apiKey: String) -> Bool {
        // Check query parameter auth (for SSE/WebSocket where headers can't be set)
        if let uri = request.uri.split(separator: "?", maxSplits: 1).dropFirst().first {
            for param in uri.split(separator: "&") {
                let kv = param.split(separator: "=", maxSplits: 1)
                if kv.count == 2 && kv[0] == "key" {
                    return RPCAuth.validate(username: "x", password: String(kv[1]), apiKey: apiKey)
                }
            }
        }

        guard let authHeader = request.header("Authorization") else {
            return false
        }

        guard authHeader.hasPrefix("Basic ") else {
            return false
        }

        let encoded = String(authHeader.dropFirst(6))
        guard let decoded = Base64.decodeString(encoded) else {
            return false
        }

        // Format is "username:password"
        let parts = decoded.split(separator: ":", maxSplits: 1)
        guard parts.count == 2 else {
            return false
        }

        let username = String(parts[0])
        let password = String(parts[1])

        return RPCAuth.validate(username: username, password: password, apiKey: apiKey)
    }

    // MARK: - Helpers

    /// Quick extraction of the "method" value from a JSON-RPC request string.
    private static func extractMethod(from json: String) -> String? {
        guard let range = json.range(of: "\"method\"") else { return nil }
        let after = json[range.upperBound...]
        guard let colonIdx = after.firstIndex(of: ":") else { return nil }
        let afterColon = after[after.index(after: colonIdx)...]
        guard let openQuote = afterColon.firstIndex(of: "\"") else { return nil }
        let afterOpen = afterColon[afterColon.index(after: openQuote)...]
        guard let closeQuote = afterOpen.firstIndex(of: "\"") else { return nil }
        return String(afterOpen[..<closeQuote])
    }
}
