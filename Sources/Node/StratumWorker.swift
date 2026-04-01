import Base
import Foundation
import RPC

/// A connected Stratum mining worker.
///
/// Handles the JSON-RPC over TCP protocol for a single miner connection.
/// Each line is a complete JSON-RPC message terminated by newline.
final class StratumWorker: @unchecked Sendable {
    let id: UInt64
    let stream: SocketStream
    let extraNonce1: UInt32
    let remoteAddress: String

    var username: String?
    var isSubscribed = false
    var isAuthorized = false

    // Share stats
    var accepted: Int = 0
    var rejected: Int = 0
    var stale: Int = 0
    var blocks: Int = 0

    private let writeLock = NSLock()

    init(id: UInt64, stream: SocketStream, extraNonce1: UInt32, remoteAddress: String) {
        self.id = id
        self.stream = stream
        self.extraNonce1 = extraNonce1
        self.remoteAddress = remoteAddress
    }

    /// Run the read loop, dispatching messages to the server.
    func run(server: StratumServer) async {
        var accumulator = AccumulationBuffer()

        while true {
            do {
                let data = try await stream.read()
                guard !data.isEmpty else { break }
                accumulator.append(data)
                guard accumulator.readableBytes <= 65536 else { return } // 64KB max
            } catch {
                break
            }

            // Process complete lines
            while let line = accumulator.consumeLine() {
                guard !line.isEmpty else { continue }
                let json = String(bytes: line, encoding: .utf8) ?? ""
                handleMessage(json, server: server)
            }
        }

        await stream.close()
    }

    /// Parse and dispatch a JSON-RPC message.
    private func handleMessage(_ json: String, server: StratumServer) {
        guard let parsed = try? JSONParser.parse(json) else { return }

        let id = parsed["id"] ?? .null
        guard let method = parsed["method"]?.stringValue else { return }
        let params = parsed["params"]?.arrayValue ?? []

        switch method {
        case "mining.subscribe":
            server.handleSubscribe(worker: self, id: id)
        case "mining.authorize":
            server.handleAuthorize(worker: self, id: id, params: params)
        case "mining.submit":
            guard isAuthorized else {
                sendResponse(id: id, result: nil, error: .string("not authorized"))
                return
            }
            server.handleSubmit(worker: self, id: id, params: params)
        default:
            sendResponse(id: id, result: nil, error: .string("unknown method"))
        }
    }

    // MARK: - Sending

    /// Send a JSON-RPC response.
    func sendResponse(id: JSONValue, result: JSONValue?, error: JSONValue? = nil) {
        var pairs: [(String, JSONValue)] = [("id", id)]
        pairs.append(("result", result ?? .null))
        pairs.append(("error", error ?? .null))
        sendJSON(JSONValue.object(pairs))
    }

    /// Send a mining.notify message.
    func sendNotify(job: StratumJob) {
        let h = job.template.header
        let params = JSONValue.array([
            .string(job.id),
            .string(h.prevBlock.hex),
            .string(h.merkleRoot.hex),
            .string(h.witnessRoot.hex),
            .string(h.treeRoot.hex),
            .string(h.reservedRoot.hex),
            .string(String(format: "%08x", h.version)),
            .string(String(format: "%08x", h.bits)),
            .string(HexEncoding.encode(withUnsafeBytes(of: h.time.littleEndian) { Array($0) })),
            .string(HexEncoding.encode(job.poolExtraNonce)),
            .bool(true),
        ])
        let msg = JSONValue.object([
            ("id", .null),
            ("method", .string("mining.notify")),
            ("params", params),
        ])
        sendJSON(msg)
    }

    /// Send a raw JSON value as a newline-terminated message.
    private func sendJSON(_ value: JSONValue) {
        let encoded = JSONEncoder.encode(value) + "\n"
        let bytes = Array(encoded.utf8)
        writeLock.lock()
        defer { writeLock.unlock() }
        Task {
            try? await stream.write(bytes)
        }
    }

    /// Close the connection.
    func close() {
        Task { await stream.close() }
    }

}

// MARK: - AccumulationBuffer line reading

extension AccumulationBuffer {
    /// Consume bytes up to and including the first newline, returning the line (without newline).
    mutating func consumeLine() -> [UInt8]? {
        let available = readableBytes
        guard available > 0 else { return nil }
        guard let bytes = peek(available) else { return nil }
        guard let nlIndex = bytes.firstIndex(of: UInt8(ascii: "\n")) else { return nil }
        let lineLen = bytes.distance(from: bytes.startIndex, to: nlIndex)
        let line = Array(bytes[..<nlIndex])
        _ = consume(lineLen + 1)  // consume line + newline
        compact()
        return line
    }
}
