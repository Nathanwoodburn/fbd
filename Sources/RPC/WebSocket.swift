import Base
import ExtCrypto

/// Minimal WebSocket server implementation (RFC 6455).
public enum WebSocket {

    /// The WebSocket GUID used in the handshake.
    private static let magic = "258EAFA5-E914-47DA-95CA-5AB5DCDD11B5"

    // MARK: - Handshake

    /// Validate an HTTP request as a WebSocket upgrade and return the accept key.
    /// Returns nil if the request is not a valid WebSocket upgrade.
    public static func acceptKey(for request: HTTPRequest) -> String? {
        guard request.method == "GET",
              request.header("Upgrade")?.lowercased() == "websocket",
              request.header("Connection")?.lowercased().contains("upgrade") == true,
              let key = request.header("Sec-WebSocket-Key") else {
            return nil
        }
        let combined = key + magic
        let hash = SHA1Hash.hash(Array(combined.utf8))
        return Base64.encode(hash)
    }

    /// Build the HTTP 101 Switching Protocols response.
    public static func upgradeResponse(acceptKey: String) -> [UInt8] {
        let response = "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Accept: \(acceptKey)\r\n" +
            "\r\n"
        return Array(response.utf8)
    }

    // MARK: - Frame encoding

    /// Encode a text frame (server → client, no masking).
    public static func textFrame(_ text: String) -> [UInt8] {
        let payload = Array(text.utf8)
        return frame(opcode: 0x01, payload: payload)
    }

    /// Encode a close frame.
    public static func closeFrame(code: UInt16 = 1000) -> [UInt8] {
        let payload: [UInt8] = [UInt8(code >> 8), UInt8(code & 0xFF)]
        return frame(opcode: 0x08, payload: payload)
    }

    /// Encode a pong frame with the given payload.
    public static func pongFrame(payload: [UInt8]) -> [UInt8] {
        frame(opcode: 0x0A, payload: payload)
    }

    private static func frame(opcode: UInt8, payload: [UInt8]) -> [UInt8] {
        var frame = [UInt8]()
        frame.append(0x80 | opcode) // FIN + opcode
        if payload.count < 126 {
            frame.append(UInt8(payload.count))
        } else if payload.count <= 0xFFFF {
            frame.append(126)
            frame.append(UInt8(payload.count >> 8))
            frame.append(UInt8(payload.count & 0xFF))
        } else {
            frame.append(127)
            for i in (0..<8).reversed() {
                frame.append(UInt8((payload.count >> (i * 8)) & 0xFF))
            }
        }
        frame.append(contentsOf: payload)
        return frame
    }

    // MARK: - Frame decoding

    /// A decoded WebSocket frame.
    public struct Frame {
        public let opcode: UInt8
        public let payload: [UInt8]
        public let bytesConsumed: Int
    }

    /// Try to parse a WebSocket frame from the buffer.
    /// Returns nil if not enough data yet.
    public static func parseFrame(_ data: [UInt8]) -> Frame? {
        guard data.count >= 2 else { return nil }

        let opcode = data[0] & 0x0F
        let masked = (data[1] & 0x80) != 0
        var payloadLen = UInt64(data[1] & 0x7F)
        var offset = 2

        if payloadLen == 126 {
            guard data.count >= 4 else { return nil }
            payloadLen = UInt64(data[2]) << 8 | UInt64(data[3])
            offset = 4
        } else if payloadLen == 127 {
            guard data.count >= 10 else { return nil }
            payloadLen = 0
            for i in 0..<8 {
                payloadLen = payloadLen << 8 | UInt64(data[2 + i])
            }
            offset = 10
        }

        // Reject frames larger than 16MB to prevent memory exhaustion
        guard payloadLen <= 16 * 1024 * 1024 else { return nil }

        var maskKey: [UInt8] = []
        if masked {
            guard data.count >= offset + 4 else { return nil }
            maskKey = Array(data[offset..<offset+4])
            offset += 4
        }

        let totalNeeded = offset + Int(payloadLen)
        guard data.count >= totalNeeded else { return nil }

        var payload = Array(data[offset..<totalNeeded])
        if masked {
            for i in 0..<payload.count {
                payload[i] ^= maskKey[i % 4]
            }
        }

        return Frame(opcode: opcode, payload: payload, bytesConsumed: totalNeeded)
    }
}
