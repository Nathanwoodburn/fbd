import XCTest
@testable import Net
import Base

final class PacketCodecTests: XCTestCase {

    func testEncodeDecodeRoundTrip() throws {
        // Encode a ping
        let nonce: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let frame = PacketFramer.encode(type: .ping, payload: nonce, network: .regtest)

        // 9-byte header + 8-byte payload
        XCTAssertEqual(frame.count, 17)

        // Decode the header
        let header = try PacketFramer.decodeHeader(frame, network: .regtest)
        XCTAssertEqual(header.type, .ping)
        XCTAssertEqual(header.payloadSize, 8)

        // Extract payload
        let payload = Array(frame[NetConstants.headerSize...])
        XCTAssertEqual(payload, nonce)
    }

    func testEmptyPayload() throws {
        let frame = PacketFramer.encode(type: .verack, payload: [], network: .main)
        XCTAssertEqual(frame.count, 9) // header only

        let header = try PacketFramer.decodeHeader(frame, network: .main)
        XCTAssertEqual(header.type, .verack)
        XCTAssertEqual(header.payloadSize, 0)
    }

    func testPartialRead() throws {
        let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let frame = PacketFramer.encode(type: .pong, payload: payload, network: .regtest)

        // Accumulate bytes one at a time
        var accum = AccumulationBuffer()
        for byte in frame {
            accum.append([byte])
        }

        // Should have enough for header
        XCTAssertTrue(accum.readableBytes >= NetConstants.headerSize)

        // Decode header
        guard let headerBytes = accum.peek(NetConstants.headerSize) else {
            XCTFail("Not enough bytes for header")
            return
        }
        let header = try PacketFramer.decodeHeader(headerBytes, network: .regtest)
        XCTAssertEqual(header.type, .pong)
        XCTAssertEqual(header.payloadSize, 4)

        // Consume header + payload
        _ = accum.consume(NetConstants.headerSize)
        let decoded = accum.consume(header.payloadSize)
        XCTAssertEqual(decoded, payload)
    }

    func testMultipleFrames() throws {
        let frame1 = PacketFramer.encode(type: .ping, payload: [1, 2, 3, 4, 5, 6, 7, 8], network: .testnet)
        let frame2 = PacketFramer.encode(type: .verack, payload: [], network: .testnet)

        var accum = AccumulationBuffer()
        accum.append(frame1)
        accum.append(frame2)

        // Decode first frame
        guard let h1Bytes = accum.peek(NetConstants.headerSize) else {
            XCTFail("Not enough bytes")
            return
        }
        let h1 = try PacketFramer.decodeHeader(h1Bytes, network: .testnet)
        XCTAssertEqual(h1.type, .ping)
        _ = accum.consume(NetConstants.headerSize + h1.payloadSize)

        // Decode second frame
        guard let h2Bytes = accum.peek(NetConstants.headerSize) else {
            XCTFail("Not enough bytes for second frame")
            return
        }
        let h2 = try PacketFramer.decodeHeader(h2Bytes, network: .testnet)
        XCTAssertEqual(h2.type, .verack)
        XCTAssertEqual(h2.payloadSize, 0)
    }

    func testPeerMessageInit() {
        let msg = PeerMessage(type: .version, payload: [0x01, 0x02])
        XCTAssertEqual(msg.type, .version)
        XCTAssertEqual(msg.payload, [0x01, 0x02])
    }
}
