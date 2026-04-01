import XCTest
import Logging
@testable import DNS

final class DNSServerTests: XCTestCase {

    // MARK: - Helpers

    private func makeResolver() -> DNSResolver {
        var logger = Logger(label: "test")
        logger.logLevel = .critical
        return DNSResolver(logger: logger)
    }

    /// Build a minimal DNS query for the given name and type.
    private func buildQuery(name: String, qtype: UInt16 = 1, id: UInt16 = 0x1234) throws -> [UInt8] {
        let question = DNSQuestion(name: name, type: qtype, qclass: 1)
        let header = DNSHeader(
            id: id,
            flags: 0x0100, // standard query, recursion desired
            qdcount: 1, ancount: 0, nscount: 0, arcount: 0
        )
        let message = DNSMessage(
            header: header,
            questions: [question],
            answers: [],
            authority: [],
            additional: []
        )
        return try message.encode()
    }

    // MARK: - Tests

    func testAQueryReturnsNXDOMAIN() throws {
        let resolver = makeResolver()
        let queryBytes = try buildQuery(name: "example.hns")

        guard let responseBytes = resolver.resolve(query: queryBytes) else {
            XCTFail("No response")
            return
        }

        let responseMsg = try DNSMessage.decode(from: responseBytes)

        // Should be a response
        XCTAssertTrue(responseMsg.header.isResponse)

        // Should be NXDOMAIN (rcode = 3)
        XCTAssertEqual(responseMsg.header.rcode, 3)

        // Should be authoritative
        XCTAssertTrue(responseMsg.header.isAuthoritative)

        // Should echo back the query ID
        XCTAssertEqual(responseMsg.header.id, 0x1234)

        // Should have the question section
        XCTAssertEqual(responseMsg.questions.count, 1)

        // Should have no answer records
        XCTAssertEqual(responseMsg.answers.count, 0)
    }

    func testMalformedPacketDoesNotCrash() throws {
        let resolver = makeResolver()
        let response = resolver.resolve(query: [0xFF, 0x00, 0x01, 0x02])
        XCTAssertNil(response)
    }

    func testEmptyPacketIsIgnored() throws {
        let resolver = makeResolver()
        let response = resolver.resolve(query: [])
        XCTAssertNil(response)
    }

    func testAAAAQueryReturnsNXDOMAIN() throws {
        let resolver = makeResolver()
        // AAAA = type 28
        let queryBytes = try buildQuery(name: "test.hns", qtype: 28)

        guard let responseBytes = resolver.resolve(query: queryBytes) else {
            XCTFail("No response")
            return
        }

        let responseMsg = try DNSMessage.decode(from: responseBytes)

        XCTAssertTrue(responseMsg.header.isResponse)
        XCTAssertEqual(responseMsg.header.rcode, 3) // NXDOMAIN
        XCTAssertEqual(responseMsg.header.id, 0x1234)
    }

    func testResponsePreservesQueryID() throws {
        let resolver = makeResolver()
        let queryBytes = try buildQuery(name: "id-test.hns", id: 0xABCD)

        guard let responseBytes = resolver.resolve(query: queryBytes) else {
            XCTFail("No response")
            return
        }

        let responseMsg = try DNSMessage.decode(from: responseBytes)
        XCTAssertEqual(responseMsg.header.id, 0xABCD)
    }
}
