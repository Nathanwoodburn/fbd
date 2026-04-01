import XCTest
@testable import DNS
import Base

// MARK: - DANE Prefix Parsing

final class DANEPrefixTests: XCTestCase {

    func testParseDANEPrefixTCP() {
        let result = ResourceConverter.parseDANEPrefix("_443._tcp.fistbump.")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.port, 443)
        XCTAssertEqual(result?.protocol, 6)
        XCTAssertEqual(result?.baseFQDN, "fistbump.")
    }

    func testParseDANEPrefixUDP() {
        let result = ResourceConverter.parseDANEPrefix("_53._udp.fistbump.")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.port, 53)
        XCTAssertEqual(result?.protocol, 17)
        XCTAssertEqual(result?.baseFQDN, "fistbump.")
    }

    func testParseDANEPrefixSCTP() {
        let result = ResourceConverter.parseDANEPrefix("_5000._sctp.fistbump.")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.port, 5000)
        XCTAssertEqual(result?.protocol, 132)
    }

    func testParseDANEPrefixSubdomain() {
        let result = ResourceConverter.parseDANEPrefix("_443._tcp.example.fistbump.")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.port, 443)
        XCTAssertEqual(result?.protocol, 6)
        XCTAssertEqual(result?.baseFQDN, "example.fistbump.")
    }

    func testParseDANEPrefixNoDot() {
        let result = ResourceConverter.parseDANEPrefix("_443._tcp.fistbump")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.port, 443)
    }

    func testParseDANEPrefixNotDANE() {
        // Regular name — no DANE prefix
        XCTAssertNil(ResourceConverter.parseDANEPrefix("fistbump."))
        XCTAssertNil(ResourceConverter.parseDANEPrefix("example.fistbump."))
    }

    func testParseDANEPrefixInvalidPort() {
        XCTAssertNil(ResourceConverter.parseDANEPrefix("_abc._tcp.fistbump."))
    }

    func testParseDANEPrefixInvalidProtocol() {
        XCTAssertNil(ResourceConverter.parseDANEPrefix("_443._xyz.fistbump."))
    }

    func testParseDANEPrefixTooFewLabels() {
        XCTAssertNil(ResourceConverter.parseDANEPrefix("_443._tcp."))
    }
}

// MARK: - TLSA Record Format

final class TLSARecordTests: XCTestCase {

    func testTLSAEncodeDecodeFull() throws {
        let cert: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let resource = Resource(records: [
            .tlsa(port: 443, protocol: 6, usage: 3, selector: 1, matchingType: 1, certificate: cert),
        ])
        let encoded = try resource.encode()
        let decoded = try Resource.decode(from: encoded)

        XCTAssertEqual(decoded.records.count, 1)
        if case .tlsa(let port, let proto, let usage, let selector, let matchingType, let certificate) = decoded.records[0] {
            XCTAssertEqual(port, 443)
            XCTAssertEqual(proto, 6)
            XCTAssertEqual(usage, 3)
            XCTAssertEqual(selector, 1)
            XCTAssertEqual(matchingType, 1)
            XCTAssertEqual(certificate, cert)
        } else {
            XCTFail("Expected TLSA record")
        }
    }

    func testTLSAMultiplePorts() throws {
        let resource = Resource(records: [
            .tlsa(port: 443, protocol: 6, usage: 3, selector: 1, matchingType: 1, certificate: [0xAA]),
            .tlsa(port: 25, protocol: 6, usage: 3, selector: 1, matchingType: 1, certificate: [0xBB]),
        ])
        let encoded = try resource.encode()
        let decoded = try Resource.decode(from: encoded)
        XCTAssertEqual(decoded.records.count, 2)
    }

    func testTLSAWithOtherRecords() throws {
        let resource = Resource(records: [
            .a(address: [192, 168, 1, 1]),
            .tlsa(port: 443, protocol: 6, usage: 3, selector: 1, matchingType: 1, certificate: [0xAA, 0xBB]),
            .txt(strings: ["hello"]),
        ])
        let encoded = try resource.encode()
        let decoded = try Resource.decode(from: encoded)
        XCTAssertEqual(decoded.records.count, 3)
    }
}

// MARK: - Subdomain DNS Resolution

final class SubdomainResolutionTests: XCTestCase {

    func testResolverExactName() throws {
        // Simulate: "fistbump" is registered with an A record
        let resource = Resource(records: [.a(address: [1, 2, 3, 4])])
        let data = try resource.encode()

        let resolver = DNSResolver(logger: .init(label: "test"), lookup: { name in
            if name == "fistbump" { return data }
            return nil
        })

        let query = try makeQuery(name: "fistbump.", type: .a)
        guard let response = resolver.resolve(query: query) else {
            XCTFail("Expected response"); return
        }
        let msg = try DNSMessage.decode(from: response)
        XCTAssertEqual(msg.answers.count, 1)
    }

    func testResolverSubdomainExact() throws {
        // "example.fistbump" has its own resource data
        let parentResource = Resource(records: [.a(address: [1, 1, 1, 1])])
        let subResource = Resource(records: [.a(address: [2, 2, 2, 2])])
        let parentData = try parentResource.encode()
        let subData = try subResource.encode()

        let resolver = DNSResolver(logger: .init(label: "test"), lookup: { name in
            if name == "fistbump" { return parentData }
            if name == "example.fistbump" { return subData }
            return nil
        })

        // Query for example.fistbump should get its records, not parent's referral
        let query = try makeQuery(name: "example.fistbump.", type: .a)
        guard let response = resolver.resolve(query: query) else {
            XCTFail("Expected response"); return
        }
        let msg = try DNSMessage.decode(from: response)
        XCTAssertEqual(msg.answers.count, 1)
        // Should be example.fistbump's IP, not parent's
        XCTAssertEqual(msg.answers[0].rdata, [2, 2, 2, 2])
    }

    func testResolverSubdomainFallsBackToParent() throws {
        // "fistbump" has NS records, "unknown.fistbump" doesn't exist
        let parentResource = Resource(records: [
            .ns(name: "ns1.fistbump."),
        ])
        let parentData = try parentResource.encode()

        let resolver = DNSResolver(logger: .init(label: "test"), lookup: { name in
            if name == "fistbump" { return parentData }
            return nil
        })

        // Query for unknown.fistbump should fall back to parent and get a referral
        let query = try makeQuery(name: "unknown.fistbump.", type: .a)
        guard let response = resolver.resolve(query: query) else {
            XCTFail("Expected response"); return
        }
        let msg = try DNSMessage.decode(from: response)
        XCTAssertEqual(msg.answers.count, 0)
        XCTAssertFalse(msg.authority.isEmpty, "Should have NS authority records")
    }

    func testResolverDANEQuery() throws {
        let cert: [UInt8] = [0xDE, 0xAD]
        let resource = Resource(records: [
            .a(address: [1, 2, 3, 4]),
            .tlsa(port: 443, protocol: 6, usage: 3, selector: 1, matchingType: 1, certificate: cert),
        ])
        let data = try resource.encode()

        let resolver = DNSResolver(logger: .init(label: "test"), lookup: { name in
            if name == "fistbump" { return data }
            return nil
        })

        let query = try makeQuery(name: "_443._tcp.fistbump.", type: .tlsa)
        guard let response = resolver.resolve(query: query) else {
            XCTFail("Expected response"); return
        }
        let msg = try DNSMessage.decode(from: response)
        XCTAssertEqual(msg.answers.count, 1)
        XCTAssertEqual(msg.answers[0].name, "_443._tcp.fistbump.")
    }

    func testResolverNXDOMAIN() throws {
        let resolver = DNSResolver(logger: .init(label: "test"), lookup: { _ in nil })
        let query = try makeQuery(name: "nonexistent.", type: .a)
        guard let response = resolver.resolve(query: query) else {
            XCTFail("Expected response"); return
        }
        let msg = try DNSMessage.decode(from: response)
        let rcode = msg.header.flags & 0x000F
        XCTAssertEqual(rcode, UInt16(DNSRcode.nxdomain.rawValue))
    }

    // MARK: - Helpers

    private func makeQuery(name: String, type: DNSType) throws -> [UInt8] {
        let msg = DNSMessage(
            header: DNSHeader(id: 1234, flags: 0x0100), // RD=1
            questions: [DNSQuestion(name: name, type: type.rawValue, qclass: DNSClass.in.rawValue)],
            answers: [],
            authority: [],
            additional: []
        )
        return try msg.encode()
    }
}
