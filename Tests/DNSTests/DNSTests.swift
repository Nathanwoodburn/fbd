import XCTest
@testable import DNS
@testable import Base

// MARK: - DNS Name Tests

final class DNSNameTests: XCTestCase {

    func testEncodeSimpleName() throws {
        let encoded = try DNSName.encode("example.com.")
        // 7 "example" 3 "com" 0
        XCTAssertEqual(encoded, [7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 3, 0x63, 0x6F, 0x6D, 0])
    }

    func testEncodeRootName() throws {
        let encoded = try DNSName.encode(".")
        XCTAssertEqual(encoded, [0])
    }

    func testEncodeWithoutTrailingDot() throws {
        let with = try DNSName.encode("test.example.")
        let without = try DNSName.encode("test.example")
        XCTAssertEqual(with, without)
    }

    func testDecodeSimpleName() throws {
        let data: [UInt8] = [7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 3, 0x63, 0x6F, 0x6D, 0]
        var reader = BufferReader(data)
        let name = try DNSName.decode(from: &reader)
        XCTAssertEqual(name, "example.com.")
    }

    func testDecodeRootName() throws {
        let data: [UInt8] = [0]
        var reader = BufferReader(data)
        let name = try DNSName.decode(from: &reader)
        XCTAssertEqual(name, ".")
    }

    func testEncodeDecodeRoundTrip() throws {
        let names = ["example.", "foo.bar.baz.", "a.b.c.d.e.", "x."]
        for name in names {
            let encoded = try DNSName.encode(name)
            var reader = BufferReader(encoded)
            let decoded = try DNSName.decode(from: &reader)
            XCTAssertEqual(decoded, name, "Round-trip failed for \(name)")
        }
    }

    func testCompressionPointer() throws {
        // Build a message with compression: write "example.com." then a pointer to it
        var writer = BufferWriter()
        var compression = [String: Int]()

        try DNSName.write("example.com.", to: &writer, compression: &compression)
        let firstEnd = writer.count

        // Write same name again — should use compression pointer
        try DNSName.write("example.com.", to: &writer, compression: &compression)

        let data = writer.data
        // Second write should be a 2-byte pointer, not a full name
        XCTAssertEqual(writer.count, firstEnd + 2)

        // Decode the pointer
        var reader = BufferReader(data)
        reader.offset = firstEnd
        let decoded = try DNSName.decode(from: &reader, message: data)
        XCTAssertEqual(decoded, "example.com.")
    }

    func testLabelTooLong() {
        let longLabel = String(repeating: "a", count: 64) + ".com."
        XCTAssertThrowsError(try DNSName.encode(longLabel))
    }

    func testSuffixCompression() throws {
        // Write "foo.example.com." then "bar.example.com." — the suffix should compress
        var writer = BufferWriter()
        var compression = [String: Int]()

        try DNSName.write("foo.example.com.", to: &writer, compression: &compression)
        let firstEnd = writer.count

        try DNSName.write("bar.example.com.", to: &writer, compression: &compression)
        let secondEnd = writer.count

        // "bar" label (1+3) + pointer to "example.com." (2) = 6 bytes
        XCTAssertEqual(secondEnd - firstEnd, 6)
    }
}

// MARK: - DNS Header Tests

final class DNSHeaderTests: XCTestCase {

    func testFlagAccessors() {
        var header = DNSHeader()
        XCTAssertFalse(header.isResponse)

        header.isResponse = true
        XCTAssertTrue(header.isResponse)

        header.isAuthoritative = true
        XCTAssertTrue(header.isAuthoritative)

        header.recursionDesired = true
        XCTAssertTrue(header.recursionDesired)

        header.rcode = DNSRcode.nxdomain.rawValue
        XCTAssertEqual(header.rcode, 3)

        header.opcode = 2
        XCTAssertEqual(header.opcode, 2)
    }

    func testHeaderRoundTrip() throws {
        var original = DNSHeader()
        original.id = 0x1234
        original.isResponse = true
        original.isAuthoritative = true
        original.rcode = DNSRcode.noerror.rawValue
        original.qdcount = 1
        original.ancount = 2

        var writer = BufferWriter()
        original.write(to: &writer)
        XCTAssertEqual(writer.count, 12)

        var reader = BufferReader(writer.data)
        let decoded = try DNSHeader.read(from: &reader)
        XCTAssertEqual(decoded, original)
    }

    func testTruncationFlag() {
        var header = DNSHeader()
        header.isTruncated = true
        XCTAssertTrue(header.isTruncated)
        header.isTruncated = false
        XCTAssertFalse(header.isTruncated)
    }

    func testAuthenticatedDataFlag() {
        var header = DNSHeader()
        header.authenticatedData = true
        XCTAssertTrue(header.authenticatedData)
        header.checkingDisabled = true
        XCTAssertTrue(header.checkingDisabled)
    }
}

// MARK: - DNS Question Tests

final class DNSQuestionTests: XCTestCase {

    func testQuestionRoundTrip() throws {
        let question = DNSQuestion(name: "example.", type: DNSType.a.rawValue)

        var writer = BufferWriter()
        var compression = [String: Int]()
        try question.write(to: &writer, compression: &compression)

        var reader = BufferReader(writer.data)
        let decoded = try DNSQuestion.read(from: &reader, message: writer.data)
        XCTAssertEqual(decoded, question)
    }
}

// MARK: - DNS Record Tests

final class DNSRecordTests: XCTestCase {

    func testARecord() throws {
        let record = DNSRecord.a(name: "example.", ip: [192, 168, 1, 1])
        XCTAssertEqual(record.type, DNSType.a.rawValue)
        XCTAssertEqual(record.rdata, [192, 168, 1, 1])
    }

    func testAAAARecord() throws {
        let ip: [UInt8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let record = DNSRecord.aaaa(name: "example.", ip: ip)
        XCTAssertEqual(record.type, DNSType.aaaa.rawValue)
        XCTAssertEqual(record.rdata, ip)
    }

    func testNSRecord() throws {
        let record = try DNSRecord.ns(name: "example.", ns: "ns1.example.")
        XCTAssertEqual(record.type, DNSType.ns.rawValue)
        // RDATA should be the encoded name
        let expectedRdata = try DNSName.encode("ns1.example.")
        XCTAssertEqual(record.rdata, expectedRdata)
    }

    func testTXTRecord() {
        let record = DNSRecord.txt(name: "example.", strings: ["hello", "world"])
        XCTAssertEqual(record.type, DNSType.txt.rawValue)
        // RDATA: len(5) + "hello" + len(5) + "world"
        XCTAssertEqual(record.rdata.count, 12)
    }

    func testDSRecord() {
        let digest: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let record = DNSRecord.ds(
            name: "example.",
            keyTag: 0x1234,
            algorithm: 8,
            digestType: 2,
            digest: digest
        )
        XCTAssertEqual(record.type, DNSType.ds.rawValue)
        // RDATA: keyTag(2) + algorithm(1) + digestType(1) + digest(4) = 8
        XCTAssertEqual(record.rdata.count, 8)
        XCTAssertEqual(record.rdata[0], 0x12) // keyTag high byte
        XCTAssertEqual(record.rdata[1], 0x34) // keyTag low byte
        XCTAssertEqual(record.rdata[2], 8)    // algorithm
        XCTAssertEqual(record.rdata[3], 2)    // digestType
    }

    func testSOARecord() throws {
        let record = try DNSRecord.soa(name: ".", serial: 1)
        XCTAssertEqual(record.type, DNSType.soa.rawValue)
        XCTAssertEqual(record.ttl, DNSConstants.soaTTL)
    }

    func testRecordRoundTrip() throws {
        let original = DNSRecord.a(name: "test.", ip: [10, 0, 0, 1])

        var writer = BufferWriter()
        var compression = [String: Int]()
        try original.write(to: &writer, compression: &compression)

        var reader = BufferReader(writer.data)
        let decoded = try DNSRecord.read(from: &reader, message: writer.data)
        XCTAssertEqual(decoded, original)
    }
}

// MARK: - DNS Message Tests

final class DNSMessageTests: XCTestCase {

    func testEmptyMessageRoundTrip() throws {
        let msg = DNSMessage(header: DNSHeader(id: 0xABCD))
        let encoded = try msg.encode()
        let decoded = try DNSMessage.decode(from: encoded)
        XCTAssertEqual(decoded.header.id, 0xABCD)
        XCTAssertTrue(decoded.questions.isEmpty)
        XCTAssertTrue(decoded.answers.isEmpty)
    }

    func testQueryMessageRoundTrip() throws {
        var header = DNSHeader(id: 0x1234)
        header.recursionDesired = true

        let question = DNSQuestion(name: "example.", type: DNSType.a.rawValue)

        let msg = DNSMessage(header: header, questions: [question])
        let encoded = try msg.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        XCTAssertEqual(decoded.header.id, 0x1234)
        XCTAssertTrue(decoded.header.recursionDesired)
        XCTAssertEqual(decoded.questions.count, 1)
        XCTAssertEqual(decoded.questions[0].name, "example.")
        XCTAssertEqual(decoded.questions[0].type, DNSType.a.rawValue)
    }

    func testResponseMessage() throws {
        var queryHeader = DNSHeader(id: 0x5678)
        queryHeader.recursionDesired = true
        let query = DNSMessage(
            header: queryHeader,
            questions: [DNSQuestion(name: "test.", type: DNSType.a.rawValue)]
        )

        let answer = DNSRecord.a(name: "test.", ip: [1, 2, 3, 4])
        let response = DNSMessage.response(for: query, answers: [answer])

        XCTAssertEqual(response.header.id, 0x5678)
        XCTAssertTrue(response.header.isResponse)
        XCTAssertTrue(response.header.isAuthoritative)
        XCTAssertTrue(response.header.recursionDesired)
        XCTAssertEqual(response.header.rcode, 0)
        XCTAssertEqual(response.answers.count, 1)
    }

    func testFullResponseRoundTrip() throws {
        let query = DNSMessage(
            header: DNSHeader(id: 0xBEEF),
            questions: [DNSQuestion(name: "test.", type: DNSType.a.rawValue)]
        )
        let answer = DNSRecord.a(name: "test.", ip: [10, 0, 0, 1])
        let ns = try DNSRecord.ns(name: "test.", ns: "ns1.test.")
        let glue = DNSRecord.a(name: "ns1.test.", ip: [10, 0, 0, 2])

        let response = DNSMessage.response(
            for: query,
            answers: [answer],
            authority: [ns],
            additional: [glue]
        )

        let encoded = try response.encode()
        let decoded = try DNSMessage.decode(from: encoded)

        XCTAssertEqual(decoded.header.id, 0xBEEF)
        XCTAssertTrue(decoded.header.isResponse)
        XCTAssertEqual(decoded.questions.count, 1)
        XCTAssertEqual(decoded.answers.count, 1)
        XCTAssertEqual(decoded.authority.count, 1)
        XCTAssertEqual(decoded.additional.count, 1)

        XCTAssertEqual(decoded.answers[0].rdata, [10, 0, 0, 1])
        XCTAssertEqual(decoded.additional[0].rdata, [10, 0, 0, 2])
    }

    func testNXDomainResponse() {
        let query = DNSMessage(
            header: DNSHeader(id: 1),
            questions: [DNSQuestion(name: "missing.", type: DNSType.a.rawValue)]
        )
        let response = DNSMessage.response(for: query, rcode: .nxdomain)
        XCTAssertEqual(response.header.rcode, DNSRcode.nxdomain.rawValue)
    }
}

// MARK: - FBD Resource Tests

final class ResourceTests: XCTestCase {

    func testEmptyResource() throws {
        let resource = try Resource.decode(from: [])
        XCTAssertTrue(resource.records.isEmpty)
    }

    func testVersionZeroOnly() throws {
        let resource = try Resource.decode(from: [0])
        XCTAssertTrue(resource.records.isEmpty)
    }

    func testUnsupportedVersion() {
        XCTAssertThrowsError(try Resource.decode(from: [1]))
    }

    func testDSRecordDecode() throws {
        // Version(1) + type(1) + keyTag(2) + algo(1) + digestType(1) + digestLen(1) + digest(4)
        let data: [UInt8] = [
            0,          // version
            0,          // type = DS
            0x12, 0x34, // keyTag
            8,          // algorithm
            2,          // digestType
            4,          // digestLen
            0xDE, 0xAD, 0xBE, 0xEF, // digest
        ]
        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 1)

        if case .ds(let keyTag, let algorithm, let digestType, let digest) = resource.records[0] {
            XCTAssertEqual(keyTag, 0x1234)
            XCTAssertEqual(algorithm, 8)
            XCTAssertEqual(digestType, 2)
            XCTAssertEqual(digest, [0xDE, 0xAD, 0xBE, 0xEF])
        } else {
            XCTFail("Expected DS record")
        }
    }

    func testNSRecordDecode() throws {
        // Version + type=NS(1) + name "ns1.example." encoded
        var data: [UInt8] = [0, 1] // version=0, type=NS
        // "ns1" label
        data.append(3)
        data.append(contentsOf: Array("ns1".utf8))
        // "example" label
        data.append(7)
        data.append(contentsOf: Array("example".utf8))
        // root terminator
        data.append(0)

        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 1)

        if case .ns(let name) = resource.records[0] {
            XCTAssertEqual(name, "ns1.example.")
        } else {
            XCTFail("Expected NS record")
        }
    }

    func testGlue4RecordDecode() throws {
        // Version + type=GLUE4(2) + name + 4 bytes IP
        var data: [UInt8] = [0, 2] // version=0, type=GLUE4
        // "ns1" label
        data.append(3)
        data.append(contentsOf: Array("ns1".utf8))
        data.append(0) // root
        // IPv4 address
        data.append(contentsOf: [192, 168, 1, 1])

        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 1)

        if case .glue4(let name, let address) = resource.records[0] {
            XCTAssertEqual(name, "ns1.")
            XCTAssertEqual(address, [192, 168, 1, 1])
        } else {
            XCTFail("Expected GLUE4 record")
        }
    }

    func testGlue6RecordDecode() throws {
        var data: [UInt8] = [0, 3] // version=0, type=GLUE6
        data.append(3)
        data.append(contentsOf: Array("ns1".utf8))
        data.append(0)
        // IPv6 address (16 bytes)
        let ipv6: [UInt8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        data.append(contentsOf: ipv6)

        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 1)

        if case .glue6(let name, let address) = resource.records[0] {
            XCTAssertEqual(name, "ns1.")
            XCTAssertEqual(address, ipv6)
        } else {
            XCTFail("Expected GLUE6 record")
        }
    }

    func testSynth4RecordDecode() throws {
        let data: [UInt8] = [0, 4, 10, 20, 30, 40] // version=0, type=SYNTH4, 4-byte address
        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 1)

        if case .synth4(let address) = resource.records[0] {
            XCTAssertEqual(address, [10, 20, 30, 40])
        } else {
            XCTFail("Expected SYNTH4 record")
        }
    }

    func testSynth6RecordDecode() throws {
        var data: [UInt8] = [0, 5] // version=0, type=SYNTH6
        let ipv6: [UInt8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        data.append(contentsOf: ipv6)

        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 1)

        if case .synth6(let address) = resource.records[0] {
            XCTAssertEqual(address, ipv6)
        } else {
            XCTFail("Expected SYNTH6 record")
        }
    }

    func testTXTRecordDecode() throws {
        var data: [UInt8] = [0, 6] // version=0, type=TXT
        data.append(2)            // 2 strings
        let s1 = Array("hello".utf8)
        data.append(UInt8(s1.count))
        data.append(contentsOf: s1)
        let s2 = Array("world".utf8)
        data.append(UInt8(s2.count))
        data.append(contentsOf: s2)

        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 1)

        if case .txt(let strings) = resource.records[0] {
            XCTAssertEqual(strings, ["hello", "world"])
        } else {
            XCTFail("Expected TXT record")
        }
    }

    func testEncodeDecodeRoundTrip() throws {
        let resource = Resource(records: [
            .ds(keyTag: 100, algorithm: 8, digestType: 2, digest: [1, 2, 3, 4]),
            .ns(name: "ns1.example."),
            .glue4(name: "ns2.example.", address: [10, 0, 0, 1]),
            .synth4(address: [172, 16, 0, 1]),
            .txt(strings: ["v=spf1 include:example"]),
        ])

        let encoded = try resource.encode()
        let decoded = try Resource.decode(from: encoded)
        XCTAssertEqual(decoded, resource)
    }

    func testMultipleRecords() throws {
        let resource = Resource(records: [
            .glue4(name: "ns1.", address: [1, 2, 3, 4]),
            .glue4(name: "ns2.", address: [5, 6, 7, 8]),
            .ds(keyTag: 1, algorithm: 8, digestType: 2, digest: [0xAA]),
        ])

        let encoded = try resource.encode()
        let decoded = try Resource.decode(from: encoded)
        XCTAssertEqual(decoded.records.count, 3)
        XCTAssertEqual(decoded.nameservers.count, 2)
        XCTAssertEqual(decoded.dsRecords.count, 1)
        XCTAssertTrue(decoded.hasNS)
    }

    func testConvenienceAccessors() {
        let resource = Resource(records: [
            .ns(name: "ns1."),
            .glue4(name: "ns2.", address: [1, 2, 3, 4]),
            .glue6(name: "ns3.", address: [UInt8](repeating: 0, count: 16)),
            .synth4(address: [10, 0, 0, 1]),
            .synth6(address: [UInt8](repeating: 0xFF, count: 16)),
            .ds(keyTag: 1, algorithm: 8, digestType: 2, digest: [0xBB]),
            .txt(strings: ["test"]),
        ])

        XCTAssertEqual(resource.nameservers.count, 5)
        XCTAssertEqual(resource.dsRecords.count, 1)
        XCTAssertEqual(resource.txtRecords.count, 1)
        XCTAssertTrue(resource.hasNS)
    }
}

// MARK: - Resource Converter Tests

final class ResourceConverterTests: XCTestCase {

    func testBase32HexEncode() {
        // Known value: [0xDE, 0xAD] = 1101_1110 1010_1101
        // Groups of 5: 11011 11010 10110 1 (padded: 10000)
        // Indices: 27=r, 26=q, 22=m, 16=g
        let encoded = ResourceConverter.base32HexEncode([0xDE, 0xAD])
        XCTAssertEqual(encoded.count, 4)
        // Verify round-trip
        let decoded = ResourceConverter.base32HexDecode(encoded)
        XCTAssertEqual(decoded, [0xDE, 0xAD])
    }

    func testBase32HexRoundTrip() {
        let testCases: [[UInt8]] = [
            [],
            [0],
            [0xFF],
            [1, 2, 3, 4],
            [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160],
        ]
        for data in testCases {
            let encoded = ResourceConverter.base32HexEncode(data)
            let decoded = ResourceConverter.base32HexDecode(encoded)
            XCTAssertEqual(decoded, data, "Round-trip failed for \(data)")
        }
    }

    func testBase32HexDecodeInvalidChars() {
        XCTAssertNil(ResourceConverter.base32HexDecode("xyz!"))
    }

    func testSynthNameIPv4() {
        let address: [UInt8] = [192, 168, 1, 1]
        let name = ResourceConverter.synthName(ipv4: address)
        XCTAssertTrue(name.hasPrefix("_"))
        XCTAssertTrue(name.hasSuffix("._synth."))

        let decoded = ResourceConverter.decodeSynth4(name)
        XCTAssertEqual(decoded, address)
    }

    func testSynthNameIPv6() {
        let address: [UInt8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let name = ResourceConverter.synthName(ipv6: address)
        XCTAssertTrue(name.hasPrefix("_"))
        XCTAssertTrue(name.hasSuffix("._synth."))

        let decoded = ResourceConverter.decodeSynth6(name)
        XCTAssertEqual(decoded, address)
    }

    func testDecodeSynth4Invalid() {
        XCTAssertNil(ResourceConverter.decodeSynth4("not.a.synth.name."))
        // "invalid" is valid base32hex that happens to decode to 4 bytes,
        // so use a string with invalid characters instead
        XCTAssertNil(ResourceConverter.decodeSynth4("_!!!._synth."))
    }

    func testDecodeSynth6WrongLength() {
        // IPv4-length data should fail for synth6
        let address4: [UInt8] = [10, 0, 0, 1]
        let name4 = ResourceConverter.synthName(ipv4: address4)
        XCTAssertNil(ResourceConverter.decodeSynth6(name4))
    }

    func testToDNSReferralWithGlue4() throws {
        let resource = Resource(records: [
            .glue4(name: "ns1.example.", address: [10, 0, 0, 1]),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        XCTAssertTrue(result.answers.isEmpty)
        XCTAssertEqual(result.authority.count, 1)
        XCTAssertEqual(result.authority[0].type, DNSType.ns.rawValue)
        XCTAssertEqual(result.additional.count, 1)
        XCTAssertEqual(result.additional[0].type, DNSType.a.rawValue)
        XCTAssertEqual(result.additional[0].rdata, [10, 0, 0, 1])
    }

    func testToDNSReferralWithSynth4() throws {
        let resource = Resource(records: [
            .synth4(address: [172, 16, 0, 1]),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        XCTAssertTrue(result.answers.isEmpty)
        XCTAssertEqual(result.authority.count, 1)
        XCTAssertEqual(result.authority[0].type, DNSType.ns.rawValue)
        XCTAssertEqual(result.additional.count, 1)
        XCTAssertEqual(result.additional[0].type, DNSType.a.rawValue)
        XCTAssertEqual(result.additional[0].rdata, [172, 16, 0, 1])
    }

    func testToDNSReferralWithDS() throws {
        let resource = Resource(records: [
            .ns(name: "ns1.example."),
            .ds(keyTag: 100, algorithm: 8, digestType: 2, digest: [0xAA, 0xBB]),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        // NS in authority, DS in authority
        XCTAssertEqual(result.authority.count, 2)
        let types = Set(result.authority.map { $0.type })
        XCTAssertTrue(types.contains(DNSType.ns.rawValue))
        XCTAssertTrue(types.contains(DNSType.ds.rawValue))
    }

    func testToDNSDSQuery() throws {
        let resource = Resource(records: [
            .ds(keyTag: 200, algorithm: 13, digestType: 2, digest: [1, 2, 3]),
            .ns(name: "ns1."),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.ds.rawValue, isReferral: false
        )

        XCTAssertEqual(result.answers.count, 1)
        XCTAssertEqual(result.answers[0].type, DNSType.ds.rawValue)
        XCTAssertTrue(result.authority.isEmpty)
    }

    func testToDNSTXTQueryWithoutNS() throws {
        let resource = Resource(records: [
            .txt(strings: ["v=spf1 include:example"]),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.txt.rawValue, isReferral: false
        )

        XCTAssertEqual(result.answers.count, 1)
        XCTAssertEqual(result.answers[0].type, DNSType.txt.rawValue)
    }

    func testToDNSTXTQueryWithNSFallsBackToReferral() throws {
        // When NS records exist, TXT queries should get a referral
        let resource = Resource(records: [
            .ns(name: "ns1.example."),
            .txt(strings: ["ignored"]),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.txt.rawValue, isReferral: false
        )

        // Should return referral (authority section, no answers)
        XCTAssertTrue(result.answers.isEmpty)
        XCTAssertFalse(result.authority.isEmpty)
    }

    func testToDNSDefaultFallsToReferral() throws {
        let resource = Resource(records: [
            .ns(name: "ns1.example."),
        ])

        // Query for A record on TLD should get referral
        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: false
        )

        XCTAssertTrue(result.answers.isEmpty)
        XCTAssertEqual(result.authority.count, 1)
    }

    func testTXTNotIncludedInReferral() throws {
        let resource = Resource(records: [
            .ns(name: "ns1."),
            .txt(strings: ["should not appear"]),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        // Only NS should be in authority, no TXT anywhere
        XCTAssertEqual(result.authority.count, 1)
        XCTAssertEqual(result.authority[0].type, DNSType.ns.rawValue)
        XCTAssertTrue(result.additional.isEmpty)
    }
}

// MARK: - DNS isPrivateIP Tests

final class DNSPrivateIPTests: XCTestCase {

    func testIsPrivateIPv4() {
        // Private / loopback / link-local / unspecified addresses
        XCTAssertTrue(DNSResolver.isPrivateIP([10, 0, 0, 1]))
        XCTAssertTrue(DNSResolver.isPrivateIP([172, 16, 0, 1]))
        XCTAssertTrue(DNSResolver.isPrivateIP([172, 31, 255, 255]))
        XCTAssertTrue(DNSResolver.isPrivateIP([192, 168, 1, 1]))
        XCTAssertTrue(DNSResolver.isPrivateIP([127, 0, 0, 1]))
        XCTAssertTrue(DNSResolver.isPrivateIP([169, 254, 1, 1]))
        XCTAssertTrue(DNSResolver.isPrivateIP([0, 0, 0, 0]))

        // Public addresses
        XCTAssertFalse(DNSResolver.isPrivateIP([8, 8, 8, 8]))
        XCTAssertFalse(DNSResolver.isPrivateIP([172, 15, 0, 1]))
        XCTAssertFalse(DNSResolver.isPrivateIP([172, 32, 0, 1]))
        XCTAssertFalse(DNSResolver.isPrivateIP([1, 1, 1, 1]))
    }

    func testIsPrivateIPv6Loopback() {
        // ::1
        let loopback: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        XCTAssertTrue(DNSResolver.isPrivateIP(loopback))
    }

    func testIsPrivateIPv6ULA() {
        // fc00::/7 includes addresses starting with 0xFC or 0xFD
        var ulaFC: [UInt8] = [UInt8](repeating: 0, count: 16)
        ulaFC[0] = 0xFC
        XCTAssertTrue(DNSResolver.isPrivateIP(ulaFC))

        var ulaFD: [UInt8] = [UInt8](repeating: 0, count: 16)
        ulaFD[0] = 0xFD
        XCTAssertTrue(DNSResolver.isPrivateIP(ulaFD))
    }

    func testIsPrivateIPv4MappedPrivate() {
        // ::ffff:10.0.0.1 (private)
        let mappedPrivate: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 1]
        XCTAssertTrue(DNSResolver.isPrivateIP(mappedPrivate))

        // ::ffff:8.8.8.8 (public)
        let mappedPublic: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 8, 8, 8, 8]
        XCTAssertFalse(DNSResolver.isPrivateIP(mappedPublic))
    }
}

// MARK: - DNS Compression Pointer Tests

final class DNSCompressionTests: XCTestCase {

    func testCompressionPointerFollowing() throws {
        // Build data: "example.com." at offset 0, then a pointer at offset 13
        var data: [UInt8] = []
        // "example" label
        data.append(7)
        data.append(contentsOf: Array("example".utf8))
        // "com" label
        data.append(3)
        data.append(contentsOf: Array("com".utf8))
        // root terminator
        data.append(0) // offset 13 is after this

        // Compression pointer back to offset 0
        data.append(0xC0)
        data.append(0x00)

        var reader = BufferReader(data)
        reader.offset = 13 // start at the pointer
        let name = try DNSName.decode(from: &reader, message: data)
        XCTAssertEqual(name, "example.com.")
    }

    func testCompressionPointerToSuffix() throws {
        // Write "com." at offset 0, then "example" + pointer to offset 0
        var data: [UInt8] = []
        // "com" at offset 0
        data.append(3)
        data.append(contentsOf: Array("com".utf8))
        data.append(0) // root, ends at offset 5

        // "example" label at offset 5
        data.append(7)
        data.append(contentsOf: Array("example".utf8))
        // pointer to "com." at offset 0
        data.append(0xC0)
        data.append(0x00)

        var reader = BufferReader(data)
        reader.offset = 5 // start at "example" + pointer
        let name = try DNSName.decode(from: &reader, message: data)
        XCTAssertEqual(name, "example.com.")
    }

    func testCompressionPointerReaderAdvances() throws {
        // After following a pointer, the reader should advance past the 2-byte pointer
        var writer = BufferWriter()
        var compression = [String: Int]()

        try DNSName.write("first.", to: &writer, compression: &compression)
        let afterFirst = writer.count

        try DNSName.write("second.", to: &writer, compression: &compression)
        let afterSecond = writer.count

        // Write "first." again — should be a 2-byte pointer
        try DNSName.write("first.", to: &writer, compression: &compression)

        let data = writer.data
        var reader = BufferReader(data)
        reader.offset = afterSecond

        let name = try DNSName.decode(from: &reader, message: data)
        XCTAssertEqual(name, "first.")
        // Reader should be exactly 2 bytes past the pointer start
        XCTAssertEqual(reader.offset, afterSecond + 2)
    }

    func testBadCompressionPointerOutOfBounds() {
        // Pointer pointing past the end of the message
        let data: [UInt8] = [0xC0, 0xFF] // pointer to offset 255 in a 2-byte message
        var reader = BufferReader(data)
        XCTAssertThrowsError(try DNSName.decode(from: &reader, message: data))
    }

    func testCompressionPointerWithoutMessage() {
        // Compression pointer without providing the full message data
        let data: [UInt8] = [0xC0, 0x00]
        var reader = BufferReader(data)
        XCTAssertThrowsError(try DNSName.decode(from: &reader))
    }

    func testMultipleCompressionPointers() throws {
        // Chain of pointers: A points to B, B has actual data
        var writer = BufferWriter()
        var compression = [String: Int]()

        try DNSName.write("a.b.c.", to: &writer, compression: &compression)
        let afterFirst = writer.count

        // Write "x.b.c." — "b.c." suffix should compress
        try DNSName.write("x.b.c.", to: &writer, compression: &compression)
        let afterSecond = writer.count

        let data = writer.data
        var reader = BufferReader(data)
        reader.offset = afterFirst
        let name = try DNSName.decode(from: &reader, message: data)
        XCTAssertEqual(name, "x.b.c.")
    }
}

// MARK: - On-Chain Resource Compression Tests

final class ResourceCompressionTests: XCTestCase {

    func testResourceNameWithCompression() throws {
        // Build resource data with NS records sharing a common suffix via compression
        var data: [UInt8] = [0] // version=0

        // NS record: type=1, then name "ns1.example."
        data.append(1) // type = NS
        let ns1Start = data.count
        data.append(3); data.append(contentsOf: Array("ns1".utf8))
        let exampleStart = data.count
        data.append(7); data.append(contentsOf: Array("example".utf8))
        data.append(0) // root

        // NS record: type=1, then name "ns2.example." with pointer to "example."
        data.append(1) // type = NS
        data.append(3); data.append(contentsOf: Array("ns2".utf8))
        data.append(0xC0) // compression pointer
        data.append(UInt8(exampleStart)) // points to "example." in first record

        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 2)

        if case .ns(let name1) = resource.records[0] {
            XCTAssertEqual(name1, "ns1.example.")
        } else { XCTFail("Expected NS record") }

        if case .ns(let name2) = resource.records[1] {
            XCTAssertEqual(name2, "ns2.example.")
        } else { XCTFail("Expected NS record") }
    }

    func testResourceCompressionPointerLimit() {
        // Build resource data with too many compression pointer jumps (limit is 10)
        var data: [UInt8] = [0] // version=0
        data.append(1) // type = NS

        // Create a chain of 11 pointers all pointing to the start of the name area
        // Each pointer is 2 bytes pointing to itself → infinite loop
        // But the limit should catch it at 10
        let nameStart = data.count
        // Self-referencing pointer
        data.append(0xC0)
        data.append(UInt8(nameStart))

        XCTAssertThrowsError(try Resource.decode(from: data))
    }

    func testResourceGlue4WithCompression() throws {
        // GLUE4 record where the NS name uses compression
        var data: [UInt8] = [0] // version=0

        // First: NS record for "ns1.example."
        data.append(1) // type = NS
        data.append(3); data.append(contentsOf: Array("ns1".utf8))
        let exampleStart = data.count
        data.append(7); data.append(contentsOf: Array("example".utf8))
        data.append(0)

        // Second: GLUE4 record for "ns2.example." with pointer + IP
        data.append(2) // type = GLUE4
        data.append(3); data.append(contentsOf: Array("ns2".utf8))
        data.append(0xC0); data.append(UInt8(exampleStart))
        data.append(contentsOf: [192, 168, 1, 1]) // IPv4

        let resource = try Resource.decode(from: data)
        XCTAssertEqual(resource.records.count, 2)

        if case .glue4(let name, let addr) = resource.records[1] {
            XCTAssertEqual(name, "ns2.example.")
            XCTAssertEqual(addr, [192, 168, 1, 1])
        } else { XCTFail("Expected GLUE4 record") }
    }
}

// MARK: - NS Deduplication Tests

final class NSDeduplicationTests: XCTestCase {

    func testGlue4AndStandaloneNSDedup() throws {
        // Same NS name in both GLUE4 and standalone NS — should produce only one NS record
        let resource = Resource(records: [
            .glue4(name: "ns1.example.", address: [10, 0, 0, 1]),
            .ns(name: "ns1.example."),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        // Should have only 1 NS record (deduped), but still 1 A record
        let nsRecords = result.authority.filter { $0.type == DNSType.ns.rawValue }
        XCTAssertEqual(nsRecords.count, 1, "Duplicate NS name should be deduped")
        XCTAssertEqual(result.additional.count, 1, "Glue A record should still be present")
    }

    func testMultipleGluesSameNSName() throws {
        // GLUE4 and GLUE6 for same NS name — one NS, two glue records
        let resource = Resource(records: [
            .glue4(name: "ns1.example.", address: [10, 0, 0, 1]),
            .glue6(name: "ns1.example.", address: [UInt8](repeating: 0, count: 16)),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        let nsRecords = result.authority.filter { $0.type == DNSType.ns.rawValue }
        XCTAssertEqual(nsRecords.count, 1, "Same NS name from GLUE4+GLUE6 should produce one NS")
        XCTAssertEqual(result.additional.count, 2, "Both A and AAAA glue records should be present")
    }

    func testDifferentNSNamesNotDeduped() throws {
        let resource = Resource(records: [
            .ns(name: "ns1.example."),
            .ns(name: "ns2.example."),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        let nsRecords = result.authority.filter { $0.type == DNSType.ns.rawValue }
        XCTAssertEqual(nsRecords.count, 2, "Different NS names should not be deduped")
    }

    func testSynthNSDedup() throws {
        // Same IP in synth4 twice — should produce one NS
        let resource = Resource(records: [
            .synth4(address: [10, 0, 0, 1]),
            .synth4(address: [10, 0, 0, 1]),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        let nsRecords = result.authority.filter { $0.type == DNSType.ns.rawValue }
        XCTAssertEqual(nsRecords.count, 1, "Same synth IP should produce one NS")
    }

    func testDSNotDeduped() throws {
        // DS records should not be deduplicated
        let resource = Resource(records: [
            .ns(name: "ns1."),
            .ds(keyTag: 100, algorithm: 8, digestType: 2, digest: [0xAA]),
            .ds(keyTag: 200, algorithm: 8, digestType: 2, digest: [0xBB]),
        ])

        let result = try ResourceConverter.toDNS(
            resource: resource, tld: "test", qtype: DNSType.a.rawValue, isReferral: true
        )

        let dsRecords = result.authority.filter { $0.type == DNSType.ds.rawValue }
        XCTAssertEqual(dsRecords.count, 2, "DS records should not be deduped")
    }
}

// MARK: - Big-Endian Buffer Tests

final class BigEndianBufferTests: XCTestCase {

    func testWriteReadUInt16BE() throws {
        var writer = BufferWriter()
        writer.writeUInt16BE(0x1234)

        XCTAssertEqual(writer.data, [0x12, 0x34])

        var reader = BufferReader(writer.data)
        let value = try reader.readUInt16BE()
        XCTAssertEqual(value, 0x1234)
    }

    func testWriteReadUInt32BE() throws {
        var writer = BufferWriter()
        writer.writeUInt32BE(0xDEADBEEF)

        XCTAssertEqual(writer.data, [0xDE, 0xAD, 0xBE, 0xEF])

        var reader = BufferReader(writer.data)
        let value = try reader.readUInt32BE()
        XCTAssertEqual(value, 0xDEADBEEF)
    }

    func testBEEdgeCases() throws {
        var writer = BufferWriter()
        writer.writeUInt16BE(0)
        writer.writeUInt16BE(0xFFFF)
        writer.writeUInt32BE(0)
        writer.writeUInt32BE(0xFFFFFFFF)

        var reader = BufferReader(writer.data)
        XCTAssertEqual(try reader.readUInt16BE(), 0)
        XCTAssertEqual(try reader.readUInt16BE(), 0xFFFF)
        XCTAssertEqual(try reader.readUInt32BE(), 0)
        XCTAssertEqual(try reader.readUInt32BE(), 0xFFFFFFFF)
    }
}
