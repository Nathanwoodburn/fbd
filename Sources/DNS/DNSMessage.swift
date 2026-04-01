import Base

/// A DNS message header (12 bytes, all big-endian).
public struct DNSHeader: Equatable, Sendable {
    /// Transaction ID.
    public var id: UInt16
    /// Flags (QR, opcode, AA, TC, RD, RA, Z, AD, CD, RCODE).
    public var flags: UInt16
    /// Question count.
    public var qdcount: UInt16
    /// Answer count.
    public var ancount: UInt16
    /// Authority count.
    public var nscount: UInt16
    /// Additional count.
    public var arcount: UInt16

    public init(
        id: UInt16 = 0,
        flags: UInt16 = 0,
        qdcount: UInt16 = 0,
        ancount: UInt16 = 0,
        nscount: UInt16 = 0,
        arcount: UInt16 = 0
    ) {
        self.id = id
        self.flags = flags
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount
    }

    // MARK: - Flag accessors

    /// Whether this is a response (true) or query (false).
    public var isResponse: Bool {
        get { (flags & 0x8000) != 0 }
        set { flags = newValue ? (flags | 0x8000) : (flags & ~0x8000) }
    }

    /// The operation code (bits 14-11).
    public var opcode: UInt8 {
        get { UInt8((flags >> 11) & 0x0F) }
        set { flags = (flags & ~0x7800) | (UInt16(newValue & 0x0F) << 11) }
    }

    /// Authoritative answer flag.
    public var isAuthoritative: Bool {
        get { (flags & 0x0400) != 0 }
        set { flags = newValue ? (flags | 0x0400) : (flags & ~0x0400) }
    }

    /// Truncation flag.
    public var isTruncated: Bool {
        get { (flags & 0x0200) != 0 }
        set { flags = newValue ? (flags | 0x0200) : (flags & ~0x0200) }
    }

    /// Recursion desired flag.
    public var recursionDesired: Bool {
        get { (flags & 0x0100) != 0 }
        set { flags = newValue ? (flags | 0x0100) : (flags & ~0x0100) }
    }

    /// Recursion available flag.
    public var recursionAvailable: Bool {
        get { (flags & 0x0080) != 0 }
        set { flags = newValue ? (flags | 0x0080) : (flags & ~0x0080) }
    }

    /// Authenticated data (DNSSEC) flag.
    public var authenticatedData: Bool {
        get { (flags & 0x0020) != 0 }
        set { flags = newValue ? (flags | 0x0020) : (flags & ~0x0020) }
    }

    /// Checking disabled flag.
    public var checkingDisabled: Bool {
        get { (flags & 0x0010) != 0 }
        set { flags = newValue ? (flags | 0x0010) : (flags & ~0x0010) }
    }

    /// Response code (bits 3-0).
    public var rcode: UInt8 {
        get { UInt8(flags & 0x000F) }
        set { flags = (flags & ~0x000F) | UInt16(newValue & 0x0F) }
    }

    // MARK: - Serialization

    public func write(to writer: inout BufferWriter) {
        writer.writeUInt16BE(id)
        writer.writeUInt16BE(flags)
        writer.writeUInt16BE(qdcount)
        writer.writeUInt16BE(ancount)
        writer.writeUInt16BE(nscount)
        writer.writeUInt16BE(arcount)
    }

    public static func read(from reader: inout BufferReader) throws -> DNSHeader {
        DNSHeader(
            id: try reader.readUInt16BE(),
            flags: try reader.readUInt16BE(),
            qdcount: try reader.readUInt16BE(),
            ancount: try reader.readUInt16BE(),
            nscount: try reader.readUInt16BE(),
            arcount: try reader.readUInt16BE()
        )
    }
}

/// A DNS question section entry.
public struct DNSQuestion: Equatable, Sendable {
    /// The queried domain name.
    public let name: String
    /// The query type (A, AAAA, NS, etc.).
    public let type: UInt16
    /// The query class (usually IN = 1).
    public let qclass: UInt16

    public init(name: String, type: UInt16, qclass: UInt16 = 1) {
        self.name = name
        self.type = type
        self.qclass = qclass
    }

    public func write(to writer: inout BufferWriter, compression: inout [String: Int]) throws {
        try DNSName.write(name, to: &writer, compression: &compression)
        writer.writeUInt16BE(type)
        writer.writeUInt16BE(qclass)
    }

    public static func read(from reader: inout BufferReader, message: [UInt8]) throws -> DNSQuestion {
        let name = try DNSName.decode(from: &reader, message: message)
        let type = try reader.readUInt16BE()
        let qclass = try reader.readUInt16BE()
        return DNSQuestion(name: name, type: type, qclass: qclass)
    }
}

/// A DNS resource record.
public struct DNSRecord: Equatable, Sendable {
    /// The record name.
    public let name: String
    /// The record type.
    public let type: UInt16
    /// The record class.
    public let rclass: UInt16
    /// Time to live in seconds.
    public let ttl: UInt32
    /// The record data.
    public let rdata: [UInt8]

    public init(
        name: String,
        type: UInt16,
        rclass: UInt16 = 1,
        ttl: UInt32 = DNSConstants.defaultTTL,
        rdata: [UInt8]
    ) {
        self.name = name
        self.type = type
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
    }

    public func write(to writer: inout BufferWriter, compression: inout [String: Int]) throws {
        try DNSName.write(name, to: &writer, compression: &compression)
        writer.writeUInt16BE(type)
        writer.writeUInt16BE(rclass)
        writer.writeUInt32BE(ttl)
        writer.writeUInt16BE(UInt16(rdata.count))
        writer.writeBytes(rdata)
    }

    public static func read(from reader: inout BufferReader, message: [UInt8]) throws -> DNSRecord {
        let name = try DNSName.decode(from: &reader, message: message)
        let type = try reader.readUInt16BE()
        let rclass = try reader.readUInt16BE()
        let ttl = try reader.readUInt32BE()
        let rdlength = Int(try reader.readUInt16BE())
        let rdataStart = reader.offset
        let rdata = try reader.readBytes(rdlength)

        // RRSIG RDATA contains an embedded DNS name (signer name at offset 18)
        // which may use compression pointers. Decompress it so downstream consumers
        // (e.g. DNSSEC verifier) can parse the RDATA independently of the original message.
        let finalRdata: [UInt8]
        if type == DNSType.rrsig.rawValue, rdlength > 18 {
            finalRdata = try DNSRecord.decompressRRSIGRdata(rdata, rdataStart: rdataStart, message: message)
        } else {
            finalRdata = rdata
        }

        return DNSRecord(name: name, type: type, rclass: rclass, ttl: ttl, rdata: finalRdata)
    }

    /// Decompress the signer name inside RRSIG RDATA.
    ///
    /// RRSIG RDATA layout: [type_covered:2][algo:1][labels:1][orig_ttl:4][expiration:4][inception:4][key_tag:2][signer_name...][signature...]
    /// The signer name starts at offset 18 and may contain compression pointers referencing the full DNS message.
    private static func decompressRRSIGRdata(_ rdata: [UInt8], rdataStart: Int, message: [UInt8]) throws -> [UInt8] {
        // Read the signer name using the full message for pointer resolution.
        // The absolute offset in the message is rdataStart + 18.
        var nameReader = BufferReader(message)
        nameReader.offset = rdataStart + 18
        let signerName = try DNSName.decode(from: &nameReader, message: message)
        let signerWire = try DNSName.encode(signerName)

        // Figure out how many raw bytes the signer name consumed in the original RDATA
        var scanOffset = 18
        while scanOffset < rdata.count {
            let b = rdata[scanOffset]
            if b == 0 { scanOffset += 1; break }
            if (b & 0xC0) == 0xC0 { scanOffset += 2; break } // compression pointer is 2 bytes
            scanOffset += 1 + Int(b)
        }

        // Rebuild RDATA: fixed header + decompressed signer name wire + signature
        var result = Array(rdata[0..<18])
        result.append(contentsOf: signerWire)
        if scanOffset < rdata.count {
            result.append(contentsOf: rdata[scanOffset...])
        }
        return result
    }

    // MARK: - RDATA builders

    /// Create an A record (IPv4 address).
    public static func a(name: String, ip: [UInt8], ttl: UInt32 = DNSConstants.defaultTTL) -> DNSRecord {
        DNSRecord(name: name, type: DNSType.a.rawValue, ttl: ttl, rdata: ip)
    }

    /// Create an AAAA record (IPv6 address).
    public static func aaaa(name: String, ip: [UInt8], ttl: UInt32 = DNSConstants.defaultTTL) -> DNSRecord {
        DNSRecord(name: name, type: DNSType.aaaa.rawValue, ttl: ttl, rdata: ip)
    }

    /// Create an NS record.
    public static func ns(name: String, ns nsName: String, ttl: UInt32 = DNSConstants.defaultTTL) throws -> DNSRecord {
        let rdata = try DNSName.encode(nsName)
        return DNSRecord(name: name, type: DNSType.ns.rawValue, ttl: ttl, rdata: rdata)
    }

    /// Create a TXT record.
    public static func txt(name: String, strings: [String], ttl: UInt32 = DNSConstants.defaultTTL) -> DNSRecord {
        var rdata = [UInt8]()
        for s in strings {
            let bytes = Array(s.utf8)
            rdata.append(UInt8(min(bytes.count, 255)))
            rdata.append(contentsOf: bytes.prefix(255))
        }
        return DNSRecord(name: name, type: DNSType.txt.rawValue, ttl: ttl, rdata: rdata)
    }

    /// Create a DS record.
    public static func ds(
        name: String,
        keyTag: UInt16,
        algorithm: UInt8,
        digestType: UInt8,
        digest: [UInt8],
        ttl: UInt32 = DNSConstants.defaultTTL
    ) -> DNSRecord {
        var rdata = [UInt8]()
        rdata.append(UInt8(keyTag >> 8))
        rdata.append(UInt8(keyTag & 0xFF))
        rdata.append(algorithm)
        rdata.append(digestType)
        rdata.append(contentsOf: digest)
        return DNSRecord(name: name, type: DNSType.ds.rawValue, ttl: ttl, rdata: rdata)
    }

    /// Create a CNAME record.
    public static func cname(name: String, target: String, ttl: UInt32 = DNSConstants.defaultTTL) throws -> DNSRecord {
        let rdata = try DNSName.encode(target)
        return DNSRecord(name: name, type: DNSType.cname.rawValue, ttl: ttl, rdata: rdata)
    }

    /// Create an MX record.
    public static func mx(name: String, preference: UInt16, exchange: String, ttl: UInt32 = DNSConstants.defaultTTL) throws -> DNSRecord {
        var rdata = [UInt8]()
        rdata.append(UInt8(preference >> 8))
        rdata.append(UInt8(preference & 0xFF))
        rdata.append(contentsOf: try DNSName.encode(exchange))
        return DNSRecord(name: name, type: DNSType.mx.rawValue, ttl: ttl, rdata: rdata)
    }

    /// Create a TLSA record.
    public static func tlsa(
        name: String,
        usage: UInt8,
        selector: UInt8,
        matchingType: UInt8,
        certificate: [UInt8],
        ttl: UInt32 = DNSConstants.defaultTTL
    ) -> DNSRecord {
        var rdata = [UInt8]()
        rdata.append(usage)
        rdata.append(selector)
        rdata.append(matchingType)
        rdata.append(contentsOf: certificate)
        return DNSRecord(name: name, type: DNSType.tlsa.rawValue, ttl: ttl, rdata: rdata)
    }

    /// Create a CAA record.
    public static func caa(
        name: String,
        flags: UInt8,
        tag: String,
        value: String,
        ttl: UInt32 = DNSConstants.defaultTTL
    ) -> DNSRecord {
        var rdata = [UInt8]()
        rdata.append(flags)
        let tagBytes = Array(tag.utf8)
        rdata.append(UInt8(tagBytes.count))
        rdata.append(contentsOf: tagBytes)
        rdata.append(contentsOf: Array(value.utf8))
        return DNSRecord(name: name, type: DNSType.caa.rawValue, ttl: ttl, rdata: rdata)
    }

    /// Create a SOA record.
    public static func soa(
        name: String,
        mname: String = ".",
        rname: String = ".",
        serial: UInt32,
        refresh: UInt32 = DNSConstants.soaRefresh,
        retry: UInt32 = DNSConstants.soaRetry,
        expire: UInt32 = DNSConstants.soaExpire,
        minimum: UInt32 = DNSConstants.soaMinTTL,
        ttl: UInt32 = DNSConstants.soaTTL
    ) throws -> DNSRecord {
        var w = BufferWriter()
        try DNSName.writeUncompressed(mname, to: &w)
        try DNSName.writeUncompressed(rname, to: &w)
        w.writeUInt32BE(serial)
        w.writeUInt32BE(refresh)
        w.writeUInt32BE(retry)
        w.writeUInt32BE(expire)
        w.writeUInt32BE(minimum)
        return DNSRecord(name: name, type: DNSType.soa.rawValue, ttl: ttl, rdata: w.data)
    }
}

/// A complete DNS message.
public struct DNSMessage: Equatable, Sendable {
    /// The message header.
    public var header: DNSHeader
    /// The question section.
    public var questions: [DNSQuestion]
    /// The answer section.
    public var answers: [DNSRecord]
    /// The authority section.
    public var authority: [DNSRecord]
    /// The additional section.
    public var additional: [DNSRecord]

    public init(
        header: DNSHeader = DNSHeader(),
        questions: [DNSQuestion] = [],
        answers: [DNSRecord] = [],
        authority: [DNSRecord] = [],
        additional: [DNSRecord] = []
    ) {
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional
    }

    /// Encode the complete DNS message.
    public func encode() throws -> [UInt8] {
        var writer = BufferWriter()
        var compression = [String: Int]()

        var h = header
        h.qdcount = UInt16(questions.count)
        h.ancount = UInt16(answers.count)
        h.nscount = UInt16(authority.count)
        h.arcount = UInt16(additional.count)
        h.write(to: &writer)

        for q in questions {
            try q.write(to: &writer, compression: &compression)
        }
        for r in answers {
            try r.write(to: &writer, compression: &compression)
        }
        for r in authority {
            try r.write(to: &writer, compression: &compression)
        }
        for r in additional {
            try r.write(to: &writer, compression: &compression)
        }
        return writer.data
    }

    /// Decode a complete DNS message from wire format.
    public static func decode(from data: [UInt8]) throws -> DNSMessage {
        var reader = BufferReader(data)
        let header = try DNSHeader.read(from: &reader)

        // Cap section counts to prevent excessive allocations from malformed packets
        guard header.qdcount <= 256 && header.ancount <= 256
              && header.nscount <= 256 && header.arcount <= 256 else {
            throw BaseError.bufferUnderflow
        }

        var questions = [DNSQuestion]()
        for _ in 0..<header.qdcount {
            questions.append(try DNSQuestion.read(from: &reader, message: data))
        }

        var answers = [DNSRecord]()
        for _ in 0..<header.ancount {
            answers.append(try DNSRecord.read(from: &reader, message: data))
        }

        var authority = [DNSRecord]()
        for _ in 0..<header.nscount {
            authority.append(try DNSRecord.read(from: &reader, message: data))
        }

        var additional = [DNSRecord]()
        for _ in 0..<header.arcount {
            additional.append(try DNSRecord.read(from: &reader, message: data))
        }

        return DNSMessage(
            header: header,
            questions: questions,
            answers: answers,
            authority: authority,
            additional: additional
        )
    }

    /// Create a response for a query.
    public static func response(
        for query: DNSMessage,
        rcode: DNSRcode = .noerror,
        authoritative: Bool = true,
        answers: [DNSRecord] = [],
        authority: [DNSRecord] = [],
        additional: [DNSRecord] = []
    ) -> DNSMessage {
        var header = DNSHeader()
        header.id = query.header.id
        header.isResponse = true
        header.opcode = query.header.opcode
        header.isAuthoritative = authoritative
        header.recursionDesired = query.header.recursionDesired
        header.rcode = rcode.rawValue

        return DNSMessage(
            header: header,
            questions: query.questions,
            answers: answers,
            authority: authority,
            additional: additional
        )
    }
}
