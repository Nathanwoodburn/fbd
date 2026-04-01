import Base

/// A parsed FBD on-chain resource record.
///
/// These represent the individual records stored in the `data` field
/// of a name's covenant (REGISTER/UPDATE). Each record is one of
/// the types that map to standard DNS records.
public enum Record: Equatable, Sendable {
    /// DNSSEC Delegation Signer record.
    case ds(keyTag: UInt16, algorithm: UInt8, digestType: UInt8, digest: [UInt8])

    /// Nameserver (external, no glue address needed).
    case ns(name: String)

    /// Nameserver with IPv4 glue address.
    case glue4(name: String, address: [UInt8])

    /// Nameserver with IPv6 glue address.
    case glue6(name: String, address: [UInt8])

    /// Synthetic nameserver from IPv4 address.
    /// The NS name is generated as `_<base32hex(address)>._synth.`
    case synth4(address: [UInt8])

    /// Synthetic nameserver from IPv6 address.
    case synth6(address: [UInt8])

    /// Text record (one or more strings).
    case txt(strings: [String])

    /// IPv4 address record.
    case a(address: [UInt8])

    /// IPv6 address record.
    case aaaa(address: [UInt8])

    /// Canonical name (alias).
    case cname(name: String)

    /// Mail exchange record.
    case mx(preference: UInt16, exchange: String)

    /// TLSA certificate association record (DANE).
    /// Port and protocol identify the service (e.g., 443/TCP for HTTPS).
    /// The DNS owner name `_port._proto.name` is synthesized at serve time.
    case tlsa(port: UInt16, protocol: UInt8, usage: UInt8, selector: UInt8, matchingType: UInt8, certificate: [UInt8])

    /// Certification Authority Authorization record.
    case caa(flags: UInt8, tag: String, value: String)

    /// Inline subdomain records.
    /// The `name` is a single label (e.g., "www") and `records` are the DNS
    /// records served for that subdomain.
    case sub(name: String, records: [Record])

    /// Fistbump wallet address (for sending FBC to a name).
    /// Stores the bech32 address string (e.g., "fb1q...").
    case wallet(address: String)
}

/// A decoded FBD resource data blob.
///
/// The resource data is stored on-chain in the `data` field of
/// REGISTER and UPDATE covenants. Format:
/// ```
/// [version: UInt8]   Must be 0
/// [records...]       Concatenated type-prefixed records
/// ```
public struct Resource: Equatable, Sendable {
    /// The decoded records.
    public let records: [Record]

    public init(records: [Record]) {
        self.records = records
    }

    /// Decode a resource blob from on-chain data.
    ///
    /// - Parameter data: The raw resource bytes from the covenant.
    /// - Returns: The parsed resource.
    public static func decode(from data: [UInt8]) throws -> Resource {
        guard !data.isEmpty else {
            return Resource(records: [])
        }

        var reader = BufferReader(data)
        let version = try reader.readUInt8()
        guard version == 0 else {
            throw DNSError.unsupportedResourceVersion(version)
        }

        var records = [Record]()
        while reader.remaining > 0 {
            let record = try readRecord(from: &reader, data: data)
            records.append(record)
        }
        return Resource(records: records)
    }

    /// Encode the resource blob for on-chain storage.
    public func encode() throws -> [UInt8] {
        var writer = BufferWriter()
        writer.writeUInt8(0) // version

        for record in records {
            try writeRecord(record, to: &writer)
        }
        return writer.data
    }

    // MARK: - Record reading

    private static func readRecord(from reader: inout BufferReader, data: [UInt8]) throws -> Record {
        let rawType = try reader.readUInt8()
        guard let type = RecordType(rawValue: rawType) else {
            throw DNSError.unknownRecordType(rawType)
        }

        switch type {
        case .ds:
            let keyTag = try reader.readUInt16BE()
            let algorithm = try reader.readUInt8()
            let digestType = try reader.readUInt8()
            let digestLen = Int(try reader.readUInt8())
            let digest = try reader.readBytes(digestLen)
            return .ds(keyTag: keyTag, algorithm: algorithm, digestType: digestType, digest: digest)

        case .ns:
            let name = try readResourceName(from: &reader, data: data)
            return .ns(name: name)

        case .glue4:
            let name = try readResourceName(from: &reader, data: data)
            let address = try reader.readBytes(4)
            return .glue4(name: name, address: address)

        case .glue6:
            let name = try readResourceName(from: &reader, data: data)
            let address = try reader.readBytes(16)
            return .glue6(name: name, address: address)

        case .synth4:
            let address = try reader.readBytes(4)
            return .synth4(address: address)

        case .synth6:
            let address = try reader.readBytes(16)
            return .synth6(address: address)

        case .txt:
            let count = Int(try reader.readUInt8())
            var strings = [String]()
            for _ in 0..<count {
                let len = Int(try reader.readUInt8())
                let bytes = try reader.readBytes(len)
                strings.append(String(decoding: bytes, as: UTF8.self))
            }
            return .txt(strings: strings)

        case .a:
            let address = try reader.readBytes(4)
            return .a(address: address)

        case .aaaa:
            let address = try reader.readBytes(16)
            return .aaaa(address: address)

        case .cname:
            let name = try readResourceName(from: &reader, data: data)
            return .cname(name: name)

        case .mx:
            let preference = try reader.readUInt16BE()
            let exchange = try readResourceName(from: &reader, data: data)
            return .mx(preference: preference, exchange: exchange)

        case .tlsa:
            let port = try reader.readUInt16BE()
            let proto = try reader.readUInt8()
            let usage = try reader.readUInt8()
            let selector = try reader.readUInt8()
            let matchingType = try reader.readUInt8()
            let certLen = Int(try reader.readUInt16BE())
            let certificate = try reader.readBytes(certLen)
            return .tlsa(port: port, protocol: proto, usage: usage, selector: selector, matchingType: matchingType, certificate: certificate)

        case .caa:
            let flags = try reader.readUInt8()
            let tagLen = Int(try reader.readUInt8())
            let tagBytes = try reader.readBytes(tagLen)
            let tag = String(decoding: tagBytes, as: UTF8.self)
            let valueLen = Int(try reader.readUInt16BE())
            let valueBytes = try reader.readBytes(valueLen)
            let value = String(decoding: valueBytes, as: UTF8.self)
            return .caa(flags: flags, tag: tag, value: value)

        case .sub:
            let nameLen = Int(try reader.readUInt8())
            let nameBytes = try reader.readBytes(nameLen)
            let name = String(decoding: nameBytes, as: UTF8.self)
            let count = Int(try reader.readUInt8())
            var nested = [Record]()
            for _ in 0..<count {
                nested.append(try readRecord(from: &reader, data: data))
            }
            return .sub(name: name, records: nested)

        case .wallet:
            let len = Int(try reader.readUInt8())
            let bytes = try reader.readBytes(len)
            let address = String(decoding: bytes, as: UTF8.self)
            return .wallet(address: address)
        }
    }

    /// Read a DNS-style name from the resource data, handling compression pointers.
    ///
    /// hsd uses DNS name compression (RFC 1035 §4.1.4) in on-chain resource data.
    /// A compression pointer is a 2-byte sequence where the first byte has the top
    /// 2 bits set (0xC0), pointing to an earlier offset in the data buffer.
    private static func readResourceName(from reader: inout BufferReader, data: [UInt8]) throws -> String {
        var labels = [String]()
        var off = reader.offset
        var resumeOffset = 0
        var pointerCount = 0

        while true {
            guard off < data.count else { throw DNSError.malformedResource("name EOF") }
            let c = data[off]
            off += 1

            if c == 0 { break }

            switch c & 0xC0 {
            case 0x00:
                // Regular label
                let len = Int(c)
                guard off + len <= data.count else {
                    throw DNSError.malformedResource("name label EOF")
                }
                labels.append(String(decoding: data[off..<(off + len)], as: UTF8.self))
                off += len

            case 0xC0:
                // Compression pointer
                guard off < data.count else {
                    throw DNSError.malformedResource("compression pointer EOF")
                }
                let c1 = data[off]
                off += 1

                // Save where the reader should resume (only on first pointer)
                if pointerCount == 0 { resumeOffset = off }
                pointerCount += 1
                guard pointerCount <= 10 else {
                    throw DNSError.badCompressionPointer(off)
                }

                // Follow the pointer
                off = (Int(c & 0x3F) << 8) | Int(c1)

            default:
                throw DNSError.malformedResource("invalid name byte: 0x\(String(c, radix: 16))")
            }
        }

        // Advance reader past what we consumed (pointer bytes or full name)
        if pointerCount > 0 {
            reader.offset = resumeOffset
        } else {
            reader.offset = off
        }

        return labels.isEmpty ? "." : labels.joined(separator: ".") + "."
    }

    // MARK: - Record writing

    private func writeRecord(_ record: Record, to writer: inout BufferWriter) throws {
        switch record {
        case .ds(let keyTag, let algorithm, let digestType, let digest):
            writer.writeUInt8(RecordType.ds.rawValue)
            writer.writeUInt16BE(keyTag)
            writer.writeUInt8(algorithm)
            writer.writeUInt8(digestType)
            writer.writeUInt8(UInt8(digest.count))
            writer.writeBytes(digest)

        case .ns(let name):
            writer.writeUInt8(RecordType.ns.rawValue)
            try writeResourceName(name, to: &writer)

        case .glue4(let name, let address):
            writer.writeUInt8(RecordType.glue4.rawValue)
            try writeResourceName(name, to: &writer)
            writer.writeBytes(address)

        case .glue6(let name, let address):
            writer.writeUInt8(RecordType.glue6.rawValue)
            try writeResourceName(name, to: &writer)
            writer.writeBytes(address)

        case .synth4(let address):
            writer.writeUInt8(RecordType.synth4.rawValue)
            writer.writeBytes(address)

        case .synth6(let address):
            writer.writeUInt8(RecordType.synth6.rawValue)
            writer.writeBytes(address)

        case .txt(let strings):
            writer.writeUInt8(RecordType.txt.rawValue)
            writer.writeUInt8(UInt8(strings.count))
            for s in strings {
                let bytes = Array(s.utf8)
                writer.writeUInt8(UInt8(min(bytes.count, 255)))
                writer.writeBytes(bytes.prefix(255))
            }

        case .a(let address):
            writer.writeUInt8(RecordType.a.rawValue)
            writer.writeBytes(address)

        case .aaaa(let address):
            writer.writeUInt8(RecordType.aaaa.rawValue)
            writer.writeBytes(address)

        case .cname(let name):
            writer.writeUInt8(RecordType.cname.rawValue)
            try writeResourceName(name, to: &writer)

        case .mx(let preference, let exchange):
            writer.writeUInt8(RecordType.mx.rawValue)
            writer.writeUInt16BE(preference)
            try writeResourceName(exchange, to: &writer)

        case .tlsa(let port, let proto, let usage, let selector, let matchingType, let certificate):
            writer.writeUInt8(RecordType.tlsa.rawValue)
            writer.writeUInt16BE(port)
            writer.writeUInt8(proto)
            writer.writeUInt8(usage)
            writer.writeUInt8(selector)
            writer.writeUInt8(matchingType)
            writer.writeUInt16BE(UInt16(certificate.count))
            writer.writeBytes(certificate)

        case .caa(let flags, let tag, let value):
            writer.writeUInt8(RecordType.caa.rawValue)
            writer.writeUInt8(flags)
            let tagBytes = Array(tag.utf8)
            writer.writeUInt8(UInt8(tagBytes.count))
            writer.writeBytes(tagBytes)
            let valueBytes = Array(value.utf8)
            writer.writeUInt16BE(UInt16(valueBytes.count))
            writer.writeBytes(valueBytes)

        case .sub(let name, let records):
            writer.writeUInt8(RecordType.sub.rawValue)
            let nameBytes = Array(name.utf8)
            writer.writeUInt8(UInt8(nameBytes.count))
            writer.writeBytes(nameBytes)
            writer.writeUInt8(UInt8(records.count))
            for record in records {
                try writeRecord(record, to: &writer)
            }

        case .wallet(let address):
            writer.writeUInt8(RecordType.wallet.rawValue)
            let addrBytes = Array(address.utf8)
            writer.writeUInt8(UInt8(min(addrBytes.count, 255)))
            writer.writeBytes(addrBytes.prefix(255))
        }
    }

    /// Write a DNS-style name (label encoding, no compression).
    private func writeResourceName(_ name: String, to writer: inout BufferWriter) throws {
        let cleaned = name.hasSuffix(".") ? String(name.dropLast()) : name
        if cleaned.isEmpty {
            writer.writeUInt8(0)
            return
        }
        let labels = cleaned.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels {
            let bytes = Array(label.utf8)
            guard bytes.count <= DNSConstants.maxLabelLength else {
                throw DNSError.labelTooLong(bytes.count)
            }
            writer.writeUInt8(UInt8(bytes.count))
            writer.writeBytes(bytes)
        }
        writer.writeUInt8(0)
    }

    // MARK: - Convenience accessors

    /// Get all NS-like records (ns, glue4, glue6, synth4, synth6).
    public var nameservers: [Record] {
        records.filter {
            switch $0 {
            case .ns, .glue4, .glue6, .synth4, .synth6: return true
            default: return false
            }
        }
    }

    /// Get all DS records.
    public var dsRecords: [Record] {
        records.filter { if case .ds = $0 { return true } else { return false } }
    }

    /// Get all TXT records.
    public var txtRecords: [Record] {
        records.filter { if case .txt = $0 { return true } else { return false } }
    }

    /// Whether this resource has any nameserver records.
    public var hasNS: Bool {
        !nameservers.isEmpty
    }

    /// Get the first WALLET record address, if any.
    public var walletAddress: String? {
        for record in records {
            if case .wallet(let address) = record { return address }
        }
        return nil
    }

    /// Find inline subdomain records matching a single label (case-insensitive).
    public func subRecords(for label: String) -> [Record]? {
        let lower = label.lowercased()
        for record in records {
            if case .sub(let name, let nested) = record, name.lowercased() == lower {
                return nested
            }
        }
        return nil
    }
}
