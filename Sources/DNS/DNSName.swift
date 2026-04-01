import Base

/// DNS domain name encoding and decoding.
///
/// DNS names are encoded as a sequence of length-prefixed labels
/// terminated by a zero byte. Compression pointers (RFC 1035 Section 4.1.4)
/// use the top 2 bits of the length byte set to `11`, with the remaining
/// 14 bits as an offset into the message.
public enum DNSName {

    /// Encode a domain name as DNS wire format labels.
    ///
    /// - Parameter name: A dot-separated domain name (e.g., "example.com." or "example.com").
    /// - Returns: The wire-format encoded name.
    public static func encode(_ name: String) throws -> [UInt8] {
        var result = [UInt8]()
        let cleaned = name.hasSuffix(".") ? String(name.dropLast()) : name

        if cleaned.isEmpty {
            // Root name
            result.append(0)
            return result
        }

        let labels = cleaned.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels {
            let bytes = Array(label.utf8)
            guard bytes.count <= DNSConstants.maxLabelLength else {
                throw DNSError.labelTooLong(bytes.count)
            }
            result.append(UInt8(bytes.count))
            result.append(contentsOf: bytes)
        }
        result.append(0) // root terminator

        guard result.count <= DNSConstants.maxNameLength else {
            throw DNSError.nameTooLong(result.count)
        }
        return result
    }

    /// Decode a DNS name from wire format.
    ///
    /// - Parameters:
    ///   - reader: The buffer reader positioned at the name.
    ///   - message: The full DNS message bytes (for resolving compression pointers).
    /// - Returns: The decoded domain name as a dot-separated string with trailing dot.
    public static func decode(from reader: inout BufferReader, message: [UInt8]? = nil) throws -> String {
        var labels = [String]()
        var jumped = false
        var jumps = 0
        var savedOffset = 0

        while true {
            guard reader.remaining > 0 else {
                throw DNSError.malformedMessage("Unexpected end of name")
            }

            let len = try reader.readUInt8()

            if len == 0 {
                // Root terminator
                break
            }

            if (len & 0xC0) == 0xC0 {
                // Compression pointer
                guard let msg = message else {
                    throw DNSError.badCompressionPointer(0)
                }
                let nextByte = try reader.readUInt8()
                let pointer = Int(UInt16(len & 0x3F) << 8 | UInt16(nextByte))
                guard pointer < msg.count else {
                    throw DNSError.badCompressionPointer(pointer)
                }

                if !jumped {
                    savedOffset = reader.offset
                    jumped = true
                }

                jumps += 1
                guard jumps < 128 else {
                    throw DNSError.malformedMessage("Too many compression pointer jumps")
                }

                reader = BufferReader(msg)
                reader.offset = pointer
                continue
            }

            guard len <= 63 else {
                throw DNSError.labelTooLong(Int(len))
            }

            let labelBytes = try reader.readBytes(Int(len))
            let label = String(decoding: labelBytes, as: UTF8.self)
            labels.append(label)
        }

        if jumped {
            // Restore original position after pointer chain
            // (We consumed 2 bytes for the pointer in the original stream)
            reader = BufferReader(message!)
            reader.offset = savedOffset
        }

        return labels.isEmpty ? "." : labels.joined(separator: ".") + "."
    }

    /// Write a DNS name with optional compression.
    ///
    /// - Parameters:
    ///   - name: The domain name to write.
    ///   - writer: The buffer writer.
    ///   - compression: A map of name suffix → offset for compression.
    public static func write(
        _ name: String,
        to writer: inout BufferWriter,
        compression: inout [String: Int]
    ) throws {
        let cleaned = name.hasSuffix(".") ? String(name.dropLast()) : name

        if cleaned.isEmpty {
            writer.writeUInt8(0)
            return
        }

        let labels = cleaned.split(separator: ".", omittingEmptySubsequences: false).map(String.init)

        for i in 0..<labels.count {
            let suffix = labels[i...].joined(separator: ".") + "."

            // Check if this suffix was already written
            if let offset = compression[suffix], offset < 16384 {
                // Write compression pointer
                writer.writeUInt8(UInt8(0xC0 | (offset >> 8)))
                writer.writeUInt8(UInt8(offset & 0xFF))
                return
            }

            // Record this suffix's position
            compression[suffix] = writer.count

            // Write label
            let bytes = Array(labels[i].utf8)
            guard bytes.count <= DNSConstants.maxLabelLength else {
                throw DNSError.labelTooLong(bytes.count)
            }
            writer.writeUInt8(UInt8(bytes.count))
            writer.writeBytes(bytes)
        }

        // Root terminator
        writer.writeUInt8(0)
    }

    /// Write a DNS name without compression.
    public static func writeUncompressed(_ name: String, to writer: inout BufferWriter) throws {
        let encoded = try encode(name)
        writer.writeBytes(encoded)
    }
}
