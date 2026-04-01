import Base

/// A Fistbump transaction output.
///
/// Wire format:
/// ```
/// [8 bytes]     value (uint64 LE, bumps)
/// [variable]    address (version + hash length + hash)
/// [variable]    covenant (type + items)
/// ```
public struct Output: Equatable, Sendable {
    /// The output value in bumps.
    public let value: UInt64

    /// The destination address (witness program).
    public let address: Address

    /// The covenant (name operation, or `.none` for standard transfers).
    public let covenant: Covenant

    public init(value: UInt64, address: Address, covenant: Covenant = .none) {
        self.value = value
        self.address = address
        self.covenant = covenant
    }
}

extension Output: WireSerializable {
    public var serializedSize: Int {
        8 + address.serializedSize + covenant.serializedSize
    }

    public func write(to writer: inout BufferWriter) {
        writer.writeUInt64LE(value)
        address.write(to: &writer)
        covenant.write(to: &writer)
    }

    public static func read(from reader: inout BufferReader) throws -> Output {
        let value = try reader.readUInt64LE()
        let address = try Address.read(from: &reader)
        let covenant = try Covenant.read(from: &reader)
        return Output(value: value, address: address, covenant: covenant)
    }
}
