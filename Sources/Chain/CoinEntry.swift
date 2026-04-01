import Base
import Protocol

/// A single unspent transaction output (UTXO) in the coin set.
///
/// Stores the output along with metadata needed for validation:
/// which transaction version created it, at what height, and whether
/// it came from a coinbase transaction.
public struct CoinEntry: Equatable, Sendable {
    /// Height sentinel for unconfirmed coins (all 31 height bits set).
    static let unconfirmedHeightSentinel: UInt32 = 0x7FFF_FFFF

    /// The transaction version that created this output.
    public let version: UInt32

    /// The block height at which this output was created (-1 = unconfirmed).
    public let height: Int

    /// Whether this output came from a coinbase transaction.
    public let coinbase: Bool

    /// The actual output (value, address, covenant).
    public let output: Output

    /// Whether this coin has been spent (in-memory flag for CoinView).
    public var spent: Bool

    /// Whether this coin was created in the current block (not loaded from DB).
    /// Used to skip DB deletion for intra-block spends.
    public var fresh: Bool

    public init(version: UInt32 = 1, height: Int = -1, coinbase: Bool = false, output: Output, spent: Bool = false, fresh: Bool = false) {
        self.version = version
        self.height = height
        self.coinbase = coinbase
        self.output = output
        self.spent = spent
        self.fresh = fresh
    }

    /// Create a CoinEntry from a transaction output at a given height.
    public static func fromOutput(_ output: Output, height: Int, coinbase: Bool, version: UInt32 = 1) -> CoinEntry {
        CoinEntry(version: version, height: height, coinbase: coinbase, output: output, fresh: true)
    }

    // MARK: - Serialization

    /// Serialize this coin entry.
    ///
    /// Format: `varint(version) | uint32(field) | output_bytes`
    /// where field packs coinbase flag (bit 0) and height (bits 1-31).
    public func serialize() -> [UInt8] {
        var out = [UInt8]()

        // Version as varint
        appendVarint(&out, UInt64(version))

        // Field: coinbase(bit 0) | height(bits 1-31)
        var field: UInt32
        // Max height sentinel for unconfirmed coins (all 31 height bits set)
        if height < 0 {
            field = Self.unconfirmedHeightSentinel << 1
        } else {
            field = UInt32(height) << 1
        }
        if coinbase { field |= 1 }
        appendUInt32LE(&out, field)

        // Output: value + address + covenant
        var writer = BufferWriter()
        output.write(to: &writer)
        out.append(contentsOf: writer.data)

        return out
    }

    /// Deserialize a coin entry from bytes.
    public static func deserialize(from data: [UInt8]) throws -> CoinEntry {
        var pos = 0

        // Version
        let (version, vSize) = readVarint(data, pos)
        pos += vSize

        // Field
        guard pos + 4 <= data.count else {
            throw ChainError.validationFailed("coin entry truncated")
        }
        var fieldReader = BufferReader(Array(data[pos..<pos + 4]))
        let field = try fieldReader.readUInt32LE()
        pos += 4

        let coinbase = (field & 1) != 0
        let rawHeight = Int(field >> 1)
        let maxHeight = Int(Self.unconfirmedHeightSentinel)
        let height = rawHeight == maxHeight ? -1 : rawHeight

        // Output
        var reader = BufferReader(Array(data[pos...]))
        let output = try Output.read(from: &reader)

        return CoinEntry(
            version: UInt32(version),
            height: height,
            coinbase: coinbase,
            output: output
        )
    }

    // MARK: - Helpers

    private func appendVarint(_ out: inout [UInt8], _ val: UInt64) {
        var v = val
        while v >= 0x80 {
            out.append(UInt8(v & 0x7F) | 0x80)
            v >>= 7
        }
        out.append(UInt8(v))
    }

    private func appendUInt32LE(_ out: inout [UInt8], _ val: UInt32) {
        out.append(UInt8(val & 0xFF))
        out.append(UInt8((val >> 8) & 0xFF))
        out.append(UInt8((val >> 16) & 0xFF))
        out.append(UInt8((val >> 24) & 0xFF))
    }

    private static func readVarint(_ data: [UInt8], _ offset: Int) -> (UInt64, Int) {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        var pos = offset
        while pos < data.count {
            let byte = data[pos]
            pos += 1
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { break }
            shift += 7
        }
        return (result, pos - offset)
    }

}
