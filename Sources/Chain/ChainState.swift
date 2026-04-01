import Base
import Protocol

/// Running totals for the chain state.
///
/// Tracks aggregate statistics that are updated as blocks are
/// connected and disconnected: total transaction count, UTXO count,
/// total value in UTXOs, and total burned value (from REGISTER covenants).
public struct ChainState: Equatable, Sendable {
    /// The current chain tip hash.
    public var tip: Hash256

    /// Total number of transactions in the chain.
    public var tx: UInt64

    /// Total number of unspent transaction outputs.
    public var coin: UInt64

    /// Total value in all UTXOs (bumps).
    public var value: UInt64

    /// Total value paid to dev fund by REGISTER covenants (bumps).
    public var burned: UInt64

    /// Create an initial (empty) chain state.
    public init(tip: Hash256 = .zero) {
        self.tip = tip
        self.tx = 0
        self.coin = 0
        self.value = 0
        self.burned = 0
    }

    /// Update totals when a block is connected.
    public mutating func connect(txCount: Int) {
        tx += UInt64(txCount)
    }

    /// Update totals when a block is disconnected (saturating to prevent underflow).
    public mutating func disconnect(txCount: Int) {
        let sub = UInt64(txCount)
        tx = tx >= sub ? tx - sub : 0
    }

    /// Track a new UTXO being added.
    public mutating func add(value v: UInt64) {
        coin += 1
        value += v
    }

    /// Track a UTXO being spent (saturating to prevent underflow).
    public mutating func spend(value v: UInt64) {
        coin = coin > 0 ? coin - 1 : 0
        value = value >= v ? value - v : 0
    }

    /// Track a UTXO being burned (REGISTER covenant).
    public mutating func burn(value v: UInt64) {
        coin += 1
        burned += v
    }

    /// Reverse a burn (disconnect a REGISTER, saturating to prevent underflow).
    public mutating func unburn(value v: UInt64) {
        coin = coin > 0 ? coin - 1 : 0
        burned = burned >= v ? burned - v : 0
    }

    /// Commit the state with a new tip hash.
    public mutating func commit(_ hash: Hash256) {
        tip = hash
    }

    // MARK: - Serialization

    /// Serialized size: tip(32) + tx(8) + coin(8) + value(8) + burned(8) = 64 bytes.
    public static let serializedSize = 64

    /// Serialize to bytes.
    public func serialize() -> [UInt8] {
        var w = BufferWriter(capacity: 64)
        w.writeBytes(tip.bytes)
        w.writeUInt64LE(tx)
        w.writeUInt64LE(coin)
        w.writeUInt64LE(value)
        w.writeUInt64LE(burned)
        return w.data
    }

    /// Deserialize from bytes.
    public static func deserialize(from data: [UInt8]) throws -> ChainState {
        var r = BufferReader(data)
        guard r.remaining >= 64 else {
            throw ChainError.validationFailed("chain state too short")
        }
        let tip = Hash256(unchecked: try r.readBytes(32))
        let tx = try r.readUInt64LE()
        let coin = try r.readUInt64LE()
        let value = try r.readUInt64LE()
        let burned = try r.readUInt64LE()
        var state = ChainState(tip: tip)
        state.tx = tx
        state.coin = coin
        state.value = value
        state.burned = burned
        return state
    }
}
