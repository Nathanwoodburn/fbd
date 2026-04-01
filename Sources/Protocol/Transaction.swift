import Base
import ExtCrypto

/// Protocol for types that can produce a witness hash.
public protocol WitnessHashable {
    func witnessHash() -> Hash256
}

/// A Fistbump transaction.
///
/// Wire format:
/// ```
/// [4 bytes]      version (uint32 LE)
/// [varint]       input count
/// [inputs...]    each input is 40 bytes
/// [varint]       output count
/// [outputs...]   variable size each
/// [4 bytes]      locktime (uint32 LE)
/// [witnesses...] one witness per input (always present, no segwit flag)
/// ```
public struct Transaction: Equatable, Sendable {
    /// The transaction version.
    public let version: UInt32

    /// The transaction inputs.
    public let inputs: [Input]

    /// The transaction outputs.
    public let outputs: [Output]

    /// The lock time (block height or timestamp threshold).
    public let locktime: UInt32

    /// The witness data (one per input).
    public let witnesses: [Witness]

    public init(
        version: UInt32 = 0,
        inputs: [Input],
        outputs: [Output],
        locktime: UInt32 = 0,
        witnesses: [Witness]? = nil
    ) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = locktime
        // Default to empty witnesses matching input count
        self.witnesses = witnesses ?? inputs.map { _ in .empty }
    }

    /// Whether this is a coinbase transaction.
    ///
    /// Matches hsd: only checks that the first input has a null prevout.
    /// Checks that the first input has a null prevout.
    public var isCoinbase: Bool {
        !inputs.isEmpty && inputs[0].isCoinbase
    }

    /// The "base" serialized size (excluding witness data), used for weight calculation.
    public var baseSize: Int {
        var size = 4 // version
        size += CompactSize.encodedSize(of: UInt64(inputs.count))
        for input in inputs {
            size += input.serializedSize
        }
        size += CompactSize.encodedSize(of: UInt64(outputs.count))
        for output in outputs {
            size += output.serializedSize
        }
        size += 4 // locktime
        return size
    }

    /// The witness data size.
    public var witnessSize: Int {
        witnesses.reduce(0) { $0 + $1.serializedSize }
    }

    /// The transaction weight (base_size * 4 + witness_size).
    public var weight: Int {
        baseSize * 4 + witnessSize
    }

    /// The virtual size (weight / 4, rounded up).
    public var virtualSize: Int {
        (weight + 3) / 4
    }

    /// Compute the transaction hash (BLAKE2b-256 of the base serialization).
    ///
    /// The base serialization excludes witness data. This matches
    /// Fistbump's transaction ID computation.
    public func txHash() -> Hash256 {
        var writer = BufferWriter()
        writer.writeUInt32LE(version)
        writer.writeCompactSize(UInt64(inputs.count))
        for input in inputs {
            input.write(to: &writer)
        }
        writer.writeCompactSize(UInt64(outputs.count))
        for output in outputs {
            output.write(to: &writer)
        }
        writer.writeUInt32LE(locktime)
        // BLAKE2b-256 of base (non-witness) serialization
        guard let hash = try? Blake2bHash.hash256(writer.data) else {
            return .zero
        }
        return hash
    }
}

extension Transaction: WireSerializable {
    public var serializedSize: Int {
        baseSize + witnessSize
    }

    public func write(to writer: inout BufferWriter) {
        writer.writeUInt32LE(version)
        writer.writeCompactSize(UInt64(inputs.count))
        for input in inputs {
            input.write(to: &writer)
        }
        writer.writeCompactSize(UInt64(outputs.count))
        for output in outputs {
            output.write(to: &writer)
        }
        writer.writeUInt32LE(locktime)
        for witness in witnesses {
            witness.write(to: &writer)
        }
    }

    public static func read(from reader: inout BufferReader) throws -> Transaction {
        let version = try reader.readUInt32LE()

        let inputCount = try reader.readCompactSize()
        guard inputCount <= 100_000 else {
            throw BaseError.bufferUnderflow
        }
        var inputs: [Input] = []
        inputs.reserveCapacity(Int(inputCount))
        for _ in 0..<inputCount {
            inputs.append(try Input.read(from: &reader))
        }

        let outputCount = try reader.readCompactSize()
        guard outputCount <= 100_000 else {
            throw BaseError.bufferUnderflow
        }
        var outputs: [Output] = []
        outputs.reserveCapacity(Int(outputCount))
        for _ in 0..<outputCount {
            outputs.append(try Output.read(from: &reader))
        }

        let locktime = try reader.readUInt32LE()

        var witnesses: [Witness] = []
        witnesses.reserveCapacity(Int(inputCount))
        for _ in 0..<inputCount {
            witnesses.append(try Witness.read(from: &reader))
        }

        return Transaction(
            version: version,
            inputs: inputs,
            outputs: outputs,
            locktime: locktime,
            witnesses: witnesses
        )
    }
}

// MARK: - WitnessHashable

extension Transaction: WitnessHashable {
    /// Compute the witness hash (wtxid).
    ///
    /// Fistbump wtxid = `blake2b(txHash || blake2b(witnessData))`
    /// where witnessData is the serialized witnesses concatenated.
    /// This matches hsd's `tx.witnessHash()` / `blake2b.root(hash, wdhash)`.
    public func witnessHash() -> Hash256 {
        witnessHash(txHash: txHash())
    }

    /// Compute witness hash using a pre-computed txHash to avoid double serialization.
    public func witnessHash(txHash: Hash256) -> Hash256 {
        // Hash just the witness data
        var witnessWriter = BufferWriter()
        for witness in witnesses {
            witness.write(to: &witnessWriter)
        }
        guard let right = try? Blake2bHash.hash256(witnessWriter.data) else {
            return .zero
        }

        // wtxid = blake2b(txHash || witnessDataHash)
        var combined = [UInt8]()
        combined.reserveCapacity(64)
        combined.append(contentsOf: txHash.bytes)
        combined.append(contentsOf: right.bytes)
        guard let root = try? Blake2bHash.hash256(combined) else {
            return .zero
        }
        return root
    }
}
