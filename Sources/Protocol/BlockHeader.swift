import Base

/// A Fistbump block header (236 bytes).
///
/// The header is divided into three sections for PoW purposes:
/// - **Preheader** (76 bytes): nonce, time, prevBlock, treeRoot
/// - **Subheader** (128 bytes): extraNonce, reservedRoot, witnessRoot, merkleRoot, version, bits
/// - **Mask** (32 bytes): unused (zeroed), kept for wire format compatibility
///
/// Wire format (236 bytes total):
/// ```
/// [4 bytes]   nonce (uint32 LE)
/// [8 bytes]   time (uint64 LE)
/// [32 bytes]  prevBlock
/// [32 bytes]  treeRoot
/// [24 bytes]  extraNonce
/// [32 bytes]  reservedRoot
/// [32 bytes]  witnessRoot
/// [32 bytes]  merkleRoot
/// [4 bytes]   version (uint32 LE)
/// [4 bytes]   bits (uint32 LE)
/// [32 bytes]  mask
/// ```
public struct BlockHeader: Equatable, Sendable {
    /// The header size in bytes.
    public static let size = 236

    /// The extra nonce size in bytes.
    public static let nonceSize = 24

    /// The PoW mask size in bytes.
    public static let maskSize = 32

    // MARK: - Preheader fields

    /// The miner-iterated nonce.
    public let nonce: UInt32

    /// The block timestamp (seconds since epoch).
    public let time: UInt64

    /// The hash of the previous block.
    public let prevBlock: Hash256

    /// The Urkel tree root (name state).
    public let treeRoot: Hash256

    // MARK: - Subheader fields

    /// The extra nonce (24 bytes, miner-malleable).
    public let extraNonce: [UInt8]

    /// Reserved root (for future use).
    public let reservedRoot: Hash256

    /// The witness commitment merkle root.
    public let witnessRoot: Hash256

    /// The transaction merkle root.
    public let merkleRoot: Hash256

    /// The block version.
    public let version: UInt32

    /// The compact difficulty target.
    public let bits: UInt32

    // MARK: - Mask

    /// The PoW mask (32 bytes, unused in FBD — always zero).
    public let mask: [UInt8]

    public init(
        nonce: UInt32 = 0,
        time: UInt64 = 0,
        prevBlock: Hash256 = .zero,
        treeRoot: Hash256 = .zero,
        extraNonce: [UInt8] = [UInt8](repeating: 0, count: 24),
        reservedRoot: Hash256 = .zero,
        witnessRoot: Hash256 = .zero,
        merkleRoot: Hash256 = .zero,
        version: UInt32 = 0,
        bits: UInt32 = 0,
        mask: [UInt8] = [UInt8](repeating: 0, count: 32)
    ) {
        self.nonce = nonce
        self.time = time
        self.prevBlock = prevBlock
        self.treeRoot = treeRoot
        self.extraNonce = extraNonce
        self.reservedRoot = reservedRoot
        self.witnessRoot = witnessRoot
        self.merkleRoot = merkleRoot
        self.version = version
        self.bits = bits
        self.mask = mask
    }
}

extension BlockHeader: WireSerializable {
    public var serializedSize: Int { BlockHeader.size }

    public func write(to writer: inout BufferWriter) {
        // Preheader
        writer.writeUInt32LE(nonce)
        writer.writeUInt64LE(time)
        prevBlock.write(to: &writer)
        treeRoot.write(to: &writer)

        // Subheader
        writer.writeBytes(extraNonce)
        reservedRoot.write(to: &writer)
        witnessRoot.write(to: &writer)
        merkleRoot.write(to: &writer)
        writer.writeUInt32LE(version)
        writer.writeUInt32LE(bits)

        // Mask
        writer.writeBytes(mask)
    }

    public static func read(from reader: inout BufferReader) throws -> BlockHeader {
        // Preheader
        let nonce = try reader.readUInt32LE()
        let time = try reader.readUInt64LE()
        let prevBlock = try Hash256.read(from: &reader)
        let treeRoot = try Hash256.read(from: &reader)

        // Subheader
        let extraNonce = try reader.readBytes(BlockHeader.nonceSize)
        let reservedRoot = try Hash256.read(from: &reader)
        let witnessRoot = try Hash256.read(from: &reader)
        let merkleRoot = try Hash256.read(from: &reader)
        let version = try reader.readUInt32LE()
        let bits = try reader.readUInt32LE()

        // Mask
        let mask = try reader.readBytes(BlockHeader.maskSize)

        return BlockHeader(
            nonce: nonce,
            time: time,
            prevBlock: prevBlock,
            treeRoot: treeRoot,
            extraNonce: extraNonce,
            reservedRoot: reservedRoot,
            witnessRoot: witnessRoot,
            merkleRoot: merkleRoot,
            version: version,
            bits: bits,
            mask: mask
        )
    }
}
