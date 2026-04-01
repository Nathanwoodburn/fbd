import Base
import ExtCrypto
import Protocol

/// Protocol for all P2P packet payloads.
public protocol Packet: Sendable {
    /// The packet type identifier.
    static var type: PacketType { get }

    /// Serialize the packet payload.
    func encode() -> [UInt8]

    /// Deserialize the packet payload.
    static func decode(from data: [UInt8]) throws -> Self
}

// MARK: - Version (type 0)

/// Version handshake packet — first message sent on connection.
public struct VersionPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .version

    /// Protocol version.
    public let version: UInt32
    /// Advertised service flags.
    public let services: UInt32
    /// Sender's unix timestamp.
    public let time: UInt64
    /// Receiver's address as seen by sender.
    public let remote: NetAddress
    /// Random nonce for self-connection detection.
    public let nonce: [UInt8]
    /// User agent string.
    public let agent: String
    /// Sender's best known block height.
    public let height: UInt32
    /// Whether to relay transactions.
    public let noRelay: Bool
    /// Sender's listen port (0 = unknown/not listening).
    public let listenPort: UInt16

    public init(
        version: UInt32 = NetConstants.protocolVersion,
        services: UInt32 = ServiceFlags.localServices.rawValue,
        time: UInt64 = 0,
        remote: NetAddress = NetAddress(),
        nonce: [UInt8] = [UInt8](repeating: 0, count: 8),
        agent: String = NetConstants.userAgent,
        height: UInt32 = 0,
        noRelay: Bool = false,
        listenPort: UInt16 = 0
    ) {
        self.version = version
        self.services = services
        self.time = time
        self.remote = remote
        self.nonce = nonce
        self.agent = agent
        self.height = height
        self.noRelay = noRelay
        self.listenPort = listenPort
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        w.writeUInt32LE(version)
        w.writeUInt32LE(services)
        w.writeUInt32LE(0) // reserved high services
        w.writeUInt64LE(time)
        remote.write(to: &w)
        w.writeBytes(nonce)
        let agentBytes = Array(agent.utf8)
        w.writeUInt8(UInt8(min(agentBytes.count, 255)))
        w.writeBytes(agentBytes.prefix(255))
        w.writeUInt32LE(height)
        w.writeUInt8(noRelay ? 1 : 0)
        w.writeUInt16LE(listenPort)
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> VersionPacket {
        var r = BufferReader(data)
        let version = try r.readUInt32LE()
        let services = try r.readUInt32LE()
        _ = try r.readUInt32LE() // reserved high services
        let time = try r.readUInt64LE()
        let remote = try NetAddress.read(from: &r)
        let nonce = try r.readBytes(8)
        let agentLen = Int(try r.readUInt8())
        let agentBytes = try r.readBytes(agentLen)
        let agent = String(bytes: agentBytes, encoding: .utf8) ?? ""
        let height = try r.readUInt32LE()
        let noRelay = r.remaining > 0 ? (try r.readUInt8()) != 0 : false
        let listenPort = r.remaining >= 2 ? (try r.readUInt16LE()) : 0
        return VersionPacket(
            version: version,
            services: services,
            time: time,
            remote: remote,
            nonce: nonce,
            agent: agent,
            height: height,
            noRelay: noRelay,
            listenPort: listenPort
        )
    }
}

// MARK: - Verack (type 1)

/// Version acknowledgment — empty payload.
public struct VerackPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .verack

    public init() {}

    public func encode() -> [UInt8] { [] }

    public static func decode(from data: [UInt8]) throws -> VerackPacket {
        VerackPacket()
    }
}

// MARK: - Ping (type 2)

/// Ping packet with an 8-byte nonce.
public struct PingPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .ping

    /// Random 8-byte nonce — the peer must echo it in a pong.
    public let nonce: [UInt8]

    public init(nonce: [UInt8] = [UInt8](repeating: 0, count: 8)) {
        self.nonce = nonce
    }

    public func encode() -> [UInt8] { nonce }

    public static func decode(from data: [UInt8]) throws -> PingPacket {
        var r = BufferReader(data)
        let nonce = try r.readBytes(8)
        return PingPacket(nonce: nonce)
    }
}

// MARK: - Pong (type 3)

/// Pong packet — mirrors the ping nonce.
public struct PongPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .pong

    /// The echoed nonce from the corresponding ping.
    public let nonce: [UInt8]

    public init(nonce: [UInt8] = [UInt8](repeating: 0, count: 8)) {
        self.nonce = nonce
    }

    public func encode() -> [UInt8] { nonce }

    public static func decode(from data: [UInt8]) throws -> PongPacket {
        var r = BufferReader(data)
        let nonce = try r.readBytes(8)
        return PongPacket(nonce: nonce)
    }
}

// MARK: - GetAddr (type 4)

/// Request peer addresses — empty payload.
public struct GetAddrPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .getaddr

    public init() {}

    public func encode() -> [UInt8] { [] }

    public static func decode(from data: [UInt8]) throws -> GetAddrPacket {
        GetAddrPacket()
    }
}

// MARK: - Addr (type 5)

/// Peer address announcement.
public struct AddrPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .addr

    /// The peer addresses.
    public let items: [NetAddress]

    public init(items: [NetAddress]) {
        self.items = items
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        w.writeCompactSize(UInt64(items.count))
        for item in items {
            item.write(to: &w)
        }
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> AddrPacket {
        var r = BufferReader(data)
        let count = Int(try r.readCompactSize())
        guard count <= NetConstants.maxAddresses else {
            throw NetError.tooManyAddresses(count)
        }
        var items = [NetAddress]()
        items.reserveCapacity(count)
        for _ in 0..<count {
            items.append(try NetAddress.read(from: &r))
        }
        return AddrPacket(items: items)
    }
}

// MARK: - Inv (type 6)

/// Inventory announcement — advertise known transactions and blocks.
public struct InvPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .inv

    /// The inventory items.
    public let items: [InvItem]

    public init(items: [InvItem]) {
        self.items = items
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        w.writeCompactSize(UInt64(items.count))
        for item in items {
            item.write(to: &w)
        }
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> InvPacket {
        var r = BufferReader(data)
        let count = Int(try r.readCompactSize())
        guard count <= NetConstants.maxInv else {
            throw NetError.tooManyInvItems(count)
        }
        var items = [InvItem]()
        items.reserveCapacity(count)
        for _ in 0..<count {
            items.append(try InvItem.read(from: &r))
        }
        return InvPacket(items: items)
    }
}

// MARK: - GetData (type 7)

/// Request data by inventory items.
public struct GetDataPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .getdata

    public let items: [InvItem]

    public init(items: [InvItem]) {
        self.items = items
    }

    public func encode() -> [UInt8] {
        InvPacket(items: items).encode()
    }

    public static func decode(from data: [UInt8]) throws -> GetDataPacket {
        let inv = try InvPacket.decode(from: data)
        return GetDataPacket(items: inv.items)
    }
}

// MARK: - NotFound (type 8)

/// Inventory items not found.
public struct NotFoundPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .notfound

    public let items: [InvItem]

    public init(items: [InvItem]) {
        self.items = items
    }

    public func encode() -> [UInt8] {
        InvPacket(items: items).encode()
    }

    public static func decode(from data: [UInt8]) throws -> NotFoundPacket {
        let inv = try InvPacket.decode(from: data)
        return NotFoundPacket(items: inv.items)
    }
}

// MARK: - GetBlocks (type 9)

/// Request block inventory using a locator.
public struct GetBlocksPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .getblocks

    /// Locator hashes (from tip back to genesis, logarithmically spaced).
    public let locator: [Hash256]
    /// Stop hash (all zeros = no stop).
    public let stop: Hash256

    public init(locator: [Hash256], stop: Hash256 = .zero) {
        self.locator = locator
        self.stop = stop
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        w.writeCompactSize(UInt64(locator.count))
        for hash in locator {
            hash.write(to: &w)
        }
        stop.write(to: &w)
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> GetBlocksPacket {
        var r = BufferReader(data)
        let count = Int(try r.readCompactSize())
        guard count <= 64 else {
            throw NetError.malformedPacket("locator count exceeds maximum")
        }
        var locator = [Hash256]()
        locator.reserveCapacity(count)
        for _ in 0..<count {
            locator.append(try Hash256.read(from: &r))
        }
        let stop = try Hash256.read(from: &r)
        return GetBlocksPacket(locator: locator, stop: stop)
    }
}

// MARK: - GetHeaders (type 10)

/// Request block headers using a locator.
public struct GetHeadersPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .getheaders

    public let locator: [Hash256]
    public let stop: Hash256

    public init(locator: [Hash256], stop: Hash256 = .zero) {
        self.locator = locator
        self.stop = stop
    }

    public func encode() -> [UInt8] {
        GetBlocksPacket(locator: locator, stop: stop).encode()
    }

    public static func decode(from data: [UInt8]) throws -> GetHeadersPacket {
        let gb = try GetBlocksPacket.decode(from: data)
        return GetHeadersPacket(locator: gb.locator, stop: gb.stop)
    }
}

// MARK: - Headers (type 11)

/// Block headers response.
///
/// Wire format (v2 with proofs):
/// ```
/// [varint]       header count
/// [headers...]   each header (236 bytes)
/// [proofs...]    one BalloonProof per header (5376 bytes each)
/// ```
///
/// If the packet is shorter than expected (no proof data), proofs default to nil.
/// This provides backwards compatibility with older peers.
public struct HeadersPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .headers

    public let items: [BlockHeader]
    public let proofs: [BalloonProof]

    public init(items: [BlockHeader], proofs: [BalloonProof]) {
        self.items = items
        self.proofs = proofs
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        w.writeCompactSize(UInt64(items.count))
        for header in items {
            header.write(to: &w)
        }
        for proof in proofs {
            w.writeBytes(proof.serialize())
        }
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> HeadersPacket {
        var r = BufferReader(data)
        let count = Int(try r.readCompactSize())
        guard count <= NetConstants.maxHeaders else {
            throw NetError.tooManyHeaders(count)
        }
        var items = [BlockHeader]()
        items.reserveCapacity(count)
        for _ in 0..<count {
            items.append(try BlockHeader.read(from: &r))
        }
        var proofs = [BalloonProof]()
        proofs.reserveCapacity(count)
        for _ in 0..<count {
            guard r.remaining >= BalloonProof.serializedSize else {
                throw NetError.malformedPacket("missing BalloonProof for header")
            }
            let proofData = try r.readBytes(BalloonProof.serializedSize)
            guard let proof = BalloonProof.deserialize(proofData) else {
                throw NetError.malformedPacket("invalid BalloonProof")
            }
            proofs.append(proof)
        }
        return HeadersPacket(items: items, proofs: proofs)
    }
}

// MARK: - SendHeaders (type 12)

/// Request headers-first block announcements — empty payload.
public struct SendHeadersPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .sendheaders

    public init() {}

    public func encode() -> [UInt8] { [] }

    public static func decode(from data: [UInt8]) throws -> SendHeadersPacket {
        SendHeadersPacket()
    }
}

// MARK: - Block (type 13)

/// A full block message.
public struct BlockPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .block

    public let block: Block

    public init(block: Block) {
        self.block = block
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        block.write(to: &w)
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> BlockPacket {
        var r = BufferReader(data)
        let block = try Block.read(from: &r)
        return BlockPacket(block: block)
    }
}

// MARK: - TX (type 14)

/// A transaction message.
public struct TxPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .tx

    public let tx: Transaction

    public init(tx: Transaction) {
        self.tx = tx
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        tx.write(to: &w)
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> TxPacket {
        var r = BufferReader(data)
        let tx = try Transaction.read(from: &r)
        return TxPacket(tx: tx)
    }
}

// MARK: - Reject (type 15)

/// Rejection codes.
public enum RejectCode: UInt8, Sendable {
    case malformed       = 0x01
    case invalid         = 0x10
    case obsolete        = 0x11
    case duplicate       = 0x12
    case nonstandard     = 0x40
    case dust            = 0x41
    case insufficientfee = 0x42
    case checkpoint      = 0x43
}

/// A reject message.
public struct RejectPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .reject

    /// The type of message being rejected.
    public let message: UInt8
    /// The rejection code.
    public let code: UInt8
    /// Human-readable reason string.
    public let reason: String
    /// The hash of the rejected item (for block/tx).
    public let hash: Hash256

    public init(
        message: UInt8 = 0,
        code: UInt8 = 0,
        reason: String = "",
        hash: Hash256 = .zero
    ) {
        self.message = message
        self.code = code
        self.reason = reason
        self.hash = hash
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        w.writeUInt8(message)
        w.writeUInt8(code)
        let reasonBytes = Array(reason.utf8)
        w.writeUInt8(UInt8(min(reasonBytes.count, 255)))
        w.writeBytes(reasonBytes.prefix(255))
        // Hash is included for block/tx rejections
        if message == PacketType.block.rawValue ||
           message == PacketType.tx.rawValue {
            hash.write(to: &w)
        }
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> RejectPacket {
        var r = BufferReader(data)
        let message = try r.readUInt8()
        let code = try r.readUInt8()
        let reasonLen = Int(try r.readUInt8())
        let reasonBytes = try r.readBytes(reasonLen)
        let reason = String(bytes: reasonBytes, encoding: .utf8) ?? ""
        let hash: Hash256
        if r.remaining >= 32 {
            hash = try Hash256.read(from: &r)
        } else {
            hash = .zero
        }
        return RejectPacket(message: message, code: code, reason: reason, hash: hash)
    }
}

// MARK: - Mempool (type 16)

/// Request mempool contents — empty payload.
public struct MempoolPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .mempool

    public init() {}

    public func encode() -> [UInt8] { [] }

    public static func decode(from data: [UInt8]) throws -> MempoolPacket {
        MempoolPacket()
    }
}

// MARK: - FeeFilter (type 21)

/// Set a minimum fee rate filter.
public struct FeeFilterPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .feefilter

    /// Minimum fee rate in bumps per kilobyte.
    public let rate: Int64

    public init(rate: Int64) {
        self.rate = rate
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        w.writeUInt64LE(UInt64(bitPattern: rate))
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> FeeFilterPacket {
        var r = BufferReader(data)
        let raw = try r.readUInt64LE()
        return FeeFilterPacket(rate: Int64(bitPattern: raw))
    }
}

// MARK: - SendCmpct (type 22)

/// Enable compact blocks.
public struct SendCmpctPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .sendcmpct

    /// 0 = low bandwidth, 1 = high bandwidth.
    public let mode: UInt8
    /// Compact block protocol version.
    public let version: UInt64

    public init(mode: UInt8 = 0, version: UInt64 = 1) {
        self.mode = mode
        self.version = version
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        w.writeUInt8(mode)
        w.writeUInt64LE(version)
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> SendCmpctPacket {
        var r = BufferReader(data)
        let mode = try r.readUInt8()
        let version = try r.readUInt64LE()
        return SendCmpctPacket(mode: mode, version: version)
    }
}

// MARK: - GetProof (type 26, FBD-specific)

/// Request an Urkel tree proof for a name.
public struct GetProofPacket: Packet, Equatable, Sendable {
    public static let type: PacketType = .getproof

    /// The Urkel tree root hash.
    public let root: Hash256
    /// The name hash to look up.
    public let key: Hash256

    public init(root: Hash256, key: Hash256) {
        self.root = root
        self.key = key
    }

    public func encode() -> [UInt8] {
        var w = BufferWriter()
        root.write(to: &w)
        key.write(to: &w)
        return w.data
    }

    public static func decode(from data: [UInt8]) throws -> GetProofPacket {
        var r = BufferReader(data)
        let root = try Hash256.read(from: &r)
        let key = try Hash256.read(from: &r)
        return GetProofPacket(root: root, key: key)
    }
}
