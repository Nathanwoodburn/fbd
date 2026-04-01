import Base
import ExtCrypto

/// The Brontide (Noise_XK) handshake state machine.
///
/// Performs a three-act handshake to establish an encrypted session:
/// - **Act 1** (Initiator → Responder): Ephemeral key exchange (es DH).
/// - **Act 2** (Responder → Initiator): Ephemeral-ephemeral key exchange (ee DH).
/// - **Act 3** (Initiator → Responder): Static key reveal (se DH).
///
/// After all three acts, both sides derive send/receive cipher states
/// for the encrypted transport.
///
/// Note: The full FBD protocol uses Elligator Squared to encode
/// ephemeral public keys as 64-byte uniform random blobs for censorship
/// resistance. This implementation uses raw 33-byte compressed keys
/// (Act 1/2 = 49 bytes, Act 3 = 65 bytes) as a simplification.
/// Elligator Squared support can be added later.
public struct BrontideHandshake: Sendable {

    /// Handshake phase.
    public enum Phase: Int, Sendable {
        case none = 0
        case actOne = 1
        case actTwo = 2
        case actThree = 3
        case done = 4
    }

    /// Whether this side initiated the connection.
    public let initiator: Bool

    /// Our static (long-term) private key.
    public var localStatic: PrivateKey

    /// Our static public key (33 bytes compressed).
    public let localStaticPub: PublicKey

    /// Remote peer's static public key (33 bytes).
    /// For XK pattern: initiator knows this before handshake.
    /// For responder: learned during Act 3.
    public var remoteStatic: [UInt8]

    /// Our ephemeral private key (generated during handshake).
    public var localEphemeral: [UInt8]

    /// Our ephemeral public key (33 bytes).
    public var localEphemeralPub: [UInt8]

    /// Remote peer's ephemeral public key (33 bytes).
    public var remoteEphemeral: [UInt8]

    /// The symmetric state for the handshake.
    public var state: SymmetricState

    /// Send cipher (after split).
    public var sendCipher: CipherState

    /// Receive cipher (after split).
    public var recvCipher: CipherState

    /// Current handshake phase.
    public var phase: Phase

    /// Size of Act 1 message (simplified: 33-byte compressed key + 16-byte tag).
    public static let actOneSize = 49

    /// Size of Act 2 message (simplified: 33-byte compressed key + 16-byte tag).
    public static let actTwoSize = 49

    /// Size of Act 3 message (33-byte encrypted pubkey + 16-byte tag1 + 16-byte tag2).
    public static let actThreeSize = 65

    /// Create a Brontide handshake.
    ///
    /// - Parameters:
    ///   - initiator: Whether this side initiates the connection.
    ///   - localStatic: Our static private key (32 bytes).
    ///   - remoteStatic: Remote peer's static public key (33 bytes).
    ///                   Required for initiator (XK pattern), empty for responder.
    public init(initiator: Bool, localStatic: PrivateKey, remoteStatic: [UInt8] = []) throws {
        self.initiator = initiator
        self.localStatic = localStatic
        self.localStaticPub = try ECDSASigner.publicKey(from: localStatic)
        self.remoteStatic = remoteStatic
        self.localEphemeral = []
        self.localEphemeralPub = []
        self.remoteEphemeral = []
        self.state = SymmetricState()
        self.sendCipher = CipherState()
        self.recvCipher = CipherState()
        self.phase = .none

        // Initialize Noise
        state.initProtocol(NetConstants.noiseProtocol)
        state.mixHash(NetConstants.noisePrologue)

        // XK pattern: initiator pre-knows responder's static key
        if initiator {
            state.mixHash(remoteStatic)
        } else {
            state.mixHash(localStaticPub.bytes)
        }
    }

    // MARK: - ECDH helper

    /// Compute ECDH shared secret, then SHA-256 hash it.
    private func ecdh(pub: [UInt8], priv: [UInt8]) throws -> [UInt8] {
        let raw = try ECDH.sharedSecret(privateKey: priv, publicKey: pub)
        return Array(SHA256Hash.hash(raw).bytes)
    }

    // MARK: - Act 1 (Initiator → Responder)

    /// Generate Act 1 message (initiator side).
    ///
    /// - Returns: The Act 1 bytes (49 bytes: ephemeral pubkey + tag).
    public mutating func genActOne() throws -> [UInt8] {
        // Generate ephemeral keypair
        let ephKey = try ECDSASigner.generatePrivateKey()
        localEphemeral = ephKey.bytes
        localEphemeralPub = try ECDSASigner.publicKey(from: ephKey).bytes

        // Mix ephemeral public key into hash
        state.mixHash(localEphemeralPub)

        // es DH: ECDH(remoteStatic, localEphemeral)
        let s = try ecdh(pub: remoteStatic, priv: localEphemeral)
        state.mixKey(s)

        // Encrypt empty payload with digest as AD
        var empty = [UInt8]()
        let tag = try state.encryptHash(&empty)

        phase = .actOne
        return localEphemeralPub + tag
    }

    /// Receive Act 1 message (responder side).
    ///
    /// - Parameter data: The Act 1 bytes (49 bytes).
    public mutating func recvActOne(_ data: [UInt8]) throws {
        guard data.count == BrontideHandshake.actOneSize else {
            throw NetError.handshakeFailed("Bad Act 1 size: \(data.count)")
        }

        // Extract ephemeral public key
        remoteEphemeral = Array(data[0..<33])
        let tag = Array(data[33..<49])

        // Mix remote ephemeral into hash
        state.mixHash(remoteEphemeral)

        // es DH: ECDH(remoteEphemeral, localStatic)
        let s = try ecdh(pub: remoteEphemeral, priv: localStatic.bytes)
        state.mixKey(s)

        // Verify tag on empty payload
        var empty = [UInt8]()
        guard state.decryptHash(&empty, tag: tag) else {
            throw NetError.handshakeFailed("Bad Act 1 tag")
        }

        phase = .actOne
    }

    // MARK: - Act 2 (Responder → Initiator)

    /// Generate Act 2 message (responder side).
    ///
    /// - Returns: The Act 2 bytes (49 bytes: ephemeral pubkey + tag).
    public mutating func genActTwo() throws -> [UInt8] {
        // Generate ephemeral keypair
        let ephKey = try ECDSASigner.generatePrivateKey()
        localEphemeral = ephKey.bytes
        localEphemeralPub = try ECDSASigner.publicKey(from: ephKey).bytes

        // Mix ephemeral public key into hash
        state.mixHash(localEphemeralPub)

        // ee DH: ECDH(remoteEphemeral, localEphemeral)
        let s = try ecdh(pub: remoteEphemeral, priv: localEphemeral)
        state.mixKey(s)

        // Encrypt empty payload
        var empty = [UInt8]()
        let tag = try state.encryptHash(&empty)

        phase = .actTwo
        return localEphemeralPub + tag
    }

    /// Receive Act 2 message (initiator side).
    ///
    /// - Parameter data: The Act 2 bytes (49 bytes).
    public mutating func recvActTwo(_ data: [UInt8]) throws {
        guard data.count == BrontideHandshake.actTwoSize else {
            throw NetError.handshakeFailed("Bad Act 2 size: \(data.count)")
        }

        remoteEphemeral = Array(data[0..<33])
        let tag = Array(data[33..<49])

        state.mixHash(remoteEphemeral)

        // ee DH
        let s = try ecdh(pub: remoteEphemeral, priv: localEphemeral)
        state.mixKey(s)

        var empty = [UInt8]()
        guard state.decryptHash(&empty, tag: tag) else {
            throw NetError.handshakeFailed("Bad Act 2 tag")
        }

        phase = .actTwo
    }

    // MARK: - Act 3 (Initiator → Responder)

    /// Generate Act 3 message (initiator side).
    ///
    /// - Returns: The Act 3 bytes (65 bytes: encrypted static pubkey + tag1 + tag2).
    public mutating func genActThree() throws -> [UInt8] {
        // Encrypt our static public key
        var pubKey = localStaticPub.bytes
        let tag1 = try state.encryptHash(&pubKey)

        // se DH: ECDH(remoteEphemeral, localStatic)
        let s = try ecdh(pub: remoteEphemeral, priv: localStatic.bytes)
        state.mixKey(s)

        // Encrypt empty payload
        var empty = [UInt8]()
        let tag2 = try state.encryptHash(&empty)

        split()
        phase = .done
        return pubKey + tag1 + tag2
    }

    /// Receive Act 3 message (responder side).
    ///
    /// - Parameter data: The Act 3 bytes (65 bytes).
    public mutating func recvActThree(_ data: [UInt8]) throws {
        guard data.count == BrontideHandshake.actThreeSize else {
            throw NetError.handshakeFailed("Bad Act 3 size: \(data.count)")
        }

        var ct = Array(data[0..<33])      // encrypted static pubkey
        let tag1 = Array(data[33..<49])
        let tag2 = Array(data[49..<65])

        // Decrypt remote static public key
        guard state.decryptHash(&ct, tag: tag1) else {
            throw NetError.handshakeFailed("Bad Act 3 tag1")
        }
        remoteStatic = ct

        // se DH: ECDH(remoteStatic, localEphemeral)
        let s = try ecdh(pub: remoteStatic, priv: localEphemeral)
        state.mixKey(s)

        // Verify second tag
        var empty = [UInt8]()
        guard state.decryptHash(&empty, tag: tag2) else {
            throw NetError.handshakeFailed("Bad Act 3 tag2")
        }

        split()
        phase = .done
    }

    // MARK: - Split

    /// Derive transport cipher keys from the handshake state.
    private mutating func split() {
        let (h1, h2) = HKDF256.expand(
            secret: [UInt8](repeating: 0, count: 0),
            salt: state.chain
        )
        if initiator {
            sendCipher.initSalt(h1, state.chain)
            recvCipher.initSalt(h2, state.chain)
        } else {
            recvCipher.initSalt(h1, state.chain)
            sendCipher.initSalt(h2, state.chain)
        }

        // Zero key material after handshake completes
        for i in localEphemeral.indices { localEphemeral[i] = 0 }
        localStatic = .zero
        for i in state.chain.indices { state.chain[i] = 0 }
        for i in state.digest.indices { state.digest[i] = 0 }
    }

    // MARK: - Post-Handshake Transport

    /// Encrypt a message for sending.
    ///
    /// Returns the encrypted frame: encrypted_length(4) + tag1(16) + encrypted_data(N) + tag2(16).
    public mutating func write(_ data: [UInt8]) throws -> [UInt8] {
        // Encrypt the 4-byte length
        var lenBuf = [UInt8](repeating: 0, count: 4)
        let len = UInt32(data.count)
        lenBuf[0] = UInt8(len & 0xFF)
        lenBuf[1] = UInt8((len >> 8) & 0xFF)
        lenBuf[2] = UInt8((len >> 16) & 0xFF)
        lenBuf[3] = UInt8((len >> 24) & 0xFF)

        let tag1 = try sendCipher.encrypt(&lenBuf)

        // Encrypt the data
        var payload = data
        let tag2 = try sendCipher.encrypt(&payload)

        return lenBuf + tag1 + payload + tag2
    }

    /// Parse an encrypted frame header (20 bytes: 4 encrypted length + 16 tag).
    ///
    /// - Returns: The decrypted payload length.
    public mutating func readHeader(_ data: [UInt8]) throws -> Int {
        guard data.count >= 20 else {
            throw NetError.handshakeFailed("Short header")
        }

        var encLen = Array(data[0..<4])
        let tag = Array(data[4..<20])

        guard recvCipher.decrypt(&encLen, tag: tag) else {
            throw NetError.badTag
        }

        let len = UInt32(encLen[0])
            | (UInt32(encLen[1]) << 8)
            | (UInt32(encLen[2]) << 16)
            | (UInt32(encLen[3]) << 24)

        let size = Int(len)
        guard size <= NetConstants.brontideMaxMessage else {
            throw NetError.messageTooLarge(size)
        }
        return size
    }

    /// Decrypt a payload (N bytes data + 16 bytes tag).
    ///
    /// - Returns: The decrypted payload bytes.
    public mutating func readBody(_ data: [UInt8], length: Int) throws -> [UInt8] {
        guard data.count >= length + 16 else {
            throw NetError.handshakeFailed("Short body")
        }

        var payload = Array(data[0..<length])
        let tag = Array(data[length..<(length + 16)])

        guard recvCipher.decrypt(&payload, tag: tag) else {
            throw NetError.badTag
        }
        return payload
    }
}
