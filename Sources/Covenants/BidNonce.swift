import Base

/// A 32-byte random nonce used for blind bid commitments.
///
/// The bid nonce is combined with the bid value to produce the blind hash
/// committed in BID covenants. It must be revealed during the REVEAL phase.
public struct BidNonce: Hashable, Sendable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw BaseError.invalidHashLength(expected: 32, got: bytes.count)
        }
        self.bytes = bytes
    }

    public init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public static let zero = BidNonce(unchecked: [UInt8](repeating: 0, count: 32))

    public var hex: String { HexEncoding.encode(bytes) }
}

extension BidNonce: CustomStringConvertible {
    public var description: String { hex }
}
