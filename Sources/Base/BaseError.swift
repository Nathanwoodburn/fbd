/// Errors thrown by Base operations.
public enum BaseError: Error, Sendable {
    /// Attempted to read past the end of the buffer.
    case bufferUnderflow

    /// A compact size value exceeds the allowed maximum.
    case compactSizeOverflow(UInt64)

    /// A compact size encoding is not canonical (uses more bytes than necessary).
    case compactSizeNonCanonical

    /// A hex string has an odd number of characters or contains invalid characters.
    case invalidHexString

    /// A hash was initialized with the wrong number of bytes.
    case invalidHashLength(expected: Int, got: Int)

    /// An amount is outside the valid range.
    case invalidAmount(Int64)
}
