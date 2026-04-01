/// Errors that can occur during DNS operations.
public enum DNSError: Error, Equatable, Sendable {
    /// The DNS message is malformed.
    case malformedMessage(String)

    /// A DNS name label exceeds 63 bytes.
    case labelTooLong(Int)

    /// A DNS name exceeds 255 bytes.
    case nameTooLong(Int)

    /// An invalid compression pointer was encountered.
    case badCompressionPointer(Int)

    /// The FBD resource data version is unsupported.
    case unsupportedResourceVersion(UInt8)

    /// An unknown FBD record type was encountered.
    case unknownRecordType(UInt8)

    /// The resource data is malformed.
    case malformedResource(String)

    /// The name was not found in the tree.
    case nameNotFound

    /// The name is blacklisted.
    case blacklistedName(String)
}
