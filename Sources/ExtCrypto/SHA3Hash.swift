import CSHA3
import Base

/// SHA3-256 hashing utilities.
///
/// Handshake uses SHA3-256 for name hashing and other protocol operations.
public enum SHA3Hash {
    /// Compute SHA3-256 of the given data, returning a 32-byte hash.
    public static func sha3_256(_ data: [UInt8]) -> Hash256 {
        var out = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBufferPointer { inBuf in
            out.withUnsafeMutableBufferPointer { outBuf in
                csha3_256(inBuf.baseAddress, data.count, outBuf.baseAddress)
            }
        }
        return Hash256(unchecked: out)
    }

    /// Compute Keccak-256 of the given data, returning a 32-byte hash.
    ///
    /// Keccak-256 uses domain suffix 0x01 (pre-FIPS), unlike SHA3-256 (0x06).
    /// Used by Handshake's OP_KECCAK opcode.
    public static func keccak_256(_ data: [UInt8]) -> Hash256 {
        var out = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBufferPointer { inBuf in
            out.withUnsafeMutableBufferPointer { outBuf in
                ckeccak_256(inBuf.baseAddress, data.count, outBuf.baseAddress)
            }
        }
        return Hash256(unchecked: out)
    }
}
