import Base
import ExtCrypto
import Protocol

/// Signature hash types used in Handshake transaction signing.
public struct SigHashType: Equatable, Sendable {
    public let rawValue: UInt32

    public init(_ rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// The base type (lower 5 bits, excluding ANYONECANPAY and NOINPUT flags).
    public var baseType: UInt32 { rawValue & 0x1F }

    public static let all            = SigHashType(0x01)
    public static let none           = SigHashType(0x02)
    public static let single         = SigHashType(0x03)
    public static let singleReverse  = SigHashType(0x04)

    /// Flag: only sign the current input (ignore other inputs).
    public static let anyoneCanPayFlag: UInt32 = 0x80

    /// Flag: zero the input prevout, making signatures reusable across inputs.
    public static let noInputFlag: UInt32 = 0x40

    public var isAnyoneCanPay: Bool { rawValue & Self.anyoneCanPayFlag != 0 }
    public var isNoInput: Bool { rawValue & Self.noInputFlag != 0 }
}

/// BIP143-style signature hash computation using BLAKE2b-256.
public enum SigHash {

    /// Compute the signature hash for a transaction input.
    ///
    /// - Parameters:
    ///   - tx: The transaction being signed.
    ///   - index: The input index being signed.
    ///   - prevScript: The script code of the output being spent.
    ///   - value: The value (in bumps) of the output being spent.
    ///   - type: The signature hash type.
    /// - Returns: The 32-byte sighash digest.
    public static func compute(
        tx: Transaction,
        index: Int,
        prevScript: Script,
        value: UInt64,
        type: SigHashType
    ) throws -> Hash256 {
        let sigType = type.baseType
        let anyoneCanPay = type.isAnyoneCanPay
        let noInput = type.isNoInput

        // hashPrevouts
        let hashPrevouts: [UInt8]
        if !anyoneCanPay && !noInput {
            var w = BufferWriter()
            for input in tx.inputs {
                input.prevout.write(to: &w)
            }
            hashPrevouts = try Blake2bHash.hash(w.data, size: 32)
        } else {
            hashPrevouts = [UInt8](repeating: 0, count: 32)
        }

        // hashSequence
        let hashSequence: [UInt8]
        if !anyoneCanPay && sigType != SigHashType.none.baseType
            && sigType != SigHashType.single.baseType
            && sigType != SigHashType.singleReverse.baseType
        {
            var w = BufferWriter()
            for input in tx.inputs {
                w.writeUInt32LE(input.sequence)
            }
            hashSequence = try Blake2bHash.hash(w.data, size: 32)
        } else {
            hashSequence = [UInt8](repeating: 0, count: 32)
        }

        // hashOutputs
        let hashOutputs: [UInt8]
        if sigType == SigHashType.all.baseType {
            var w = BufferWriter()
            for output in tx.outputs {
                output.write(to: &w)
            }
            hashOutputs = try Blake2bHash.hash(w.data, size: 32)
        } else if sigType == SigHashType.single.baseType && index < tx.outputs.count {
            var w = BufferWriter()
            tx.outputs[index].write(to: &w)
            hashOutputs = try Blake2bHash.hash(w.data, size: 32)
        } else if sigType == SigHashType.singleReverse.baseType {
            let mirrorIndex = tx.outputs.count - 1 - index
            if mirrorIndex >= 0 && mirrorIndex < tx.outputs.count {
                var w = BufferWriter()
                tx.outputs[mirrorIndex].write(to: &w)
                hashOutputs = try Blake2bHash.hash(w.data, size: 32)
            } else {
                hashOutputs = [UInt8](repeating: 0, count: 32)
            }
        } else {
            hashOutputs = [UInt8](repeating: 0, count: 32)
        }

        // Build the preimage
        let input = tx.inputs[index]
        let prevout: Outpoint
        if noInput {
            prevout = Outpoint(hash: .zero, index: 0)
        } else {
            prevout = input.prevout
        }

        var preimage = BufferWriter()
        preimage.writeUInt32LE(tx.version)          // 4: version
        preimage.writeBytes(hashPrevouts)            // 32: prevouts hash
        preimage.writeBytes(hashSequence)            // 32: sequences hash
        prevout.write(to: &preimage)                 // 36: outpoint
        preimage.writeVarBytes(prevScript.raw)       // var: script code
        preimage.writeUInt64LE(value)                // 8: value
        preimage.writeUInt32LE(input.sequence)       // 4: sequence
        preimage.writeBytes(hashOutputs)             // 32: outputs hash
        preimage.writeUInt32LE(tx.locktime)          // 4: locktime
        preimage.writeUInt32LE(type.rawValue)        // 4: sighash type

        return try Blake2bHash.hash256(preimage.data)
    }

    /// Extract the sighash type from a signature.
    /// The last byte of the signature is the sighash type.
    /// Returns nil if the base type is not in the valid range (ALL..SINGLEREVERSE).
    public static func extractType(from signature: [UInt8]) -> SigHashType? {
        guard !signature.isEmpty else { return nil }
        let type = SigHashType(UInt32(signature[signature.count - 1]))
        let base = type.baseType
        guard base >= 1 && base <= 4 else { return nil }
        return type
    }

    /// Strip the sighash type byte from a signature.
    public static func stripType(from signature: [UInt8]) -> [UInt8] {
        guard !signature.isEmpty else { return [] }
        return Array(signature.dropLast())
    }
}
