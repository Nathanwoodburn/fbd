import Storage
import Foundation
import Base
import ExtCrypto
import Protocol

// MARK: - Storage Helpers

extension WalletDB {
    func get(db: UInt8, key: [UInt8]) throws -> [UInt8]? {
        try store.get(db: db, key: key)
    }

    func put(db: UInt8, key: [UInt8], value: [UInt8]) throws {
        try store.put(db: db, key: key, value: value)
    }

    func writeBatch(_ operations: [(db: UInt8, op: LevelDBStore.BatchOp)]) throws {
        try store.writeBatch(operations)
    }

    func forEachEntry(db: UInt8, _ body: ([UInt8], [UInt8]) throws -> Void) throws {
        try store.forEachEntry(db: db, body)
    }

    func reverseForEachEntry(db: UInt8, _ body: ([UInt8], [UInt8]) throws -> Bool) throws {
        try store.reverseForEachEntry(db: db, body)
    }

    func clearDB(_ db: UInt8) throws {
        try store.clearDatabase(db: db)
    }

    /// Serialize an extended private key to 73 bytes: key(32) + chainCode(32) + depth(1) + fingerprint(4 BE) + index(4 BE).
    func serializeAccountKey(_ k: ExtendedPrivateKey) -> [UInt8] {
        var w = BufferWriter(capacity: 73)
        w.writeBytes(k.key)
        w.writeBytes(k.chainCode)
        w.writeUInt8(k.depth)
        w.writeUInt32BE(k.fingerprint)
        w.writeUInt32BE(k.index)
        return w.data
    }

    // MARK: - Key Encoding Helpers

    func outpointKey(_ outpoint: Outpoint) -> [UInt8] {
        var w = BufferWriter(capacity: 36)
        w.writeBytes(outpoint.hash.bytes)
        w.writeUInt32LE(outpoint.index)
        return w.data
    }

    func addressKeyBytes(_ address: Address) -> [UInt8] {
        var key = [address.version]
        key.append(contentsOf: address.hash)
        return key
    }

    func intToBytes(_ value: Int) -> [UInt8] {
        var w = BufferWriter(capacity: 8)
        w.writeInt64LE(Int64(value))
        return w.data
    }

    func bytesToInt(_ data: [UInt8]) -> Int {
        var r = BufferReader(data)
        guard let v = try? r.readInt64LE() else { return -1 }
        return Int(v)
    }

    // MARK: - Undo Serialization

    /// Serialize a single undo entry: [keyLen:4 LE][key][valueLen:4 LE][value]
    func serializeUndoEntry(_ key: [UInt8], _ value: [UInt8]) -> [UInt8] {
        var w = BufferWriter(capacity: 8 + key.count + value.count)
        w.writeUInt32LE(UInt32(key.count))
        w.writeBytes(key)
        w.writeUInt32LE(UInt32(value.count))
        w.writeBytes(value)
        return w.data
    }

    /// Deserialize undo entries: returns [(coinKey, coinData)] pairs.
    func deserializeUndoEntries(_ data: [UInt8]) -> [([UInt8], [UInt8])] {
        var r = BufferReader(data)
        var result = [([UInt8], [UInt8])]()
        while let keyLen = try? r.readUInt32LE(),
              let key = try? r.readBytes(Int(keyLen)),
              let valLen = try? r.readUInt32LE(),
              let value = try? r.readBytes(Int(valLen)) {
            result.append((key, value))
        }
        return result
    }

    /// Reconstruct an Outpoint from a 36-byte coin key.
    func outpointFromKey(_ key: [UInt8]) -> Outpoint {
        var r = BufferReader(key)
        guard let hash = try? r.readBytes(32),
              let idx = try? r.readUInt32LE()
        else { return Outpoint(hash: .zero, index: 0) }
        return Outpoint(hash: Hash256(unchecked: hash), index: idx)
    }

    // MARK: - History Key

    /// Build a history key: [height:4 BE][txIndex:2 BE][txHash:32]
    /// Big-endian height ensures LevelDB sorts chronologically (oldest first).
    func historyKey(height: Int, txIndex: Int, txHash: Hash256) -> [UInt8] {
        var key = [UInt8]()
        key.reserveCapacity(38)
        let h = UInt32(clamping: height)
        key.append(UInt8((h >> 24) & 0xFF))
        key.append(UInt8((h >> 16) & 0xFF))
        key.append(UInt8((h >> 8) & 0xFF))
        key.append(UInt8(h & 0xFF))
        let ti = UInt16(clamping: txIndex)
        key.append(UInt8((ti >> 8) & 0xFF))
        key.append(UInt8(ti & 0xFF))
        key.append(contentsOf: txHash.bytes)
        return key
    }
}
