import Foundation
import Base

/// Errors from the chain store.
public enum ChainStoreError: Error, Sendable {
    /// The file's network magic does not match the expected network.
    case networkMismatch
    /// The file format version is not supported.
    case unsupportedVersion
    /// The file is corrupted (bad header or impossible size).
    case corruptedFile
    /// An underlying I/O error occurred.
    case ioError(String)
}

/// Append-only binary file store for ChainEntry records.
///
/// Layout:
/// - 16-byte file header: magic (4B) + format version (4B) + entry size (4B) + reserved (4B)
/// - N records of fixed size (308 bytes each)
///
/// Genesis is never stored (always reconstructed from code).
/// On reload, entries are read sequentially and the last entry is the tip.
public final class ChainStore: @unchecked Sendable {

    /// Current file format version.
    private static let formatVersion: UInt32 = 1

    /// File header size in bytes.
    private static let fileHeaderSize = 16

    /// The network this store was created for.
    public let network: NetworkType

    /// The file path.
    public let path: String

    /// The underlying file handle for appending.
    private var fileHandle: FileHandle

    /// Number of entries currently in the file.
    private(set) var entryCount: Int

    /// Open or create a chain store at the given path for the given network.
    public init(path: String, network: NetworkType) throws {
        self.network = network
        self.path = path

        let fm = FileManager.default
        if fm.fileExists(atPath: path) {
            // Open existing file and validate header
            let fh = try FileHandle(forUpdating: URL(fileURLWithPath: path))
            self.fileHandle = fh

            try fh.seek(toOffset: 0)
            guard let headerData = try fh.read(upToCount: Self.fileHeaderSize),
                  headerData.count == Self.fileHeaderSize else {
                throw ChainStoreError.corruptedFile
            }

            var reader = BufferReader([UInt8](headerData))
            let magic = try reader.readUInt32LE()
            let version = try reader.readUInt32LE()
            let entrySize = try reader.readUInt32LE()
            _ = try reader.readUInt32LE() // reserved

            guard magic == network.magic else {
                throw ChainStoreError.networkMismatch
            }
            guard version == Self.formatVersion else {
                throw ChainStoreError.unsupportedVersion
            }
            guard entrySize == UInt32(ChainEntry.recordSize) else {
                throw ChainStoreError.corruptedFile
            }

            // Calculate entry count, truncate partial trailing entry
            let fileSize = try fh.seekToEnd()
            let dataSize = Int(fileSize) - Self.fileHeaderSize
            let fullEntries = dataSize / ChainEntry.recordSize
            let remainder = dataSize % ChainEntry.recordSize

            if remainder != 0 {
                // Truncate partial entry
                let truncatedSize = UInt64(Self.fileHeaderSize + fullEntries * ChainEntry.recordSize)
                try fh.truncate(atOffset: truncatedSize)
            }

            self.entryCount = fullEntries
        } else {
            // Create new file with header
            fm.createFile(atPath: path, contents: nil)
            let fh = try FileHandle(forUpdating: URL(fileURLWithPath: path))
            self.fileHandle = fh

            var writer = BufferWriter(capacity: Self.fileHeaderSize)
            writer.writeUInt32LE(network.magic)
            writer.writeUInt32LE(Self.formatVersion)
            writer.writeUInt32LE(UInt32(ChainEntry.recordSize))
            writer.writeUInt32LE(0) // reserved

            try fh.seek(toOffset: 0)
            fh.write(Data(writer.data))
            try fh.synchronize()

            self.entryCount = 0
        }
    }

    /// Read all stored entries from the file.
    ///
    /// Returns entries in order (lowest height first).
    /// Genesis is NOT included — it must be reconstructed from code.
    public func loadEntries() throws -> [ChainEntry] {
        guard entryCount > 0 else { return [] }

        try fileHandle.seek(toOffset: UInt64(Self.fileHeaderSize))

        let dataSize = entryCount * ChainEntry.recordSize
        guard let data = try fileHandle.read(upToCount: dataSize),
              data.count == dataSize else {
            throw ChainStoreError.corruptedFile
        }

        var entries: [ChainEntry] = []
        entries.reserveCapacity(entryCount)

        var reader = BufferReader([UInt8](data))
        for _ in 0..<entryCount {
            let entry = try ChainEntry.read(from: &reader)
            entries.append(entry)
        }

        return entries
    }

    /// Append entries to the file and fsync.
    ///
    /// Entries should be in height order (lowest first).
    public func appendEntries(_ entries: [ChainEntry]) throws {
        guard !entries.isEmpty else { return }

        var writer = BufferWriter(capacity: entries.count * ChainEntry.recordSize)
        for entry in entries {
            entry.write(to: &writer)
        }

        try fileHandle.seekToEnd()
        fileHandle.write(Data(writer.data))
        try fileHandle.synchronize()

        entryCount += entries.count
    }

    /// Truncate the store to keep only entries up to and including the given height.
    ///
    /// Genesis (height 0) is never stored, so height 0 means keep no entries.
    /// Height N means keep entries for heights 1...N.
    public func truncateToHeight(_ height: Int) throws {
        let keepCount = max(0, height)
        guard keepCount < entryCount else { return }

        let newSize = UInt64(Self.fileHeaderSize + keepCount * ChainEntry.recordSize)
        try fileHandle.truncate(atOffset: newSize)
        try fileHandle.synchronize()
        entryCount = keepCount
    }

    /// Close the file handle.
    public func close() throws {
        try fileHandle.close()
    }
}
