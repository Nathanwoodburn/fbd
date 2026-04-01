import Foundation
import Base
import Protocol

/// Errors from the block store.
public enum BlockStoreError: Error, Sendable {
    /// The file's network magic does not match the expected network.
    case networkMismatch
    /// The file format version is not supported.
    case unsupportedVersion
    /// The file is corrupted (bad header or impossible size).
    case corruptedFile
    /// An underlying I/O error occurred.
    case ioError(String)
    /// Attempted to store a block at the wrong height.
    case heightMismatch(expected: Int, got: Int)
}

/// Chunked block storage matching hsd's `blocks/` layout.
///
/// Data is split across `blk{NNNNN}.dat` files that rotate at 128MB.
/// Each block is framed as `[magic:4 LE][length:4 LE][block data]`.
///
/// A single `index.bin` file maps height → (fileNo, offset, size):
/// - 16-byte header: magic(4) + version(4) + entryCount(4) + reserved(4)
/// - Per entry (12 bytes): fileNo(4 LE) + offset(4 LE) + size(4 LE)
public final class BlockStore: @unchecked Sendable {

    /// Current file format version.
    private static let formatVersion: UInt32 = 2

    /// Index file header size in bytes.
    private static let fileHeaderSize = 16

    /// Index entry size: fileNo(4) + offset(4) + size(4).
    private static let indexEntrySize = 12

    /// Maximum data file size before rotation (128MB).
    /// Tests can override via the internal initializer.
    let maxFileSize: UInt64

    /// The network this store was created for.
    public let network: NetworkType

    /// The blocks directory path.
    public let blocksDir: String

    /// The index file handle.
    private var indexHandle: FileHandle

    /// Number of blocks currently stored.
    public private(set) var storedCount: Int

    /// Current data file number being written to.
    private var currentFileNo: UInt32

    /// Current write offset within the active data file.
    private var currentOffset: UInt64

    /// The active data file handle (for writing and reading the current file).
    private var currentDataHandle: FileHandle

    /// Cached read handles for older data files.
    private var readHandles: [UInt32: FileHandle] = [:]

    /// Open or create a block store in the given directory.
    ///
    /// - Parameters:
    ///   - blocksDir: Path to the `blocks/` directory (must exist).
    ///   - network: The network type.
    public convenience init(blocksDir: String, network: NetworkType) throws {
        try self.init(blocksDir: blocksDir, network: network, maxFileSize: 128 * 1024 * 1024) // 128 MB
    }

    /// Internal initializer that allows overriding maxFileSize (for tests).
    init(blocksDir: String, network: NetworkType, maxFileSize: UInt64) throws {
        self.network = network
        self.blocksDir = blocksDir
        self.maxFileSize = maxFileSize

        let fm = FileManager.default
        let indexPath = blocksDir + "/index.bin"

        // Open or create index.bin
        if fm.fileExists(atPath: indexPath) {
            let fh = try FileHandle(forUpdating: URL(fileURLWithPath: indexPath))
            self.indexHandle = fh

            try fh.seek(toOffset: 0)
            guard let headerData = try fh.read(upToCount: Self.fileHeaderSize),
                  headerData.count == Self.fileHeaderSize else {
                throw BlockStoreError.corruptedFile
            }

            var reader = BufferReader([UInt8](headerData))
            let magic = try reader.readUInt32LE()
            let version = try reader.readUInt32LE()
            let entryCount = try reader.readUInt32LE()
            _ = try reader.readUInt32LE() // reserved

            guard magic == network.magic else {
                throw BlockStoreError.networkMismatch
            }
            guard version == Self.formatVersion else {
                throw BlockStoreError.unsupportedVersion
            }

            // Validate file size against entry count
            let fileSize = try fh.seekToEnd()
            let expectedSize = UInt64(Self.fileHeaderSize + Int(entryCount) * Self.indexEntrySize)
            if fileSize < expectedSize {
                let dataSize = Int(fileSize) - Self.fileHeaderSize
                self.storedCount = max(0, dataSize / Self.indexEntrySize)
            } else {
                self.storedCount = Int(entryCount)
            }
        } else {
            fm.createFile(atPath: indexPath, contents: nil)
            let fh = try FileHandle(forUpdating: URL(fileURLWithPath: indexPath))
            self.indexHandle = fh

            var writer = BufferWriter(capacity: Self.fileHeaderSize)
            writer.writeUInt32LE(network.magic)
            writer.writeUInt32LE(Self.formatVersion)
            writer.writeUInt32LE(0) // entry count
            writer.writeUInt32LE(0) // reserved

            try fh.seek(toOffset: 0)
            fh.write(Data(writer.data))
            try fh.synchronize()

            self.storedCount = 0
        }

        // Determine current file number and offset from last index entry
        if storedCount > 0 {
            let lastEntryOffset = UInt64(Self.fileHeaderSize + (storedCount - 1) * Self.indexEntrySize)
            try indexHandle.seek(toOffset: lastEntryOffset)
            guard let entryData = try indexHandle.read(upToCount: Self.indexEntrySize),
                  entryData.count == Self.indexEntrySize else {
                throw BlockStoreError.corruptedFile
            }

            var reader = BufferReader([UInt8](entryData))
            let fileNo = try reader.readUInt32LE()
            let offset = try reader.readUInt32LE()
            let size = try reader.readUInt32LE()

            self.currentFileNo = fileNo
            // Resume position: after the last block's frame (8-byte header + data)
            self.currentOffset = UInt64(offset) + 8 + UInt64(size)
        } else {
            self.currentFileNo = 0
            self.currentOffset = 0
        }

        // Open the current data file
        let dataPath = Self.dataFilePath(dir: blocksDir, fileNo: currentFileNo)
        if !fm.fileExists(atPath: dataPath) {
            fm.createFile(atPath: dataPath, contents: nil)
        }
        self.currentDataHandle = try FileHandle(forUpdating: URL(fileURLWithPath: dataPath))
    }

    /// Whether a block at the given height is stored.
    public func hasBlock(height: Int) -> Bool {
        height >= 0 && height < storedCount
    }

    /// Store a block at the given height.
    ///
    /// Blocks must be stored sequentially — the height must equal `storedCount`.
    public func storeBlock(_ block: Block, height: Int) throws {
        guard height == storedCount else {
            throw BlockStoreError.heightMismatch(expected: storedCount, got: height)
        }

        // Serialize block
        var blockWriter = BufferWriter(capacity: block.serializedSize)
        block.write(to: &blockWriter)
        let blockData = blockWriter.data
        let frameSize = UInt64(8 + blockData.count) // magic(4) + length(4) + data

        // Check if we need to rotate to a new file
        if currentOffset > 0 && currentOffset + frameSize > maxFileSize {
            // Close the current file if it's also cached as a read handle
            // (it won't be — current file isn't in readHandles — but be safe)
            try currentDataHandle.synchronize()
            try currentDataHandle.close()

            currentFileNo += 1
            currentOffset = 0

            let newPath = Self.dataFilePath(dir: blocksDir, fileNo: currentFileNo)
            FileManager.default.createFile(atPath: newPath, contents: nil)
            currentDataHandle = try FileHandle(forUpdating: URL(fileURLWithPath: newPath))
        }

        // Write frame: [magic:4 LE][length:4 LE][block data]
        var frameWriter = BufferWriter(capacity: 8)
        frameWriter.writeUInt32LE(network.magic)
        frameWriter.writeUInt32LE(UInt32(blockData.count))

        let writeOffset = currentOffset
        try currentDataHandle.seek(toOffset: writeOffset)
        currentDataHandle.write(Data(frameWriter.data))
        currentDataHandle.write(Data(blockData))

        // Write index entry: [fileNo:4 LE][offset:4 LE][size:4 LE]
        var idxWriter = BufferWriter(capacity: Self.indexEntrySize)
        idxWriter.writeUInt32LE(currentFileNo)
        idxWriter.writeUInt32LE(UInt32(writeOffset))
        idxWriter.writeUInt32LE(UInt32(blockData.count))

        let idxOffset = UInt64(Self.fileHeaderSize + height * Self.indexEntrySize)
        try indexHandle.seek(toOffset: idxOffset)
        indexHandle.write(Data(idxWriter.data))

        currentOffset = writeOffset + frameSize
        storedCount = height + 1

        // Update entry count in index header
        try updateIndexEntryCount()
    }

    /// Load a block at the given height.
    ///
    /// Returns nil if the height is out of range.
    public func loadBlock(height: Int) throws -> Block? {
        guard height >= 0 && height < storedCount else { return nil }

        // Read index entry
        let idxOffset = UInt64(Self.fileHeaderSize + height * Self.indexEntrySize)
        try indexHandle.seek(toOffset: idxOffset)
        guard let entryData = try indexHandle.read(upToCount: Self.indexEntrySize),
              entryData.count == Self.indexEntrySize else {
            return nil
        }

        var reader = BufferReader([UInt8](entryData))
        let fileNo = try reader.readUInt32LE()
        let offset = try reader.readUInt32LE()
        let size = try reader.readUInt32LE()

        guard size > 0 else { return nil }

        // Get the appropriate file handle
        let handle = try dataHandle(for: fileNo)

        // Seek past the 8-byte frame header (magic + length) to the block data
        try handle.seek(toOffset: UInt64(offset) + 8)
        guard let blockData = try handle.read(upToCount: Int(size)),
              blockData.count == Int(size) else {
            return nil
        }

        var blockReader = BufferReader([UInt8](blockData))
        return try Block.read(from: &blockReader)
    }

    /// Truncate to keep only blocks through the given height.
    ///
    /// Removes index entries beyond `height`. Data files are NOT truncated —
    /// old block data remains on disk but is unreachable via the index.
    public func truncateToHeight(_ height: Int) throws {
        let keepCount = height + 1
        guard keepCount < storedCount else { return }

        let previousFileNo = currentFileNo

        // Truncate index file
        let newIndexSize = UInt64(Self.fileHeaderSize + keepCount * Self.indexEntrySize)
        try indexHandle.truncate(atOffset: newIndexSize)

        // Update stored count
        storedCount = keepCount
        try updateIndexEntryCount()
        try indexHandle.synchronize()

        // Update current file number and offset from last entry
        if keepCount > 0 {
            let lastOffset = UInt64(Self.fileHeaderSize + (keepCount - 1) * Self.indexEntrySize)
            try indexHandle.seek(toOffset: lastOffset)
            guard let entryData = try indexHandle.read(upToCount: Self.indexEntrySize),
                  entryData.count == Self.indexEntrySize else { return }
            var reader = BufferReader([UInt8](entryData))
            let fileNo = try reader.readUInt32LE()
            let offset = try reader.readUInt32LE()
            let size = try reader.readUInt32LE()
            currentFileNo = fileNo
            currentOffset = UInt64(offset) + 8 + UInt64(size)
        } else {
            currentFileNo = 0
            currentOffset = 0
        }

        // Reopen data handle if the active file changed
        if currentFileNo != previousFileNo {
            try currentDataHandle.close()
            let dataPath = Self.dataFilePath(dir: blocksDir, fileNo: currentFileNo)
            if !FileManager.default.fileExists(atPath: dataPath) {
                FileManager.default.createFile(atPath: dataPath, contents: nil)
            }
            currentDataHandle = try FileHandle(forUpdating: URL(fileURLWithPath: dataPath))
            // Remove stale read handle for the new current file if cached
            if let cached = readHandles.removeValue(forKey: currentFileNo) {
                try cached.close()
            }
        }
    }

    /// Flush all file handles to disk.
    public func flush() throws {
        try currentDataHandle.synchronize()
        try indexHandle.synchronize()
    }

    /// Close all file handles.
    public func close() throws {
        try currentDataHandle.close()
        try indexHandle.close()
        for (_, handle) in readHandles {
            try handle.close()
        }
        readHandles.removeAll()
    }

    // MARK: - Private

    /// Get a file handle for reading data from a given file number.
    private func dataHandle(for fileNo: UInt32) throws -> FileHandle {
        if fileNo == currentFileNo {
            return currentDataHandle
        }
        if let cached = readHandles[fileNo] {
            return cached
        }
        let path = Self.dataFilePath(dir: blocksDir, fileNo: fileNo)
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        readHandles[fileNo] = handle
        return handle
    }

    /// Generate the path for a data file: `blk{NNNNN}.dat`
    static func dataFilePath(dir: String, fileNo: UInt32) -> String {
        let name = String(format: "blk%05d.dat", fileNo)
        return dir + "/" + name
    }

    /// Update the entry count field in the index file header.
    private func updateIndexEntryCount() throws {
        var writer = BufferWriter(capacity: 4)
        writer.writeUInt32LE(UInt32(storedCount))
        try indexHandle.seek(toOffset: 8) // offset of entry count in header
        indexHandle.write(Data(writer.data))
    }
}
