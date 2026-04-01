import CLevelDB
import Foundation

/// Errors from LevelDB operations.
public enum LevelDBError: Error, Equatable, Sendable {
    /// LevelDB returned an error string.
    case levelDBError(String)
    /// Key was not found.
    case notFound
}

/// Thin Swift wrapper around the LevelDB C API.
///
/// Manages a single LevelDB database with support for "named databases"
/// via key prefixes (each logical database gets a 1-byte prefix).
/// Shared by Chain, Tree, and Wallet modules.
public final class LevelDBStore {
    private var db: OpaquePointer?
    private var readOptions: OpaquePointer?
    private var writeOptions: OpaquePointer?
    private var isOpen = false

    /// Counter for assigning prefix bytes to named databases.
    private var nextPrefix: UInt8 = 0

    /// Open a LevelDB database at the given path.
    ///
    /// - Parameters:
    ///   - path: Directory path for the LevelDB data files.
    ///   - cacheSize: LRU block cache size in bytes (default 64MB).
    public init(path: String, cacheSize: Int = 64 * 1024 * 1024) throws {
        // Create directory if needed
        let fm = FileManager.default
        if !fm.fileExists(atPath: path) {
            try fm.createDirectory(atPath: path, withIntermediateDirectories: true)
        }

        let options = leveldb_options_create()!
        defer { leveldb_options_destroy(options) }

        leveldb_options_set_create_if_missing(options, 1)

        // Snappy compression — fast and reduces disk usage significantly
        leveldb_options_set_compression(options, Int32(leveldb_snappy_compression))

        // Bloom filter: 10 bits per key (matches Bitcoin Core)
        let filterPolicy = leveldb_filterpolicy_create_bloom(10)!
        leveldb_options_set_filter_policy(options, filterPolicy)

        // Block cache
        let cache = leveldb_cache_create_lru(cacheSize)!
        leveldb_options_set_cache(options, cache)

        // Write buffer: 16MB
        // 64MB write buffer — reduces L0 SSTable flush frequency during
        // write-heavy operations (tree commits), which reduces compaction
        // stalls on reads.
        leveldb_options_set_write_buffer_size(options, 64 * 1024 * 1024)

        // Max open files (matches Bitcoin Core default)
        leveldb_options_set_max_open_files(options, 256)

        // Block size: 4KB (LevelDB default)
        leveldb_options_set_block_size(options, 4096)

        var errptr: UnsafeMutablePointer<CChar>?
        let db = leveldb_open(options, path, &errptr)
        if let errptr = errptr {
            let msg = String(cString: errptr)
            leveldb_free(errptr)
            // Clean up resources that won't be managed by deinit
            leveldb_cache_destroy(cache)
            leveldb_filterpolicy_destroy(filterPolicy)
            throw LevelDBError.levelDBError(msg)
        }
        guard let db = db else {
            leveldb_cache_destroy(cache)
            leveldb_filterpolicy_destroy(filterPolicy)
            throw LevelDBError.levelDBError("leveldb_open returned nil")
        }

        self.db = db
        self.isOpen = true

        // Create default read/write options
        self.readOptions = leveldb_readoptions_create()
        self.writeOptions = leveldb_writeoptions_create()
        // No fsync on every write (async durability)
        leveldb_writeoptions_set_sync(self.writeOptions, 0)
    }

    /// Open (or assign) a named database within this environment.
    ///
    /// Returns a 1-byte prefix that is prepended to all keys for this "database".
    /// Each LevelDBStore instance is a separate LevelDB directory, so prefixes
    /// don't collide between different stores.
    public func openDatabase(name: String?) -> UInt8 {
        let prefix = nextPrefix
        nextPrefix += 1
        return prefix
    }

    /// Get a value by key from a database.
    ///
    /// Returns `nil` if the key is not found.
    public func get(db: UInt8, key: [UInt8]) throws -> [UInt8]? {
        let prefixedKey = prefixed(db, key)
        return try rawGet(readOptions: readOptions!, key: prefixedKey)
    }

    /// Put a key-value pair into a database.
    public func put(db: UInt8, key: [UInt8], value: [UInt8]) throws {
        let prefixedKey = prefixed(db, key)
        try prefixedKey.withUnsafeBufferPointer { keyBuf in
            try value.withUnsafeBufferPointer { valBuf in
                var errptr: UnsafeMutablePointer<CChar>?
                leveldb_put(
                    self.db, writeOptions,
                    keyBuf.baseAddress, keyBuf.count,
                    valBuf.baseAddress, valBuf.count,
                    &errptr
                )
                try checkError(errptr)
            }
        }
    }

    /// Delete a key from a database.
    public func delete(db: UInt8, key: [UInt8]) throws {
        let prefixedKey = prefixed(db, key)
        try prefixedKey.withUnsafeBufferPointer { keyBuf in
            var errptr: UnsafeMutablePointer<CChar>?
            leveldb_delete(
                self.db, writeOptions,
                keyBuf.baseAddress, keyBuf.count,
                &errptr
            )
            try checkError(errptr)
        }
    }

    /// Operation for batch writes.
    public enum BatchOp {
        case put(key: [UInt8], value: [UInt8])
        case delete(key: [UInt8])
    }

    /// Execute multiple operations in a single atomic write batch.
    public func writeBatch(_ operations: [(db: UInt8, op: BatchOp)]) throws {
        guard !operations.isEmpty else { return }

        let batch = leveldb_writebatch_create()!
        defer { leveldb_writebatch_destroy(batch) }

        for (dbPrefix, op) in operations {
            switch op {
            case .put(let key, let value):
                let prefixedKey = prefixed(dbPrefix, key)
                prefixedKey.withUnsafeBufferPointer { keyBuf in
                    value.withUnsafeBufferPointer { valBuf in
                        leveldb_writebatch_put(
                            batch,
                            keyBuf.baseAddress, keyBuf.count,
                            valBuf.baseAddress, valBuf.count
                        )
                    }
                }
            case .delete(let key):
                let prefixedKey = prefixed(dbPrefix, key)
                prefixedKey.withUnsafeBufferPointer { keyBuf in
                    leveldb_writebatch_delete(
                        batch,
                        keyBuf.baseAddress, keyBuf.count
                    )
                }
            }
        }

        var errptr: UnsafeMutablePointer<CChar>?
        leveldb_write(db, writeOptions, batch, &errptr)
        try checkError(errptr)
    }

    /// Iterate all key-value pairs in a named database via iterator.
    public func forEachEntry(db prefix: UInt8, _ body: ([UInt8], [UInt8]) throws -> Void) throws {
        let iter = leveldb_create_iterator(db, readOptions)!
        defer { leveldb_iter_destroy(iter) }

        // Seek to the first key with our prefix
        let seekKey: [UInt8] = [prefix]
        seekKey.withUnsafeBufferPointer { buf in
            leveldb_iter_seek(iter, buf.baseAddress, buf.count)
        }

        while leveldb_iter_valid(iter) != 0 {
            var keyLen = 0
            let keyPtr = leveldb_iter_key(iter, &keyLen)!

            // Stop when we leave our prefix range
            guard keyLen > 0 else { break }
            let firstByte = keyPtr.withMemoryRebound(to: UInt8.self, capacity: 1) { $0.pointee }
            guard firstByte == prefix else { break }

            var valLen = 0
            let valPtr = leveldb_iter_value(iter, &valLen)!

            // Strip the prefix byte from the returned key
            let key = Array(UnsafeBufferPointer(
                start: keyPtr.advanced(by: 1).withMemoryRebound(to: UInt8.self, capacity: keyLen - 1) { $0 },
                count: keyLen - 1
            ))
            let value = Array(UnsafeBufferPointer(
                start: valPtr.withMemoryRebound(to: UInt8.self, capacity: valLen) { $0 },
                count: valLen
            ))
            try body(key, value)

            leveldb_iter_next(iter)
        }
        var iterErr: UnsafeMutablePointer<CChar>?
        leveldb_iter_get_error(iter, &iterErr)
        try checkError(iterErr)
    }

    /// Iterate key-value pairs in a named database matching a key prefix.
    ///
    /// Seeks to `[dbPrefix] + keyPrefix` and iterates while the key starts
    /// with that combined prefix. The body receives keys with both the db
    /// prefix and keyPrefix stripped. Return `true` from body to continue,
    /// `false` to stop early.
    public func forEachEntry(db prefix: UInt8, keyPrefix: [UInt8], _ body: ([UInt8], [UInt8]) throws -> Bool) throws {
        let iter = leveldb_create_iterator(db, readOptions)!
        defer { leveldb_iter_destroy(iter) }

        let seekKey = prefixed(prefix, keyPrefix)
        seekKey.withUnsafeBufferPointer { buf in
            leveldb_iter_seek(iter, buf.baseAddress, buf.count)
        }

        let fullPrefixLen = seekKey.count  // 1 (db prefix) + keyPrefix.count

        while leveldb_iter_valid(iter) != 0 {
            var keyLen = 0
            let keyPtr = leveldb_iter_key(iter, &keyLen)!

            // Stop when key is shorter than our prefix or doesn't start with it
            guard keyLen >= fullPrefixLen else { break }
            let rawKey = UnsafeRawBufferPointer(start: keyPtr, count: keyLen)
            var matches = true
            for i in 0..<fullPrefixLen {
                if rawKey[i] != seekKey[i] { matches = false; break }
            }
            guard matches else { break }

            var valLen = 0
            let valPtr = leveldb_iter_value(iter, &valLen)!

            // Strip the db prefix byte and keyPrefix from the returned key
            let key = Array(UnsafeBufferPointer(
                start: keyPtr.advanced(by: fullPrefixLen).withMemoryRebound(to: UInt8.self, capacity: keyLen - fullPrefixLen) { $0 },
                count: keyLen - fullPrefixLen
            ))
            let value = Array(UnsafeBufferPointer(
                start: valPtr.withMemoryRebound(to: UInt8.self, capacity: valLen) { $0 },
                count: valLen
            ))
            let shouldContinue = try body(key, value)
            guard shouldContinue else { break }

            leveldb_iter_next(iter)
        }
        var iterErr: UnsafeMutablePointer<CChar>?
        leveldb_iter_get_error(iter, &iterErr)
        try checkError(iterErr)
    }

    /// Iterate all key-value pairs in a named database in reverse order.
    ///
    /// Body returns `true` to continue, `false` to stop early.
    public func reverseForEachEntry(db prefix: UInt8, _ body: ([UInt8], [UInt8]) throws -> Bool) throws {
        let iter = leveldb_create_iterator(db, readOptions)!
        defer { leveldb_iter_destroy(iter) }

        // Seek to the first key PAST our prefix range (prefix+1),
        // then step back one to land on the last key with our prefix.
        let nextPrefix = prefix &+ 1
        if nextPrefix > prefix {
            let seekKey: [UInt8] = [nextPrefix]
            seekKey.withUnsafeBufferPointer { buf in
                leveldb_iter_seek(iter, buf.baseAddress, buf.count)
            }
            // If valid, the iterator is at nextPrefix or beyond — back up one
            if leveldb_iter_valid(iter) != 0 {
                leveldb_iter_prev(iter)
            } else {
                // Past all data, seek to the very last entry
                leveldb_iter_seek_to_last(iter)
            }
        } else {
            // prefix == 0xFF: seek to end
            leveldb_iter_seek_to_last(iter)
        }

        while leveldb_iter_valid(iter) != 0 {
            var keyLen = 0
            let keyPtr = leveldb_iter_key(iter, &keyLen)!

            guard keyLen > 0 else { break }
            let firstByte = keyPtr.withMemoryRebound(to: UInt8.self, capacity: 1) { $0.pointee }
            guard firstByte == prefix else { break }

            var valLen = 0
            let valPtr = leveldb_iter_value(iter, &valLen)!

            let key = Array(UnsafeBufferPointer(
                start: keyPtr.advanced(by: 1).withMemoryRebound(to: UInt8.self, capacity: keyLen - 1) { $0 },
                count: keyLen - 1
            ))
            let value = Array(UnsafeBufferPointer(
                start: valPtr.withMemoryRebound(to: UInt8.self, capacity: valLen) { $0 },
                count: valLen
            ))
            let shouldContinue = try body(key, value)
            guard shouldContinue else { break }

            leveldb_iter_prev(iter)
        }
        var iterErr: UnsafeMutablePointer<CChar>?
        leveldb_iter_get_error(iter, &iterErr)
        try checkError(iterErr)
    }

    /// Delete all entries in a named database.
    ///
    /// Iterates all keys with the given prefix and batch-deletes them.
    public func clearDatabase(db prefix: UInt8) throws {
        let iter = leveldb_create_iterator(db, readOptions)!
        defer { leveldb_iter_destroy(iter) }

        let batch = leveldb_writebatch_create()!
        defer { leveldb_writebatch_destroy(batch) }

        let seekKey: [UInt8] = [prefix]
        seekKey.withUnsafeBufferPointer { buf in
            leveldb_iter_seek(iter, buf.baseAddress, buf.count)
        }

        var count = 0
        while leveldb_iter_valid(iter) != 0 {
            var keyLen = 0
            let keyPtr = leveldb_iter_key(iter, &keyLen)!

            guard keyLen > 0 else { break }
            let firstByte = keyPtr.withMemoryRebound(to: UInt8.self, capacity: 1) { $0.pointee }
            guard firstByte == prefix else { break }

            leveldb_writebatch_delete(batch, keyPtr, keyLen)
            count += 1

            leveldb_iter_next(iter)
        }

        if count > 0 {
            var errptr: UnsafeMutablePointer<CChar>?
            leveldb_write(db, writeOptions, batch, &errptr)
            try checkError(errptr)
        }
    }

    // MARK: - Snapshot-based reads

    /// Bundles a LevelDB snapshot with pre-built read options for reuse across many reads.
    public final class Snapshot {
        public let snapshot: OpaquePointer
        public let readOptions: OpaquePointer

        public init(snapshot: OpaquePointer) {
            self.snapshot = snapshot
            self.readOptions = leveldb_readoptions_create()!
            leveldb_readoptions_set_snapshot(self.readOptions, snapshot)
        }

        deinit {
            leveldb_readoptions_destroy(readOptions)
        }
    }

    /// Begin a snapshot for consistent reads across multiple gets.
    ///
    /// The returned `Snapshot` bundles pre-built read options so thousands
    /// of reads don't each allocate/destroy their own options.
    public func beginReadTransaction() -> Snapshot {
        Snapshot(snapshot: leveldb_create_snapshot(db)!)
    }

    /// Release a snapshot.
    public func endReadTransaction(_ snapshot: Snapshot) {
        leveldb_release_snapshot(db, snapshot.snapshot)
    }

    /// Get a value within a snapshot (consistent read).
    public func get(snapshot: Snapshot, db prefix: UInt8, key: [UInt8]) throws -> [UInt8]? {
        let prefixedKey = prefixed(prefix, key)
        return try rawGet(readOptions: snapshot.readOptions, key: prefixedKey)
    }

    /// Close the LevelDB database.
    public func close() {
        guard isOpen else { return }
        isOpen = false
        if let readOptions = readOptions {
            leveldb_readoptions_destroy(readOptions)
            self.readOptions = nil
        }
        if let writeOptions = writeOptions {
            leveldb_writeoptions_destroy(writeOptions)
            self.writeOptions = nil
        }
        if let db = db {
            leveldb_close(db)
            self.db = nil
        }
    }

    deinit {
        close()
    }

    // MARK: - Private Helpers

    /// Prepend a 1-byte prefix to a key.
    private func prefixed(_ prefix: UInt8, _ key: [UInt8]) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(1 + key.count)
        result.append(prefix)
        result.append(contentsOf: key)
        return result
    }

    /// Raw get using specific read options (for snapshot support).
    private func rawGet(readOptions: OpaquePointer, key: [UInt8]) throws -> [UInt8]? {
        try key.withUnsafeBufferPointer { keyBuf in
            var valLen = 0
            var errptr: UnsafeMutablePointer<CChar>?
            let valPtr = leveldb_get(
                db, readOptions,
                keyBuf.baseAddress, keyBuf.count,
                &valLen,
                &errptr
            )
            try checkError(errptr)

            guard let valPtr = valPtr else {
                return nil // key not found
            }
            defer { leveldb_free(valPtr) }

            return Array(UnsafeBufferPointer(
                start: valPtr.withMemoryRebound(to: UInt8.self, capacity: valLen) { $0 },
                count: valLen
            ))
        }
    }

    /// Check a LevelDB error pointer and throw if set.
    private func checkError(_ errptr: UnsafeMutablePointer<CChar>?) throws {
        if let errptr = errptr {
            let msg = String(cString: errptr)
            leveldb_free(errptr)
            throw LevelDBError.levelDBError(msg)
        }
    }
}
