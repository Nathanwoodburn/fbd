import XCTest
@testable import Storage

final class LevelDBStoreTests: XCTestCase {

    private var tmpDir: String!

    override func setUp() {
        super.setUp()
        tmpDir = NSTemporaryDirectory() + "fbd-storage-test-\(UUID().uuidString)"
    }

    override func tearDown() {
        if let dir = tmpDir {
            try? FileManager.default.removeItem(atPath: dir)
        }
        super.tearDown()
    }

    // MARK: - Basic CRUD

    func testPutAndGet() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "test")

        try store.put(db: db, key: [1, 2, 3], value: [4, 5, 6])
        let result = try store.get(db: db, key: [1, 2, 3])
        XCTAssertEqual(result, [4, 5, 6])
    }

    func testGetNonexistentKeyReturnsNil() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "test")

        let result = try store.get(db: db, key: [99, 99])
        XCTAssertNil(result)
    }

    func testDelete() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "test")

        try store.put(db: db, key: [1], value: [2])
        try store.delete(db: db, key: [1])
        let result = try store.get(db: db, key: [1])
        XCTAssertNil(result)
    }

    func testOverwriteKey() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "test")

        try store.put(db: db, key: [1], value: [10])
        try store.put(db: db, key: [1], value: [20])
        let result = try store.get(db: db, key: [1])
        XCTAssertEqual(result, [20])
    }

    // MARK: - Named Databases

    func testNamedDatabasesDontCollide() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db1 = store.openDatabase(name: "alpha")
        let db2 = store.openDatabase(name: "beta")

        try store.put(db: db1, key: [1], value: [10])
        try store.put(db: db2, key: [1], value: [20])

        let val1 = try store.get(db: db1, key: [1])
        let val2 = try store.get(db: db2, key: [1])
        XCTAssertEqual(val1, [10])
        XCTAssertEqual(val2, [20])
    }

    func testOpenDatabaseIncrementsPrefix() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db1 = store.openDatabase(name: "first")
        let db2 = store.openDatabase(name: "second")
        XCTAssertNotEqual(db1, db2)
    }

    func testOpenDatabaseWithNilName() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: nil)

        try store.put(db: db, key: [1], value: [10])
        let result = try store.get(db: db, key: [1])
        XCTAssertEqual(result, [10])
    }

    // MARK: - Batch Writes

    func testBatchWriteAtomicPutAndDelete() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "batch")

        try store.put(db: db, key: [1], value: [10])

        try store.writeBatch([
            (db: db, op: .put(key: [2], value: [20])),
            (db: db, op: .delete(key: [1])),
        ])

        XCTAssertNil(try store.get(db: db, key: [1]))
        XCTAssertEqual(try store.get(db: db, key: [2]), [20])
    }

    func testEmptyBatchIsNoOp() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "test")

        try store.put(db: db, key: [1], value: [10])
        try store.writeBatch([])
        XCTAssertEqual(try store.get(db: db, key: [1]), [10])
    }

    func testBatchAcrossTwoDatabases() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db1 = store.openDatabase(name: "one")
        let db2 = store.openDatabase(name: "two")

        try store.writeBatch([
            (db: db1, op: .put(key: [1], value: [11])),
            (db: db2, op: .put(key: [1], value: [22])),
        ])

        XCTAssertEqual(try store.get(db: db1, key: [1]), [11])
        XCTAssertEqual(try store.get(db: db2, key: [1]), [22])
    }

    // MARK: - Iteration

    func testForEachEntrySeesAllEntriesInOrder() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "iter")

        try store.put(db: db, key: [3], value: [30])
        try store.put(db: db, key: [1], value: [10])
        try store.put(db: db, key: [2], value: [20])

        var keys = [[UInt8]]()
        try store.forEachEntry(db: db) { key, _ in
            keys.append(key)
        }

        XCTAssertEqual(keys, [[1], [2], [3]])
    }

    func testForEachEntryStopsAtPrefixBoundary() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db1 = store.openDatabase(name: "a")
        let db2 = store.openDatabase(name: "b")

        try store.put(db: db1, key: [1], value: [10])
        try store.put(db: db2, key: [2], value: [20])

        var count = 0
        try store.forEachEntry(db: db1) { _, _ in
            count += 1
        }
        XCTAssertEqual(count, 1)
    }

    func testForEachEntryEmptyDB() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "empty")

        var count = 0
        try store.forEachEntry(db: db) { _, _ in
            count += 1
        }
        XCTAssertEqual(count, 0)
    }

    // MARK: - Key Prefix Iteration

    func testForEachEntryKeyPrefixFilters() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "prefix")

        try store.put(db: db, key: [0xAA, 1], value: [10])
        try store.put(db: db, key: [0xAA, 2], value: [20])
        try store.put(db: db, key: [0xBB, 1], value: [30])

        var values = [[UInt8]]()
        try store.forEachEntry(db: db, keyPrefix: [0xAA]) { _, value in
            values.append(value)
            return true
        }

        XCTAssertEqual(values.count, 2)
    }

    func testForEachEntryKeyPrefixEarlyExit() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "prefix2")

        try store.put(db: db, key: [0xAA, 1], value: [10])
        try store.put(db: db, key: [0xAA, 2], value: [20])
        try store.put(db: db, key: [0xAA, 3], value: [30])

        var count = 0
        try store.forEachEntry(db: db, keyPrefix: [0xAA]) { _, _ in
            count += 1
            return count < 2 // stop after 2
        }

        XCTAssertEqual(count, 2)
    }

    func testForEachEntryKeyPrefixNoMatches() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "prefix3")

        try store.put(db: db, key: [0xAA, 1], value: [10])

        var count = 0
        try store.forEachEntry(db: db, keyPrefix: [0xFF]) { _, _ in
            count += 1
            return true
        }

        XCTAssertEqual(count, 0)
    }

    // MARK: - Reverse Iteration

    func testReverseForEachEntry() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "rev")

        try store.put(db: db, key: [1], value: [10])
        try store.put(db: db, key: [2], value: [20])
        try store.put(db: db, key: [3], value: [30])

        var keys = [[UInt8]]()
        try store.reverseForEachEntry(db: db) { key, _ in
            keys.append(key)
            return true
        }

        XCTAssertEqual(keys, [[3], [2], [1]])
    }

    func testReverseForEachEntryEarlyExit() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "rev2")

        try store.put(db: db, key: [1], value: [10])
        try store.put(db: db, key: [2], value: [20])
        try store.put(db: db, key: [3], value: [30])

        var count = 0
        try store.reverseForEachEntry(db: db) { _, _ in
            count += 1
            return count < 2
        }

        XCTAssertEqual(count, 2)
    }

    func testReverseForEachEntryEmptyDB() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "rev3")

        var count = 0
        try store.reverseForEachEntry(db: db) { _, _ in
            count += 1
            return true
        }
        XCTAssertEqual(count, 0)
    }

    // MARK: - Clear Database

    func testClearDatabase() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db1 = store.openDatabase(name: "clear")
        let db2 = store.openDatabase(name: "keep")

        try store.put(db: db1, key: [1], value: [10])
        try store.put(db: db1, key: [2], value: [20])
        try store.put(db: db2, key: [1], value: [30])

        try store.clearDatabase(db: db1)

        XCTAssertNil(try store.get(db: db1, key: [1]))
        XCTAssertNil(try store.get(db: db1, key: [2]))
        XCTAssertEqual(try store.get(db: db2, key: [1]), [30], "Other database should be unaffected")
    }

    // MARK: - Snapshots

    func testSnapshotDoesNotSeePostSnapshotWrites() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "snap")

        try store.put(db: db, key: [1], value: [10])

        let snapshot = store.beginReadTransaction()

        // Write after snapshot
        try store.put(db: db, key: [2], value: [20])

        // Snapshot should not see key [2]
        let val1 = try store.get(snapshot: snapshot, db: db, key: [1])
        let val2 = try store.get(snapshot: snapshot, db: db, key: [2])
        XCTAssertEqual(val1, [10])
        XCTAssertNil(val2)

        store.endReadTransaction(snapshot)
    }

    func testSnapshotSeesPreSnapshotWrites() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "snap2")

        try store.put(db: db, key: [1], value: [10])
        try store.put(db: db, key: [2], value: [20])

        let snapshot = store.beginReadTransaction()

        let val1 = try store.get(snapshot: snapshot, db: db, key: [1])
        let val2 = try store.get(snapshot: snapshot, db: db, key: [2])
        XCTAssertEqual(val1, [10])
        XCTAssertEqual(val2, [20])

        store.endReadTransaction(snapshot)
    }

    // MARK: - Close

    func testCloseIsIdempotent() throws {
        let store = try LevelDBStore(path: tmpDir)
        store.close()
        store.close() // Should not crash
    }

    // MARK: - Large Values

    func testLargeValue() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "large")

        let largeValue = [UInt8](repeating: 0xAB, count: 1_000_000)
        try store.put(db: db, key: [1], value: largeValue)

        let result = try store.get(db: db, key: [1])
        XCTAssertEqual(result, largeValue)
    }

    // MARK: - Multiple Keys

    func testManyKeys() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "many")

        for i: UInt16 in 0..<100 {
            let key = [UInt8(i >> 8), UInt8(i & 0xFF)]
            try store.put(db: db, key: key, value: [UInt8(i & 0xFF)])
        }

        var count = 0
        try store.forEachEntry(db: db) { _, _ in
            count += 1
        }
        XCTAssertEqual(count, 100)
    }

    func testDeleteNonexistentKeyIsNoOp() throws {
        let store = try LevelDBStore(path: tmpDir)
        let db = store.openDatabase(name: "dne")

        // Should not throw
        try store.delete(db: db, key: [99])
    }
}
