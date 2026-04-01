import XCTest
@testable import Urkel
import ExtCrypto

// MARK: - Bits Tests

final class BitsTests: XCTestCase {

    func testEmptyBits() {
        let bits = Bits()
        XCTAssertEqual(bits.size, 0)
        XCTAssertTrue(bits.isEmpty)
    }

    func testGetBit() {
        // 0xA5 = 10100101
        let bits = Bits(data: [0xA5], size: 8)
        XCTAssertEqual(bits.get(0), 1)
        XCTAssertEqual(bits.get(1), 0)
        XCTAssertEqual(bits.get(2), 1)
        XCTAssertEqual(bits.get(3), 0)
        XCTAssertEqual(bits.get(4), 0)
        XCTAssertEqual(bits.get(5), 1)
        XCTAssertEqual(bits.get(6), 0)
        XCTAssertEqual(bits.get(7), 1)
    }

    func testGetBitFromKey() {
        let key: [UInt8] = [0x80] // 10000000
        XCTAssertEqual(Bits.getBit(key, 0), 1)
        XCTAssertEqual(Bits.getBit(key, 1), 0)
        XCTAssertEqual(Bits.getBit(key, 7), 0)
    }

    func testHasMatchesKey() {
        // Prefix = 101 (3 bits) = 0xA0
        let bits = Bits(data: [0xA0], size: 3)
        // Key starts with 101... = 0xA0
        let key: [UInt8] = [0xA0] + [UInt8](repeating: 0, count: 31)
        XCTAssertTrue(bits.has(key, 0))
    }

    func testHasDoesNotMatchKey() {
        // Prefix = 101 (3 bits) = 0xA0
        let bits = Bits(data: [0xA0], size: 3)
        // Key starts with 110... = 0xC0
        let key: [UInt8] = [0xC0] + [UInt8](repeating: 0, count: 31)
        XCTAssertFalse(bits.has(key, 0))
    }

    func testCountMatchingBits() {
        // Prefix = 1010 (4 bits) = 0xA0
        let bits = Bits(data: [0xA0], size: 4)
        // Key = 10110000 = 0xB0
        // bit 0: 1==1 ✓, bit 1: 0==0 ✓, bit 2: 1==1 ✓, bit 3: 0!=1 ✗
        let key: [UInt8] = [0xB0] + [UInt8](repeating: 0, count: 31)
        XCTAssertEqual(bits.count(key, 0), 3)
    }

    func testSlice() {
        // 10101100 = 0xAC
        let bits = Bits(data: [0xAC], size: 8)
        // Slice bits 2-5: 1011
        let sliced = bits.slice(2, 6)
        XCTAssertEqual(sliced.size, 4)
        XCTAssertEqual(sliced.get(0), 1)
        XCTAssertEqual(sliced.get(1), 0)
        XCTAssertEqual(sliced.get(2), 1)
        XCTAssertEqual(sliced.get(3), 1)
    }

    func testSplit() {
        // 10110 (5 bits) = 0xB0
        let bits = Bits(data: [0xB0], size: 5)
        // Split at index 2: front=[1,0], back=[1,0]  (bit at index 2 is excluded)
        let (front, back) = bits.split(2)
        XCTAssertEqual(front.size, 2)
        XCTAssertEqual(front.get(0), 1) // bit 0
        XCTAssertEqual(front.get(1), 0) // bit 1
        XCTAssertEqual(back.size, 2)
        XCTAssertEqual(back.get(0), 1) // bit 3
        XCTAssertEqual(back.get(1), 0) // bit 4
    }

    func testJoin() {
        let a = Bits(data: [0x80], size: 1) // 1
        let b = Bits(data: [0x80], size: 1) // 1
        let result = a.join(b, 0) // 1 + 0 + 1 = 101
        XCTAssertEqual(result.size, 3)
        XCTAssertEqual(result.get(0), 1)
        XCTAssertEqual(result.get(1), 0)
        XCTAssertEqual(result.get(2), 1)
    }

    func testCollide() {
        // key1 starts: 11010...
        let key1: [UInt8] = [0xD0] + [UInt8](repeating: 0, count: 31)
        // key2 starts: 11001...
        let key2: [UInt8] = [0xC8] + [UInt8](repeating: 0, count: 31)
        let prefix = Bits.collide(key1, key2, depth: 0, maxBits: 256)
        // key1 = 0xD0 = 11010000
        // key2 = 0xC8 = 11001000
        // bit 0: 1==1 ✓, bit 1: 1==1 ✓, bit 2: 0==0 ✓, bit 3: 1!=0 ✗
        XCTAssertEqual(prefix.size, 3) // 110 matches
    }

    func testSerializeDeserializeSmall() {
        let bits = Bits(data: [0xA5], size: 8)
        let serialized = bits.serialize()
        guard let (deserialized, consumed) = Bits.deserialize(from: serialized, at: 0) else {
            XCTFail("Failed to deserialize")
            return
        }
        XCTAssertEqual(consumed, serialized.count)
        XCTAssertEqual(deserialized.size, 8)
        XCTAssertEqual(deserialized.data.prefix(1), bits.data.prefix(1))
    }

    func testSerializeDeserializeLarge() {
        // 200 bits (requires 2-byte size encoding)
        let data = [UInt8](repeating: 0xAA, count: 25)
        let bits = Bits(data: data, size: 200)
        let serialized = bits.serialize()
        // Size should be 2 bytes since 200 >= 0x80
        XCTAssertTrue(serialized[0] & 0x80 != 0)
        guard let (deserialized, _) = Bits.deserialize(from: serialized, at: 0) else {
            XCTFail("Failed to deserialize")
            return
        }
        XCTAssertEqual(deserialized.size, 200)
    }
}

// MARK: - UrkelNode Tests

final class UrkelNodeTests: XCTestCase {

    func testNullNodeHash() throws {
        let node = UrkelNode.null
        let hash = try node.hash()
        XCTAssertEqual(hash, urkelZeroHash)
    }

    func testLeafHash() throws {
        let key = [UInt8](repeating: 0x01, count: 32)
        let value = [UInt8](repeating: 0x02, count: 10)
        let leaf = UrkelLeaf(key: key, value: value)
        let hash = try leaf.hash()
        XCTAssertEqual(hash.count, 32)
        // Hash should not be zero
        XCTAssertNotEqual(hash, urkelZeroHash)
    }

    func testLeafHashDeterministic() throws {
        let key = [UInt8](repeating: 0xAA, count: 32)
        let value = Array("hello".utf8)
        let hash1 = try UrkelLeaf(key: key, value: value).hash()
        let hash2 = try UrkelLeaf(key: key, value: value).hash()
        XCTAssertEqual(hash1, hash2)
    }

    func testLeafHashDifferentValues() throws {
        let key = [UInt8](repeating: 0xAA, count: 32)
        let hash1 = try UrkelLeaf(key: key, value: [0x01]).hash()
        let hash2 = try UrkelLeaf(key: key, value: [0x02]).hash()
        XCTAssertNotEqual(hash1, hash2)
    }

    func testInternalNodeHashNoPrefix() throws {
        let leftHash = [UInt8](repeating: 0x01, count: 32)
        let rightHash = [UInt8](repeating: 0x02, count: 32)
        let hash = try UrkelInternal.computeHash(
            prefix: Bits(), left: leftHash, right: rightHash
        )
        XCTAssertEqual(hash.count, 32)
        // Should be BLAKE2b-256(0x01 || leftHash || rightHash)
        var expected = [UInt8]()
        expected.append(0x01)
        expected.append(contentsOf: leftHash)
        expected.append(contentsOf: rightHash)
        let expectedHash = try Blake2bHash.hash(expected, size: 32)
        XCTAssertEqual(hash, expectedHash)
    }

    func testInternalNodeHashWithPrefix() throws {
        let prefix = Bits(data: [0x80], size: 1) // single bit: 1
        let leftHash = [UInt8](repeating: 0x01, count: 32)
        let rightHash = [UInt8](repeating: 0x02, count: 32)
        let hash = try UrkelInternal.computeHash(
            prefix: prefix, left: leftHash, right: rightHash
        )
        XCTAssertEqual(hash.count, 32)
        // Should be BLAKE2b-256(0x02 || LE16(1) || 0x80 || leftHash || rightHash)
        var expected = [UInt8]()
        expected.append(0x02)
        expected.append(0x01) // LE16 low byte
        expected.append(0x00) // LE16 high byte
        expected.append(0x80) // 1 byte of prefix data
        expected.append(contentsOf: leftHash)
        expected.append(contentsOf: rightHash)
        let expectedHash = try Blake2bHash.hash(expected, size: 32)
        XCTAssertEqual(hash, expectedHash)
    }
}

// MARK: - UrkelTree Tests

final class UrkelTreeTests: XCTestCase {

    private func makeKey(_ byte: UInt8) -> [UInt8] {
        [UInt8](repeating: byte, count: 32)
    }

    func testEmptyTree() throws {
        let tree = UrkelTree()
        let root = try tree.rootHash()
        XCTAssertEqual(root, urkelZeroHash)
    }

    func testInsertAndGet() throws {
        var tree = UrkelTree()
        let key = makeKey(0x01)
        let value: [UInt8] = [1, 2, 3, 4]
        try tree.insert(key, value)
        let retrieved = try tree.get(key)
        XCTAssertEqual(retrieved, value)
    }

    func testGetMissing() throws {
        let tree = UrkelTree()
        let key = makeKey(0x01)
        let result = try tree.get(key)
        XCTAssertNil(result)
    }

    func testInsertUpdatesValue() throws {
        var tree = UrkelTree()
        let key = makeKey(0x01)
        try tree.insert(key, [1, 2, 3])
        try tree.insert(key, [4, 5, 6])
        let retrieved = try tree.get(key)
        XCTAssertEqual(retrieved, [4, 5, 6])
    }

    func testInsertMultipleKeys() throws {
        var tree = UrkelTree()
        let key1 = makeKey(0x01)
        let key2 = makeKey(0x02)
        let key3 = makeKey(0xFF)

        try tree.insert(key1, [1])
        try tree.insert(key2, [2])
        try tree.insert(key3, [3])

        XCTAssertEqual(try tree.get(key1), [1])
        XCTAssertEqual(try tree.get(key2), [2])
        XCTAssertEqual(try tree.get(key3), [3])
    }

    func testRootHashChanges() throws {
        var tree = UrkelTree()
        let root0 = try tree.rootHash()

        try tree.insert(makeKey(0x01), [1])
        let root1 = try tree.rootHash()
        XCTAssertNotEqual(root0, root1)

        try tree.insert(makeKey(0x02), [2])
        let root2 = try tree.rootHash()
        XCTAssertNotEqual(root1, root2)
    }

    func testRootHashDeterministic() throws {
        var tree1 = UrkelTree()
        var tree2 = UrkelTree()

        try tree1.insert(makeKey(0x01), [1])
        try tree1.insert(makeKey(0x02), [2])

        try tree2.insert(makeKey(0x01), [1])
        try tree2.insert(makeKey(0x02), [2])

        XCTAssertEqual(try tree1.rootHash(), try tree2.rootHash())
    }

    func testRemove() throws {
        var tree = UrkelTree()
        let key = makeKey(0x01)
        try tree.insert(key, [1, 2, 3])
        XCTAssertNotNil(try tree.get(key))

        let removed = try tree.remove(key)
        XCTAssertTrue(removed)
        XCTAssertNil(try tree.get(key))
    }

    func testRemoveNonexistent() throws {
        var tree = UrkelTree()
        let removed = try tree.remove(makeKey(0x01))
        XCTAssertFalse(removed)
    }

    func testRemoveRestoresRoot() throws {
        var tree = UrkelTree()
        let emptyRoot = try tree.rootHash()

        let key = makeKey(0x01)
        try tree.insert(key, [1])
        try tree.remove(key)

        let afterRemove = try tree.rootHash()
        XCTAssertEqual(emptyRoot, afterRemove)
    }

    func testRemoveOneOfMany() throws {
        var tree = UrkelTree()
        let key1 = makeKey(0x01)
        let key2 = makeKey(0x02)

        try tree.insert(key1, [1])
        try tree.insert(key2, [2])

        try tree.remove(key1)
        XCTAssertNil(try tree.get(key1))
        XCTAssertEqual(try tree.get(key2), [2])
    }

    func testInvalidKeySize() throws {
        var tree = UrkelTree()
        XCTAssertThrowsError(try tree.insert([0x01], [1])) { error in
            guard case UrkelError.invalidKeySize(1) = error else {
                XCTFail("Wrong error: \(error)")
                return
            }
        }
    }

    func testValueTooLarge() throws {
        var tree = UrkelTree()
        let key = makeKey(0x01)
        let bigValue = [UInt8](repeating: 0xFF, count: urkelMaxValueSize + 1)
        XCTAssertThrowsError(try tree.insert(key, bigValue)) { error in
            guard case UrkelError.valueTooLarge = error else {
                XCTFail("Wrong error: \(error)")
                return
            }
        }
    }

    // MARK: - Proof Tests

    func testProveExistence() throws {
        var tree = UrkelTree()
        let key = makeKey(0x01)
        let value: [UInt8] = [1, 2, 3, 4]
        try tree.insert(key, value)

        let root = try tree.rootHash()
        let proof = try tree.prove(key)

        XCTAssertEqual(proof.type, .exists)
        XCTAssertEqual(proof.value, value)

        let verified = try proof.verify(root: root, key: key)
        XCTAssertEqual(verified, value)
    }

    func testProveNonExistenceDeadend() throws {
        let tree = UrkelTree()
        let key = makeKey(0x01)

        let root = try tree.rootHash()
        let proof = try tree.prove(key)

        XCTAssertEqual(proof.type, .deadend)

        let verified = try proof.verify(root: root, key: key)
        XCTAssertNil(verified)
    }

    func testProveNonExistenceCollision() throws {
        var tree = UrkelTree()
        let key1 = makeKey(0x01)
        try tree.insert(key1, [1, 2, 3])

        // key2 is different from key1, so if it ends up at a leaf with key1
        // we get a collision proof
        let key2 = makeKey(0x02)
        let root = try tree.rootHash()
        let proof = try tree.prove(key2)

        // The proof should be a non-existence proof (collision or deadend or short)
        XCTAssertNotEqual(proof.type, .exists)

        let verified = try proof.verify(root: root, key: key2)
        XCTAssertNil(verified)
    }

    func testProveMultipleKeys() throws {
        var tree = UrkelTree()
        let keys = (0..<10).map { makeKey(UInt8($0)) }
        let values = (0..<10).map { [UInt8($0)] }

        for i in 0..<10 {
            try tree.insert(keys[i], values[i])
        }

        let root = try tree.rootHash()

        // Verify each key has a valid existence proof
        for i in 0..<10 {
            let proof = try tree.prove(keys[i])
            XCTAssertEqual(proof.type, .exists)
            let verified = try proof.verify(root: root, key: keys[i])
            XCTAssertEqual(verified, values[i])
        }

        // Verify a non-existent key
        let missingKey = makeKey(0xFF)
        let missingProof = try tree.prove(missingKey)
        XCTAssertNotEqual(missingProof.type, .exists)
        let missingResult = try missingProof.verify(root: root, key: missingKey)
        XCTAssertNil(missingResult)
    }

    func testProofVerificationFailsWithWrongRoot() throws {
        var tree = UrkelTree()
        let key = makeKey(0x01)
        try tree.insert(key, [1, 2, 3])

        let proof = try tree.prove(key)
        let fakeRoot = [UInt8](repeating: 0xFF, count: 32)

        XCTAssertThrowsError(try proof.verify(root: fakeRoot, key: key)) { error in
            guard case UrkelError.proofHashMismatch = error else {
                XCTFail("Expected proofHashMismatch, got \(error)")
                return
            }
        }
    }

    func testProofVerificationFailsWithWrongKey() throws {
        var tree = UrkelTree()
        let key = makeKey(0x01)
        try tree.insert(key, [1, 2, 3])

        let root = try tree.rootHash()
        let proof = try tree.prove(key)
        let wrongKey = makeKey(0x02)

        // Verifying with a wrong key should fail (hash mismatch or other error)
        XCTAssertThrowsError(try proof.verify(root: root, key: wrongKey))
    }

    // MARK: - Proof Serialization Tests

    func testProofSerializeDeserialize() throws {
        var tree = UrkelTree()
        for i in 0..<5 {
            try tree.insert(makeKey(UInt8(i)), [UInt8(i)])
        }

        let key = makeKey(0x02)
        let proof = try tree.prove(key)
        let serialized = proof.serialize()
        let deserialized = try UrkelProof.deserialize(from: serialized)

        XCTAssertEqual(deserialized.type, proof.type)
        XCTAssertEqual(deserialized.depth, proof.depth)
        XCTAssertEqual(deserialized.nodes.count, proof.nodes.count)
        XCTAssertEqual(deserialized.value, proof.value)

        // Deserialized proof should verify correctly
        let root = try tree.rootHash()
        let verified = try deserialized.verify(root: root, key: key)
        XCTAssertEqual(verified, [0x02])
    }

    func testDeadendProofSerializeDeserialize() throws {
        let tree = UrkelTree()
        let key = makeKey(0x01)
        let proof = try tree.prove(key)

        let serialized = proof.serialize()
        let deserialized = try UrkelProof.deserialize(from: serialized)

        XCTAssertEqual(deserialized.type, .deadend)
        XCTAssertEqual(deserialized.depth, 0)
        XCTAssertEqual(deserialized.nodes.count, 0)
    }

    // MARK: - Stress

    func testManyInsertions() throws {
        var tree = UrkelTree()
        // Insert 100 keys derived from SHA3 to get good distribution
        for i in 0..<100 {
            var keyData = [UInt8](repeating: 0, count: 32)
            keyData[0] = UInt8(i & 0xFF)
            keyData[1] = UInt8((i >> 8) & 0xFF)
            // Use the raw bytes as key (they'll have good first-byte distribution for i<256)
            let key = SHA3Hash.sha3_256(keyData).bytes
            try tree.insert(key, [UInt8(i & 0xFF)])
        }

        // Verify all 100 exist
        for i in 0..<100 {
            var keyData = [UInt8](repeating: 0, count: 32)
            keyData[0] = UInt8(i & 0xFF)
            keyData[1] = UInt8((i >> 8) & 0xFF)
            let key = SHA3Hash.sha3_256(keyData).bytes
            let val = try tree.get(key)
            XCTAssertEqual(val, [UInt8(i & 0xFF)])
        }
    }

    // MARK: - Cross-implementation verification against hsd's urkel

    func testDeserializeRejectsNodeCountAbove256() {
        // Build raw bytes for an UrkelProof with node count = 257,
        // which exceeds the maximum trie depth of 256.
        var bytes = [UInt8]()

        // Field bytes: type=deadend(0) << 14 | depth=0 => 0x0000 LE
        bytes.append(0x00)
        bytes.append(0x00)

        // Count = 257 as little-endian UInt16
        bytes.append(0x01)
        bytes.append(0x01)

        // Bitmap: (257 + 7) / 8 = 33 bytes of zeros
        bytes.append(contentsOf: [UInt8](repeating: 0, count: 33))

        XCTAssertThrowsError(try UrkelProof.deserialize(from: bytes)) { error in
            guard case UrkelError.malformedProof(let msg) = error else {
                XCTFail("Expected UrkelError.malformedProof, got \(error)")
                return
            }
            XCTAssertTrue(msg.contains("exceeds max trie depth"),
                          "Error message should mention max trie depth: \(msg)")
        }
    }

    func testSingleInsertMatchesHSD() throws {
        // nameHash for "7am" = SHA3-256("7am")
        // hsd produces: 248b5048808926239a8b3e9e817df3c5c307ba05725ba2fa00ca0e07c747afe4
        let nameHash: [UInt8] = [
            0x24, 0x8b, 0x50, 0x48, 0x80, 0x89, 0x26, 0x23,
            0x9a, 0x8b, 0x3e, 0x9e, 0x81, 0x7d, 0xf3, 0xc5,
            0xc3, 0x07, 0xba, 0x05, 0x72, 0x5b, 0xa2, 0xfa,
            0x00, 0xca, 0x0e, 0x07, 0xc7, 0x47, 0xaf, 0xe4
        ]

        // Serialized NameState: OPEN at height 2777
        // nameLen=3, name='7am', dataLen=0, height=2777, renewal=2777, field=0
        let value: [UInt8] = [
            0x03, 0x37, 0x61, 0x6d,
            0x00, 0x00,
            0xd9, 0x0a, 0x00, 0x00,
            0xd9, 0x0a, 0x00, 0x00,
            0x00, 0x00
        ]

        var tree = UrkelTree()
        try tree.insert(nameHash, value)
        let root = try tree.rootHash()
        let rootHex = root.map { String(format: "%02x", $0) }.joined()

        // Expected from hsd's urkel: 1c1c25d9984d91f163bf0e432dadde610f40dff69dca6428abfa6fa6e8547b6d
        XCTAssertEqual(rootHex, "1c1c25d9984d91f163bf0e432dadde610f40dff69dca6428abfa6fa6e8547b6d",
                        "Single insert root must match hsd urkel")
    }
}
