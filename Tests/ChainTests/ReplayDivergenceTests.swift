import XCTest
@testable import Chain
import Base
import Protocol
import Covenants
@testable import Consensus
import ExtCrypto

/// Tests that replayCovenants produces identical tree roots as processCovenants.
final class ReplayDivergenceTests: XCTestCase {

    // MARK: - Real block divergence finder

    /// Load actual mainnet blocks and replay through replayCovenants twice:
    /// 1. Continuous replay from genesis to 3390
    /// 2. Replay from genesis to some midpoint, commit, clear pending (simulate restart),
    ///    then replay remaining blocks to 3390
    ///
    /// If these diverge, the bug is in how cross-commit-boundary state is handled.
    func testFindRealBlockDivergence() throws {
        let blocksDir = NSHomeDirectory() + "/.fbd/blocks"
        let mainParams = NameParams.params(for: .main)

        let blockStore: BlockStore
        do {
            blockStore = try BlockStore(blocksDir: blocksDir, network: .main)
        } catch {
            throw XCTSkip("No mainnet block data at \(blocksDir): \(error)")
        }

        let totalBlocks = blockStore.storedCount
        guard totalBlocks > 30 else { throw XCTSkip("Not enough blocks") }

        // Genesis setup shared by both paths
        func registerGenesisNames(_ db: NameDB, block: Block) {
            var genesisNames = ["fistbump"]
            for char in "abcdefghijklmnopqrstuvwxyz0123456789" {
                genesisNames.append(String(char))
            }
            var hashToName = [[UInt8]: [UInt8]]()
            for name in genesisNames {
                hashToName[NameRules.hashName(name).bytes] = Array(name.utf8)
            }
            let cb = block.transactions[0]
            let txH = cb.txHash()
            for (outputIdx, output) in cb.outputs.enumerated() {
                if output.covenant.type == .register {
                    let nameHashBytes = output.covenant.items[0]
                    let nameHash = NameHash(unchecked: nameHashBytes)
                    let resource = output.covenant.items.count > 2 ? output.covenant.items[2] : [UInt8]()
                    let nameBytes = hashToName[nameHashBytes] ?? nameHashBytes
                    var ns = NameState()
                    ns.name = nameBytes
                    ns.nameHash = nameHash
                    ns.height = 0; ns.renewal = 0; ns.registered = true
                    ns.owner = NameState.Outpoint(hash: txH.bytes, index: outputIdx)
                    ns.data = resource; ns.value = 0; ns.highest = 0
                    if let flags = CovenantData.registerFlags(from: output.covenant) {
                        ns.flags = flags
                    }
                    db.putNameState(nameHash, ns)
                }
            }
            try! db.commit(height: 0)
        }

        guard let genesisBlock = try blockStore.loadBlock(height: 0) else {
            XCTFail("Missing genesis block"); return
        }

        // === PATH A: Continuous replay (no restart) ===
        let continuousDB = NameDB()
        registerGenesisNames(continuousDB, block: genesisBlock)

        for h in 1..<totalBlocks {
            guard let block = try blockStore.loadBlock(height: h) else {
                XCTFail("Missing block \(h)"); return
            }
            try CovenantProcessor.replayCovenants(block: block, nameDB: continuousDB, height: h, nameParams: mainParams)
            if h % mainParams.treeInterval == 0 {
                try continuousDB.commit(height: h)
                if h == 3390 {
                    let root3390 = try continuousDB.treeRoot()
                    let expected = "227608a45936273ea02067425ef4e3a97e9e4d14b6d523627e7f53d16537ff65"
                    let actual = HexEncoding.encode(root3390)
                    print("Replay root at 3390: \(actual)")
                    print("Expected (block 3391): \(expected)")
                    print("Match: \(actual == expected)")
                    if actual != expected {
                        // Find which names differ by dumping all pending entries at each commit
                        print("REPLAY ROOT DOES NOT MATCH BLOCK 3391 EXPECTED ROOT")
                        print("This confirms the bug is in replayCovenants vs processCovenants")
                    }
                }
            }
        }
        let continuousRoot = try continuousDB.treeRoot()
        print("Continuous replay root at \(totalBlocks - 1): \(HexEncoding.encode(continuousRoot))")

        // === PATH B: Replay with simulated restart at each treeInterval ===
        // This simulates what happens on restart: the tree has committed state,
        // pending is empty, and blocks after the commit are replayed.
        // The key difference: after commit+clear, getNameState reads from the TREE
        // (deserialized), not from the pending map (in-memory).
        let restartDB = NameDB()
        registerGenesisNames(restartDB, block: genesisBlock)

        for h in 1..<totalBlocks {
            guard let block = try blockStore.loadBlock(height: h) else {
                XCTFail("Missing block \(h)"); return
            }
            try CovenantProcessor.replayCovenants(block: block, nameDB: restartDB, height: h, nameParams: mainParams)
            if h % mainParams.treeInterval == 0 {
                try restartDB.commit(height: h)

                // Simulate restart: clear pending so next reads come from tree
                // This is exactly what happens when a node restarts — committedHeight
                // is loaded, pending is empty, and blocks after commitHeight are replayed.
                restartDB.clearPendingForTest()
            }
        }
        let restartRoot = try restartDB.treeRoot()
        print("Restart-simulated replay root at \(totalBlocks - 1): \(HexEncoding.encode(restartRoot))")

        if continuousRoot != restartRoot {
            // Find the exact treeInterval where they diverge
            // Re-run both paths side by side
            let db1 = NameDB()
            let db2 = NameDB()
            registerGenesisNames(db1, block: genesisBlock)
            registerGenesisNames(db2, block: genesisBlock)

            for h in 1..<totalBlocks {
                guard let block = try blockStore.loadBlock(height: h) else { break }
                try CovenantProcessor.replayCovenants(block: block, nameDB: db1, height: h, nameParams: mainParams)
                try CovenantProcessor.replayCovenants(block: block, nameDB: db2, height: h, nameParams: mainParams)

                if h % mainParams.treeInterval == 0 {
                    try db1.commit(height: h)
                    try db2.commit(height: h)
                    db2.clearPendingForTest()

                    let r1 = try db1.treeRoot()
                    let r2 = try db2.treeRoot()
                    if r1 != r2 {
                        let windowStart = h - mainParams.treeInterval + 1
                        print("=== FIRST DIVERGENCE at commit height \(h) ===")
                        print("continuous: \(HexEncoding.encode(r1))")
                        print("restarted: \(HexEncoding.encode(r2))")

                        // Dump covenant txs in this window
                        for bh in windowStart...h {
                            guard let b = try blockStore.loadBlock(height: bh) else { continue }
                            for (ti, tx) in b.transactions.enumerated() {
                                for (oi, out) in tx.outputs.enumerated() {
                                    if out.covenant.type.isName {
                                        let nhHex = out.covenant.items.isEmpty ? "?" : HexEncoding.encode(Array(out.covenant.items[0].prefix(8)))
                                        print("  block \(bh) tx \(ti) output \(oi): \(out.covenant.type) nameHash=\(nhHex)...")
                                    }
                                }
                            }
                        }

                        XCTFail("Tree roots diverge at height \(h)")
                        return
                    }
                }
            }
        }

        XCTAssertEqual(continuousRoot, restartRoot, "Continuous and restarted replay must produce identical tree roots")
    }

    func testReadNameDBBackup() throws {
        let path = NSHomeDirectory() + "/.fbd/tree/names.bak"
        let db: NameDB
        do {
            db = try NameDB(path: path)
        } catch {
            throw XCTSkip("No NameDB backup at \(path): \(error)")
        }
        print("committedHeight: \(db.committedHeight)")
        print("treeRoot: \(HexEncoding.encode(try db.treeRoot()))")
        db.close()
    }

    /// Check if the corrupted root matches a genesis-only tree (no covenant changes).
    func testGenesisOnlyRoot() throws {
        let blocksDir = NSHomeDirectory() + "/.fbd/blocks"
        let blockStore = try BlockStore(blocksDir: blocksDir, network: .main)
        guard let genesisBlock = try blockStore.loadBlock(height: 0) else {
            XCTFail("No genesis"); return
        }

        let db = NameDB()
        // Register genesis names exactly as connectBlock does
        var genesisNames = ["fistbump"]
        for char in "abcdefghijklmnopqrstuvwxyz0123456789" { genesisNames.append(String(char)) }
        var hashToName = [[UInt8]: [UInt8]]()
        for name in genesisNames { hashToName[NameRules.hashName(name).bytes] = Array(name.utf8) }
        let cb = genesisBlock.transactions[0]
        let txH = cb.txHash()
        for (oi, out) in cb.outputs.enumerated() {
            if out.covenant.type == .register {
                let nhb = out.covenant.items[0]
                let nh = NameHash(unchecked: nhb)
                let res = out.covenant.items.count > 2 ? out.covenant.items[2] : [UInt8]()
                let nb = hashToName[nhb] ?? nhb
                var ns = NameState()
                ns.name = nb; ns.nameHash = nh; ns.height = 0; ns.renewal = 0
                ns.registered = true
                ns.owner = NameState.Outpoint(hash: txH.bytes, index: oi)
                ns.data = res; ns.value = 0; ns.highest = 0
                if let f = CovenantData.registerFlags(from: out.covenant) { ns.flags = f }
                db.putNameState(nh, ns)
            }
        }
        try db.commit(height: 0)
        let genesisRoot = HexEncoding.encode(try db.treeRoot())
        print("Genesis-only root: \(genesisRoot)")
        print("Corrupted root:    163a97c338539a51e162d9bc5ed3e33cb28e8f209da3d244a409287bdad7a0cf")
        print("Correct root:      227608a45936273ea02067425ef4e3a97e9e4d14b6d523627e7f53d16537ff65")
        print("Genesis matches corrupted: \(genesisRoot == "163a97c338539a51e162d9bc5ed3e33cb28e8f209da3d244a409287bdad7a0cf")")
    }
}
