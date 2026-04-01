import XCTest
@testable import Node
@testable import RPC
@testable import Base
@testable import Wallet
@testable import Chain
@testable import Mempool
import Protocol
import ExtCrypto
import Consensus

final class NodeRPCTests: XCTestCase {

    private var tmpDir: String!

    override func setUp() {
        super.setUp()
        tmpDir = NSTemporaryDirectory() + "fbd-rpc-test-\(UUID().uuidString)"
    }

    override func tearDown() {
        if let dir = tmpDir {
            try? FileManager.default.removeItem(atPath: dir)
        }
        super.tearDown()
    }

    // MARK: - Helpers

    /// Build a dispatcher with a wallet-only context (no chain/mempool).
    private func makeWalletDispatcher(walletName: String = "test") throws -> (RPCDispatcher, WalletDB, NodeContext) {
        let walletPath = tmpDir + "/wallets/\(walletName)"
        let wallet = try WalletDB(path: walletPath, network: .regtest)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let ctx = NodeContext()
        ctx.setWallet(walletName, wallet)

        let config = NodeConfig(network: .regtest, dataDir: tmpDir)
        let node = FullNode(config: config)
        let dispatcher = node.buildRPCDispatcher(ctx: ctx)

        return (dispatcher, wallet, ctx)
    }

    /// Build a dispatcher with chain and mempool.
    private func makeFullDispatcher(walletName: String = "test") throws -> (RPCDispatcher, WalletDB, Chain, NodeContext) {
        let walletPath = tmpDir + "/wallets/\(walletName)"
        let wallet = try WalletDB(path: walletPath, network: .regtest)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let chain = try Chain(network: .regtest)
        let mempool = Mempool()

        let ctx = NodeContext()
        ctx.setWallet(walletName, wallet)
        ctx.chain = chain
        ctx.mempool = mempool

        let config = NodeConfig(network: .regtest, dataDir: tmpDir)
        let node = FullNode(config: config)
        let dispatcher = node.buildRPCDispatcher(ctx: ctx)

        return (dispatcher, wallet, chain, ctx)
    }

    private func dispatch(_ dispatcher: RPCDispatcher, method: String, params: [JSONValue] = [], wallet: String? = nil) -> RPCResponse {
        dispatcher.dispatch(RPCRequest(method: method, params: params, wallet: wallet))
    }

    // MARK: - Help

    func testUnknownMethodReturnsError() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher()
        let response = dispatch(dispatcher, method: "nonexistent")
        XCTAssertNotNil(response.error)
    }

    // MARK: - Stop

    func testStop() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher()
        let response = dispatch(dispatcher, method: "stop")
        guard case .string(let msg) = response.result else {
            XCTFail("Expected string result")
            return
        }
        XCTAssertTrue(msg.contains("Stopping"))
    }

    // MARK: - List Wallets

    func testListWallets() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "mywallet")
        let response = dispatch(dispatcher, method: "listwallets")
        guard case .array(let names) = response.result else {
            XCTFail("Expected array")
            return
        }
        XCTAssertEqual(names.count, 1)
        XCTAssertEqual(names[0].stringValue, "mywallet")
    }

    func testListWalletsEmpty() throws {
        let ctx = NodeContext()
        let config = NodeConfig(network: .regtest, dataDir: tmpDir)
        let node = FullNode(config: config)
        let dispatcher = node.buildRPCDispatcher(ctx: ctx)

        let response = dispatch(dispatcher, method: "listwallets")
        guard case .array(let names) = response.result else {
            XCTFail("Expected array")
            return
        }
        XCTAssertEqual(names.count, 0)
    }

    // MARK: - Create Wallet

    func testCreateWallet() throws {
        let ctx = NodeContext()
        try FileManager.default.createDirectory(atPath: tmpDir + "/wallets", withIntermediateDirectories: true)

        let config = NodeConfig(network: .regtest, dataDir: tmpDir)
        let node = FullNode(config: config)
        let dispatcher = node.buildRPCDispatcher(ctx: ctx)

        let response = dispatch(dispatcher, method: "createwallet", params: [.string("newwallet")])
        XCTAssertNil(response.error, "Should not have error")
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object result")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["name"]?.stringValue, "newwallet")
        XCTAssertNotNil(dict["mnemonic"]?.stringValue)

        // Wallet should be registered in context
        XCTAssertNotNil(ctx.wallet(named: "newwallet"))
    }

    func testCreateWalletDuplicateFails() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "existing")
        let response = dispatch(dispatcher, method: "createwallet", params: [.string("existing")])
        XCTAssertNotNil(response.error, "Should fail for duplicate wallet")
    }

    // MARK: - Delete Wallet

    func testDeleteWallet() throws {
        let (dispatcher, _, ctx) = try makeWalletDispatcher(walletName: "todelete")
        XCTAssertNotNil(ctx.wallet(named: "todelete"))

        let response = dispatch(dispatcher, method: "deletewallet", wallet: "todelete")
        XCTAssertNil(response.error)
        XCTAssertNil(ctx.wallet(named: "todelete"), "Wallet should be removed from context")
    }

    // MARK: - Get Wallet Info

    func testGetWalletInfo() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "info")
        let response = dispatch(dispatcher, method: "getwalletinfo", wallet: "info")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object result")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["name"]?.stringValue, "info")
        XCTAssertEqual(dict["initialized"]?.boolValue, true)
        XCTAssertNil(dict["mnemonic"], "mnemonic should not be in getwalletinfo")
        XCTAssertNil(dict["xpriv"], "xpriv should not be in getwalletinfo")
        XCTAssertNotNil(dict["balance"])
    }

    // MARK: - Get Balance

    func testGetBalance() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "bal")
        let response = dispatch(dispatcher, method: "getbalance", wallet: "bal")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object result")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["confirmed"]?.intValue, 0)
        XCTAssertEqual(dict["spendable"]?.intValue, 0)
        // pending, locked, immature are omitted when zero
    }

    // MARK: - Get New Address / Get Change Address

    func testGetNewAddress() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "addr")
        let response = dispatch(dispatcher, method: "getnewaddress", wallet: "addr")
        XCTAssertNil(response.error)
        guard case .string(let addr) = response.result else {
            XCTFail("Expected string address")
            return
        }
        XCTAssertTrue(addr.hasPrefix("fr1"), "Regtest address should start with fr1")
    }

    func testGetChangeAddress() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "change")
        let response = dispatch(dispatcher, method: "getchangeaddress", wallet: "change")
        XCTAssertNil(response.error)
        guard case .string(let addr) = response.result else {
            XCTFail("Expected string address")
            return
        }
        XCTAssertTrue(addr.hasPrefix("fr1"), "Regtest address should start with fr1")
    }

    func testNewAndChangeAddressesDiffer() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "diff")
        let resp1 = dispatch(dispatcher, method: "getnewaddress", wallet: "diff")
        let resp2 = dispatch(dispatcher, method: "getchangeaddress", wallet: "diff")
        XCTAssertNotEqual(resp1.result?.stringValue, resp2.result?.stringValue)
    }

    // MARK: - Sign / Verify Message

    func testSignAndVerifyMessage() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "sig")

        // Get an address first
        let addrResp = dispatch(dispatcher, method: "getnewaddress", wallet: "sig")
        guard let addr = addrResp.result?.stringValue else {
            XCTFail("Failed to get address")
            return
        }

        // Sign a message
        let signResp = dispatch(dispatcher, method: "signmessage",
                                params: [.string(addr), .string("hello world")],
                                wallet: "sig")
        XCTAssertNil(signResp.error)
        guard let signature = signResp.result?.stringValue else {
            XCTFail("Expected signature string")
            return
        }

        // Verify the signature
        let verifyResp = dispatch(dispatcher, method: "verifymessage",
                                  params: [.string(addr), .string(signature), .string("hello world")])
        XCTAssertNil(verifyResp.error)
        XCTAssertEqual(verifyResp.result?.boolValue, true)
    }

    func testVerifyMessageWrongMessage() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "sig2")

        let addrResp = dispatch(dispatcher, method: "getnewaddress", wallet: "sig2")
        guard let addr = addrResp.result?.stringValue else {
            XCTFail("Failed to get address")
            return
        }

        let signResp = dispatch(dispatcher, method: "signmessage",
                                params: [.string(addr), .string("original message")],
                                wallet: "sig2")
        guard let signature = signResp.result?.stringValue else {
            XCTFail("Expected signature")
            return
        }

        // Verify with wrong message
        let verifyResp = dispatch(dispatcher, method: "verifymessage",
                                  params: [.string(addr), .string(signature), .string("wrong message")])
        XCTAssertEqual(verifyResp.result?.boolValue, false)
    }

    // MARK: - Validate Address

    func testValidateAddressValid() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "val")

        let addrResp = dispatch(dispatcher, method: "getnewaddress", wallet: "val")
        guard let addr = addrResp.result?.stringValue else {
            XCTFail("Failed to get address")
            return
        }

        let response = dispatch(dispatcher, method: "validateaddress", params: [.string(addr)], wallet: "val")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["isvalid"]?.boolValue, true)
        XCTAssertEqual(dict["ismine"]?.boolValue, true)
        XCTAssertEqual(dict["address"]?.stringValue, addr)
    }

    func testValidateAddressInvalid() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher()
        let response = dispatch(dispatcher, method: "validateaddress", params: [.string("notanaddress")])
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["isvalid"]?.boolValue, false)
    }

    func testValidateAddressNotMine() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "notmine")
        // A valid regtest address that isn't ours
        let otherAddr = Address(unchecked: 0, hash: [UInt8](repeating: 0xFF, count: 20))
        let bech32 = otherAddr.toBech32(network: .regtest)

        let response = dispatch(dispatcher, method: "validateaddress", params: [.string(bech32)], wallet: "notmine")
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["isvalid"]?.boolValue, true)
        XCTAssertEqual(dict["ismine"]?.boolValue, false)
    }

    // MARK: - Backup / Restore Wallet

    func testBackupAndRestoreWallet() throws {
        let (dispatcher, wallet, ctx) = try makeWalletDispatcher(walletName: "backup")
        let backupPath = tmpDir + "/backup.json"

        // Backup
        let backupResp = dispatch(dispatcher, method: "backupwallet",
                                  params: [.string(backupPath)],
                                  wallet: "backup")
        XCTAssertNil(backupResp.error)
        XCTAssertTrue(FileManager.default.fileExists(atPath: backupPath))

        // Delete the wallet
        ctx.setWallet("backup", nil)

        // Restore
        let restorePath = tmpDir + "/wallets"
        try FileManager.default.createDirectory(atPath: restorePath, withIntermediateDirectories: true)
        let restoreResp = dispatch(dispatcher, method: "restorewallet",
                                   params: [.string("restored"), .string(backupPath)])
        XCTAssertNil(restoreResp.error, "Restore should succeed: \(restoreResp.error?.message ?? "")")
        XCTAssertNotNil(ctx.wallet(named: "restored"), "Restored wallet should exist in context")
    }

    // MARK: - Chain RPC

    func testGetBlockCount() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblockcount")
        XCTAssertNil(response.error)
        // Genesis = height 0
        XCTAssertEqual(response.result?.intValue, 0)
    }

    func testGetBestBlockHash() throws {
        let (dispatcher, _, chain, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getbestblockhash")
        XCTAssertNil(response.error)
        XCTAssertEqual(response.result?.stringValue, chain.tip.hash.hex)
    }

    func testGetBlockHash() throws {
        let (dispatcher, _, chain, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblockhash", params: [.int(0)])
        XCTAssertNil(response.error)
        XCTAssertEqual(response.result?.stringValue, chain.tip.hash.hex)
    }

    func testGetBlockHashInvalid() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblockhash", params: [.int(999)])
        XCTAssertNotNil(response.error, "Should fail for non-existent height")
    }

    func testGetBlockchainInfo() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblockchaininfo")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["chain"]?.stringValue, "regtest")
        XCTAssertNotNil(dict["headers"])
        XCTAssertNotNil(dict["bestblockhash"])
    }

    // MARK: - Mempool RPC

    func testGetMempoolInfo() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getmempoolinfo")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["size"]?.intValue, 0)
        XCTAssertEqual(dict["bytes"]?.intValue, 0)
    }

    func testGetRawMempool() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getrawmempool")
        XCTAssertNil(response.error)
        guard case .array(let txs) = response.result else {
            XCTFail("Expected array")
            return
        }
        XCTAssertEqual(txs.count, 0)
    }

    // MARK: - Estimate Fee

    func testEstimateFee() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "estimatefee")
        XCTAssertNil(response.error)
        XCTAssertEqual(response.result?.intValue, MempoolPolicy.minRelay)
    }

    // MARK: - Error Cases

    func testUnknownMethod() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher()
        let response = dispatch(dispatcher, method: "nonexistentmethod")
        XCTAssertNotNil(response.error)
        XCTAssertEqual(response.error?.code, -32601, "Should be method not found")
    }

    func testWalletNotFound() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "exists")
        let response = dispatch(dispatcher, method: "getbalance", wallet: "nosuch")
        XCTAssertNotNil(response.error, "Should fail for non-existent wallet")
    }

    func testMissingWalletParam() throws {
        let ctx = NodeContext()
        // No wallets at all
        let config = NodeConfig(network: .regtest, dataDir: tmpDir)
        let node = FullNode(config: config)
        let dispatcher = node.buildRPCDispatcher(ctx: ctx)

        let response = dispatch(dispatcher, method: "getbalance")
        XCTAssertNotNil(response.error, "Should fail when no wallets exist")
    }

    func testSignmessageMissingParams() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "sig3")
        let response = dispatch(dispatcher, method: "signmessage", params: [], wallet: "sig3")
        XCTAssertNotNil(response.error, "Should fail with missing params")
    }

    func testValidateAddressMissingParam() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher()
        let response = dispatch(dispatcher, method: "validateaddress")
        XCTAssertNotNil(response.error, "Should fail with missing address param")
    }

    // MARK: - Auto-select Wallet

    func testAutoSelectSingleWallet() throws {
        let (dispatcher, _, _) = try makeWalletDispatcher(walletName: "only")
        // Don't pass wallet name — should auto-select the only wallet
        let response = dispatch(dispatcher, method: "getbalance")
        XCTAssertNil(response.error, "Should auto-select the only wallet")
    }

    func testMultipleWalletsRequiresExplicitSelection() throws {
        let walletPath1 = tmpDir + "/wallets/w1"
        let walletPath2 = tmpDir + "/wallets/w2"

        let w1 = try WalletDB(path: walletPath1, network: .regtest)
        _ = try w1.create()
        let w2 = try WalletDB(path: walletPath2, network: .regtest)
        _ = try w2.create()

        let ctx = NodeContext()
        ctx.setWallet("w1", w1)
        ctx.setWallet("w2", w2)

        let config = NodeConfig(network: .regtest, dataDir: tmpDir)
        let node = FullNode(config: config)
        let dispatcher = node.buildRPCDispatcher(ctx: ctx)

        // No --wallet specified with multiple wallets → error
        let response = dispatch(dispatcher, method: "getbalance")
        XCTAssertNotNil(response.error, "Should require explicit wallet selection")
    }

    // MARK: - Mining Info

    func testGetMiningInfo() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getmininginfo")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertNotNil(dict["blocks"])
        XCTAssertNotNil(dict["difficulty"])
        XCTAssertNotNil(dict["pooledtx"])
    }

    // MARK: - Network Info

    func testGetNetworkInfo() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getnetworkinfo")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertNotNil(dict["subversion"]?.stringValue)
        XCTAssertTrue(dict["subversion"]!.stringValue!.contains("fbd"))
    }

    // MARK: - Block Header

    func testGetBlockHeader() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblockheader", params: [.int(0)])
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["height"]?.intValue, 0)
        XCTAssertNotNil(dict["hash"]?.stringValue)
    }

    func testGetBlockHeaderByHash() throws {
        let (dispatcher, _, chain, _) = try makeFullDispatcher()
        let hash = chain.tip.hash.hex
        let response = dispatch(dispatcher, method: "getblockheader", params: [.string(hash)])
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["height"]?.intValue, 0)
    }

    func testGetBlockHeaderNotFound() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let fakeHash = String(repeating: "aa", count: 32)
        let response = dispatch(dispatcher, method: "getblockheader", params: [.string(fakeHash)])
        XCTAssertNotNil(response.error)
    }

    // MARK: - Get Block

    func testGetBlockNotStored() throws {
        // In test context, full blocks aren't stored — only chain entries exist
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblock", params: [.int(0)])
        // Should return error since block data isn't stored in test Chain
        XCTAssertNotNil(response.error)
    }

    func testGetBlockUnknownHash() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let fakeHash = String(repeating: "bb", count: 32)
        let response = dispatch(dispatcher, method: "getblock", params: [.string(fakeHash)])
        XCTAssertNotNil(response.error, "Should fail for nonexistent block hash")
    }

    func testGetBlockMissingParam() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblock")
        XCTAssertNotNil(response.error, "Should fail with missing params")
    }

    // MARK: - Get Name Info

    func testGetNameInfoUnknown() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getnameinfo", params: [.string("nonexistentname")])
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertNotNil(dict["name"])
        // State should be INACTIVE for nonexistent name
        XCTAssertEqual(dict["state"]?.stringValue, "INACTIVE")
    }

    func testGetNameInfoMissingParam() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getnameinfo")
        XCTAssertNotNil(response.error, "Should fail with missing name param")
    }

    // MARK: - Transaction RPCs

    func testGetRawTransactionUnknown() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let fakeHash = String(repeating: "cc", count: 32)
        let response = dispatch(dispatcher, method: "getrawtransaction", params: [.string(fakeHash)])
        XCTAssertNotNil(response.error, "Should return error for unknown tx")
    }

    func testGetRawTransactionMissingParam() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getrawtransaction")
        XCTAssertNotNil(response.error, "Should fail with missing txid")
    }

    func testSendRawTransactionMalformed() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "sendrawtransaction", params: [.string("notvalidhex")])
        XCTAssertNotNil(response.error, "Should fail for malformed hex")
    }

    func testSendRawTransactionMissingParam() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "sendrawtransaction")
        XCTAssertNotNil(response.error, "Should fail with missing params")
    }

    // MARK: - Peer RPCs

    func testGetPeerInfoNoPeers() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getpeerinfo")
        XCTAssertNil(response.error)
        guard case .array(let peers) = response.result else {
            XCTFail("Expected array")
            return
        }
        XCTAssertEqual(peers.count, 0, "Should return empty array when no peers")
    }

    func testGetNetworkInfoReturnsFields() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getnetworkinfo")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertNotNil(dict["version"])
        XCTAssertNotNil(dict["subversion"])
        XCTAssertNotNil(dict["connections"])
    }

    // MARK: - Mempool RPCs (extended)

    func testGetMempoolInfoFields() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getmempoolinfo")
        XCTAssertNil(response.error)
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertEqual(dict["size"]?.intValue, 0)
        XCTAssertEqual(dict["bytes"]?.intValue, 0)
    }

    // MARK: - Wallet RPCs (gaps)

    func testListAddresses() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "listaddresses", wallet: "test")
        XCTAssertNil(response.error)
        guard case .array(let addrs) = response.result else {
            XCTFail("Expected array")
            return
        }
        XCTAssertGreaterThan(addrs.count, 0, "Should list derived addresses")
        // Each address should have fields
        if case .object(let pairs) = addrs[0] {
            let dict = Dictionary(uniqueKeysWithValues: pairs)
            XCTAssertNotNil(dict["address"])
            XCTAssertNotNil(dict["path"])
        }
    }

    func testListTransactionsEmpty() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "listtransactions", wallet: "test")
        XCTAssertNil(response.error)
        guard case .array(let txs) = response.result else {
            XCTFail("Expected array")
            return
        }
        XCTAssertEqual(txs.count, 0, "Should be empty for new wallet")
    }

    func testListTransactionsPagination() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        // Request with explicit count and offset
        let response = dispatch(dispatcher, method: "listtransactions",
                                params: [.int(5), .int(0)], wallet: "test")
        XCTAssertNil(response.error)
        guard case .array(_) = response.result else {
            XCTFail("Expected array")
            return
        }
    }

    func testListUnspent() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "listunspent", wallet: "test")
        XCTAssertNil(response.error)
        guard case .array(let coins) = response.result else {
            XCTFail("Expected array")
            return
        }
        XCTAssertEqual(coins.count, 0, "Should be empty for new wallet")
    }

    // MARK: - Name Auction RPC Error Cases

    func testSendOpenMissingName() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "sendopen", wallet: "test")
        XCTAssertNotNil(response.error, "Should fail with missing name")
    }

    func testSendbidMissingParams() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "sendbid", wallet: "test")
        XCTAssertNotNil(response.error, "Should fail with missing params")
    }

    func testSendnoneMissingParams() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "sendnone", wallet: "test")
        XCTAssertNotNil(response.error, "Should fail with missing destination")
    }

    func testSendmanyMissingParams() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "sendmany", wallet: "test")
        XCTAssertNotNil(response.error, "Should fail with missing params")
    }

    // MARK: - Block/Chain Edge Cases

    func testGetBlockHashInvalidHeight() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblockhash", params: [.int(-1)])
        XCTAssertNotNil(response.error, "Should fail for negative height")
    }

    func testGetBlockCountReturnsZero() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblockcount")
        XCTAssertEqual(response.result?.intValue, 0)
    }

    func testGetBlockchainInfoContainsExpectedFields() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getblockchaininfo")
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertNotNil(dict["blocks"])
        XCTAssertNotNil(dict["headers"])
        XCTAssertNotNil(dict["bestblockhash"])
        XCTAssertNotNil(dict["chain"])
        XCTAssertNotNil(dict["difficulty"])
    }

    // MARK: - Mining RPC Fields

    func testGetMiningInfoFields() throws {
        let (dispatcher, _, _, _) = try makeFullDispatcher()
        let response = dispatch(dispatcher, method: "getmininginfo")
        guard case .object(let pairs) = response.result else {
            XCTFail("Expected object")
            return
        }
        let dict = Dictionary(uniqueKeysWithValues: pairs)
        XCTAssertNotNil(dict["blocks"])
        XCTAssertNotNil(dict["difficulty"])
        XCTAssertNotNil(dict["pooledtx"])
    }
}
