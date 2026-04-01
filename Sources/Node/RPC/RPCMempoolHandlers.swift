import Foundation
import Base
import Chain
import Consensus
import Covenants
import ExtCrypto
import DNS
import Mempool
import Mining
import Net
import Protocol
import RPC
import Script
@preconcurrency import Wallet
import Logging

extension FullNode {

    // MARK: - Mempool RPC Handlers

    func mempoolRPCHandlers(ctx: NodeContext, network: NetworkType) -> [String: RPCDispatcher.Handler] {
        var handlers: [String: RPCDispatcher.Handler] = [:]

        handlers["getmempoolinfo"] = { _ in
                let mp = ctx.mempool
                return RPCMethods.getMempoolInfo(
                    size: mp?.count ?? 0,
                    bytes: mp?.size ?? 0,
                    orphans: mp?.orphans.count ?? 0
                )
            }

        handlers["getrawmempool"] = { _ in
                guard let mp = ctx.mempool else { return .array([]) }
                return .array(mp.map.keys.map { .string($0.hex) })
            }

        handlers["removetx"] = { req in
                let params = req.params
                guard let hashStr = params.first?.stringValue else {
                    throw RPCError.invalidParams("expected txid hex")
                }
                let hash = try Hash256.fromHex(hashStr)
                guard let mp = ctx.mempool else {
                    throw RPCError.internalError("mempool not ready")
                }
                let removed = mp.evictEntry(hash)
                return .object([("removed", .int(Int64(removed.count)))])
            }

        handlers["gettransaction"] = { req in
                let params = req.params
                guard let hashStr = params.first?.stringValue else {
                    throw RPCError.invalidParams("expected txid hex")
                }
                let hash = try Hash256.fromHex(hashStr)
                let (chain, mempool, _) = try Self.requireNode(ctx)

                // Check mempool first
                if let entry = mempool.get(hash) {
                    var result = RPCMethods.formatTransaction(entry.tx, confirmations: 0, network: network)
                    if case .object(var pairs) = result {
                        pairs.append(("time", .int(Int64(entry.time))))
                        result = .object(pairs)
                    }
                    return result
                }

                // Check tx index (if enabled)
                if chain.hasTxIndex, let loc = chain.getTxLocation(txHash: hash) {
                    guard let block = try chain.getBlock(height: loc.height) else {
                        throw RPCError.internalError("block not found at height \(loc.height)")
                    }
                    guard loc.txIndex < block.transactions.count else {
                        throw RPCError.internalError("tx index out of range")
                    }
                    let tx = block.transactions[loc.txIndex]
                    let confirmations = chain.height - loc.height + 1
                    var result = RPCMethods.formatTransaction(tx, confirmations: confirmations, network: network)
                    if case .object(var pairs) = result,
                       let entry = chain.getEntryByHeight(loc.height) {
                        pairs.append(("blockhash", .string(entry.hash.hex)))
                        pairs.append(("height", .int(Int64(loc.height))))
                        result = .object(pairs)
                    }
                    return result
                }

                if !chain.hasTxIndex {
                    throw RPCError.invalidParams("tx not in mempool (enable --index-tx for historical lookup)")
                }
                throw RPCError.invalidParams("transaction not found")
            }

        handlers["getrawtransaction"] = { req in
                let params = req.params
                guard let hashStr = params.first?.stringValue else {
                    throw RPCError.invalidParams("expected txid hex")
                }
                let hash = try Hash256.fromHex(hashStr)
                let (chain, mempool, _) = try Self.requireNode(ctx)

                // Check mempool first
                if let entry = mempool.get(hash) {
                    var writer = BufferWriter()
                    entry.tx.write(to: &writer)
                    return .string(HexEncoding.encode(writer.data))
                }

                // Check tx index (if enabled)
                if chain.hasTxIndex, let loc = chain.getTxLocation(txHash: hash) {
                    guard let block = try chain.getBlock(height: loc.height) else {
                        throw RPCError.internalError("block not found at height \(loc.height)")
                    }
                    guard loc.txIndex < block.transactions.count else {
                        throw RPCError.internalError("tx index out of range")
                    }
                    let tx = block.transactions[loc.txIndex]
                    var writer = BufferWriter()
                    tx.write(to: &writer)
                    return .string(HexEncoding.encode(writer.data))
                }

                if !chain.hasTxIndex {
                    throw RPCError.invalidParams("tx not in mempool (enable --index-tx for historical lookup)")
                }
                throw RPCError.invalidParams("transaction not found")
            }

        handlers["decoderawtransaction"] = { req in
                let params = req.params
                guard let hexStr = params.first?.stringValue else {
                    throw RPCError.invalidParams("expected raw transaction or PSTX hex")
                }
                let rawBytes = try HexEncoding.decode(hexStr)

                // Try PSTX first (starts with version byte 0x01 + txLen)
                let tx: Transaction
                var pstxInfo: PartiallySignedTx?
                if let pstx = PartiallySignedTx.deserialize(rawBytes) {
                    tx = pstx.tx
                    pstxInfo = pstx
                } else {
                    var reader = BufferReader(rawBytes)
                    tx = try Transaction.read(from: &reader)
                }

                let txHash = tx.txHash()

                // Inputs
                let inputsJSON: [JSONValue] = tx.inputs.enumerated().map { (i, input) in
                    var obj: [(String, JSONValue)] = [
                        ("prevout", .object([
                            ("hash", .string(input.prevout.hash.hex)),
                            ("index", .int(Int64(input.prevout.index))),
                        ])),
                        ("sequence", .int(Int64(input.sequence))),
                    ]
                    if i < tx.witnesses.count && !tx.witnesses[i].items.isEmpty {
                        let wit = tx.witnesses[i]
                        obj.append(("witness", .array(wit.items.map { .string(HexEncoding.encode($0)) })))
                    }
                    if let pstx = pstxInfo, i < pstx.coins.count {
                        let coin = pstx.coins[i]
                        obj.append(("coinValue", .int(Int64(coin.value))))
                        obj.append(("coinAddress", .string(coin.address.toBech32(network: network))))
                    }
                    if let pstx = pstxInfo, i < pstx.signatures.count {
                        let sigs = pstx.signatures[i]
                        let signedCount = sigs.filter { !$0.isEmpty }.count
                        let totalSlots = sigs.count
                        obj.append(("signatures", .string("\(signedCount)/\(totalSlots)")))
                    }
                    if let pstx = pstxInfo, i < pstx.configs.count, let config = pstx.configs[i] {
                        obj.append(("multisig", .string("\(config.m)-of-\(config.n)")))
                    }
                    return .object(obj)
                }

                // Outputs
                let outputsJSON: [JSONValue] = tx.outputs.enumerated().map { (i, output) in
                    let addrStr = output.address.toBech32(network: network)
                    var obj: [(String, JSONValue)] = [
                        ("value", .int(Int64(output.value))),
                        ("index", .int(Int64(i))),
                        ("address", .string(addrStr)),
                    ]
                    let cov = output.covenant
                    var covObj: [(String, JSONValue)] = [
                        ("type", .int(Int64(cov.type.rawValue))),
                        ("action", .string("\(cov.type)".uppercased())),
                    ]
                    if !cov.items.isEmpty {
                        covObj.append(("items", .array(cov.items.map { .string(HexEncoding.encode($0)) })))
                    }
                    obj.append(("covenant", .object(covObj)))
                    return .object(obj)
                }

                // Compute fee if PSTX (has input coin values)
                var fee: Int64?
                if let pstx = pstxInfo {
                    let inputTotal = pstx.coins.reduce(UInt64(0)) { $0 + $1.value }
                    let outputTotal = tx.outputs.reduce(UInt64(0)) { $0 + $1.value }
                    fee = Int64(inputTotal) - Int64(outputTotal)
                }

                var result: [(String, JSONValue)] = [
                    ("txid", .string(txHash.hex)),
                    ("version", .int(Int64(tx.version))),
                    ("locktime", .int(Int64(tx.locktime))),
                    ("inputs", .array(inputsJSON)),
                    ("outputs", .array(outputsJSON)),
                ]
                if pstxInfo != nil {
                    result.append(("format", .string("pstx")))
                }
                if let fee = fee {
                    result.append(("fee", .int(fee)))
                }

                // Size metrics: use finalized tx if PSTX (to show actual broadcast size)
                if let pstx = pstxInfo, let finalized = try? WalletDB.finalizeTransaction(pstx) {
                    result.append(("weight", .int(Int64(finalized.weight))))
                    result.append(("vsize", .int(Int64(finalized.virtualSize))))
                } else {
                    result.append(("weight", .int(Int64(tx.weight))))
                    result.append(("vsize", .int(Int64(tx.virtualSize))))
                }

                return .object(result)
            }

        handlers["gettxbyaddress"] = { req in
                let params = req.params
                guard let addrStr = params.first?.stringValue else {
                    throw RPCError.invalidParams("expected address")
                }
                let chain = try Self.requireChain(ctx)
                guard chain.hasAddrIndex else {
                    throw RPCError.invalidParams("address index not enabled (use --index-address)")
                }
                let address = try Address(bech32: addrStr, network: network)
                let txHashes = chain.getTxHashesByAddress(address)
                return .array(txHashes.map { .string($0.hex) })
            }

        handlers["getcoinsbyaddress"] = { req in
                let params = req.params
                guard let addrStr = params.first?.stringValue else {
                    throw RPCError.invalidParams("expected address")
                }
                let chain = try Self.requireChain(ctx)
                guard chain.hasAddrIndex else {
                    throw RPCError.invalidParams("address index not enabled (use --index-address)")
                }
                let address = try Address(bech32: addrStr, network: network)
                let outpoints = chain.getCoinsByAddress(address)

                var coins: [JSONValue] = []
                for op in outpoints {
                    let coin = ctx.coinDB?.getCoin(Outpoint(hash: op.hash, index: op.index))
                    let entry: JSONValue = .object([
                        ("txid", .string(op.hash.hex)),
                        ("vout", .int(Int64(op.index))),
                        ("value", .int(Int64(coin?.output.value ?? 0))),
                        ("address", .string(coin?.output.address.toBech32(network: network) ?? "")),
                    ])
                    coins.append(entry)
                }
                return .array(coins)
            }

        handlers["sendrawtransaction"] = { req in
                let params = req.params
                guard let hexStr = params.first?.stringValue else {
                    throw RPCError.invalidParams("expected hex string")
                }
                let rawBytes = try HexEncoding.decode(hexStr)

                var reader = BufferReader(rawBytes)
                let tx = try Transaction.read(from: &reader)
                let txHash = tx.txHash()

                let (chain, mempool, coinDB) = try Self.requireNode(ctx)

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)

                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .string(txHash.hex)
            }

        return handlers
    }
}
