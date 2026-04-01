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

    // MARK: - Blockchain RPC Handlers

    func blockchainRPCHandlers(ctx: NodeContext, network: NetworkType) -> [String: RPCDispatcher.Handler] {
        var handlers: [String: RPCDispatcher.Handler] = [:]

        handlers["getblockchaininfo"] = { _ in
                guard let chain = ctx.chain else { return .null }
                let headerTip = chain.tip
                let storedHeight = chain.storedHeight
                // Use the stored block tip for blocks/bestblockhash/mediantime
                let blockTip = chain.getEntryByHeight(storedHeight) ?? headerTip
                let progress = storedHeight >= 0
                    ? Double(storedHeight) / max(Double(headerTip.height), 1.0)
                    : 0.0
                let mtp = chain.medianTimePast(for: blockTip)
                let chainwork = HexEncoding.encode(blockTip.chainwork.bigEndianBytes())

                // Compute soft fork states for the current stored tip
                var softforks: [(String, JSONValue)] = []
                for deployment in chain.params.deployments {
                    guard deployment.name != "testdummy" else { continue }
                    let state = chain.getDeploymentState(prev: blockTip, deployment: deployment)
                    softforks.append((
                        deployment.name,
                        RPCMethods.formatDeployment(deployment, status: state)
                    ))
                }

                return RPCMethods.getBlockchainInfo(
                    chain: network.rawValue,
                    blocks: storedHeight,
                    headers: headerTip.height,
                    bestHash: blockTip.hash,
                    treeRoot: blockTip.treeRoot,
                    bits: blockTip.bits,
                    medianTime: mtp,
                    chainwork: chainwork,
                    progress: min(progress, 1.0),
                    softforks: softforks,
                    version: FullNode.fullVersion
                )
            }

        handlers["getblockcount"] = { _ in
                guard let chain = ctx.chain else { return .int(0) }
                return RPCMethods.getBlockCount(max(chain.storedHeight, 0))
            }

        handlers["getbestblockhash"] = { _ in
                guard let chain = ctx.chain else { return .string(Hash256.zero.hex) }
                let tip = chain.getEntryByHeight(chain.storedHeight) ?? chain.tip
                return RPCMethods.getBestBlockHash(tip.hash)
            }

        handlers["getblockhash"] = { req in
                let params = req.params
                let chain = try Self.requireChain(ctx)
                guard let h = params.first?.intValue else {
                    throw RPCError.invalidParams("expected height")
                }
                guard let entry = chain.getEntryByHeight(Int(h)) else {
                    throw RPCError.invalidParams("Block not found at height \(h)")
                }
                return RPCMethods.getBlockHash(entry.hash)
            }

        handlers["getblockheader"] = { req in
                let params = req.params
                let chain = try Self.requireChain(ctx)
                let entry: ChainEntry?
                if let h = params.first?.intValue {
                    entry = chain.getEntryByHeight(Int(h))
                } else if let hashStr = params.first?.stringValue {
                    let hash = try Hash256.fromHex(hashStr)
                    entry = chain.getEntry(hash: hash)
                } else {
                    throw RPCError.invalidParams("expected height or hash")
                }
                guard let entry = entry else {
                    throw RPCError.invalidParams("Block not found")
                }
                return RPCMethods.formatBlockHeader(entry: entry)
            }

        handlers["getblock"] = { req in
                let params = req.params
                let chain = try Self.requireChain(ctx)

                // Resolve to a height
                let height: Int
                if let h = params.first?.intValue {
                    height = Int(h)
                } else if let hashStr = params.first?.stringValue {
                    let hash = try Hash256.fromHex(hashStr)
                    guard let entry = chain.getEntry(hash: hash) else {
                        throw RPCError.invalidParams("Block not found")
                    }
                    height = entry.height
                } else {
                    throw RPCError.invalidParams("expected height or hash")
                }

                guard let entry = chain.getEntryByHeight(height) else {
                    throw RPCError.invalidParams("Block not found at height \(height)")
                }

                // Verbose mode (default): include full tx details
                let verbose = params.count < 2 || params[1].boolValue != false

                if verbose {
                    guard let block = try chain.getBlock(height: height) else {
                        throw RPCError.invalidParams("Block data not stored for height \(height)")
                    }
                    let confirmations = chain.height - height + 1
                    let txs: [JSONValue] = block.transactions.map { tx in
                        RPCMethods.formatTransaction(tx, confirmations: confirmations, network: network)
                    }
                    var header = RPCMethods.formatBlockHeader(entry: entry)
                    // Append proof, tx array and confirmations to the header object
                    if case .object(var pairs) = header {
                        pairs.append(("confirmations", .int(Int64(confirmations))))
                        pairs.append(("proof", .string(HexEncoding.encode(block.balloonProof.serialize()))))
                        pairs.append(("tx", .array(txs)))
                        header = .object(pairs)
                    }
                    return header
                } else {
                    // Non-verbose: just the header
                    return RPCMethods.formatBlockHeader(entry: entry)
                }
            }

        return handlers
    }
}
