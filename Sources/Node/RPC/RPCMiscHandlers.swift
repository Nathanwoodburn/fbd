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

    // MARK: - Misc RPC Handlers

    func miscRPCHandlers(ctx: NodeContext, network: NetworkType, walletsDir: String) -> [String: RPCDispatcher.Handler] {
        var handlers: [String: RPCDispatcher.Handler] = [:]

        // MARK: Control

        handlers["stop"] = { [weak self] _ in
                // Trigger shutdown after the response is sent.
                Task {
                    try? await Task.sleep(nanoseconds: 100_000_000)
                    self?.requestShutdown()
                }
                return .string("Stopping node...")
            }

        // MARK: DNSSEC Proof

        handlers["getdnssecproof"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected: getdnssecproof <name>")
                }
                guard NameRules.verifyName(name) else {
                    throw RPCError.invalidParams("invalid name: \(name)")
                }
                let addr = try wallet.getReceiveAddress()
                let bech32 = addr.toBech32(network: network)
                let txtValue = "fbd=\(name):\(bech32)"
                return .object([
                    ("record", .string(txtValue)),
                    ("subdomain", .string("_fbd")),
                    ("type", .string("TXT")),
                ])
            }

        handlers["verifydnssecproof"] = { req in
                let params = req.params
                guard params.count >= 2,
                      let name = params[0].stringValue, !name.isEmpty,
                      let domain = params[1].stringValue, !domain.isEmpty else {
                    throw RPCError.invalidParams("expected: verifydnssecproof <name> <domain> [resolver]")
                }

                let resolver = params.count >= 3 ? (params[2].stringValue ?? "8.8.8.8") : "8.8.8.8"
                let proofBytes: [UInt8]
                do {
                    proofBytes = try DNSSECProber.buildProof(name: name, domain: domain, resolver: resolver)
                } catch {
                    throw RPCError.internalError("\(error)")
                }

                let blockTime = UInt64(Date().timeIntervalSince1970)
                do {
                    let binding = try DNSSECProofValidator.validateProof(
                        proofBytes, claimedName: name,
                        blockTime: blockTime, gracePeriod: 86_400,
                        expectedAddressHRP: network.addressHRP
                    )
                    let bindingAddr = Address(unchecked: binding.version, hash: binding.hash)
                    return .object([
                        ("proof", .string(HexEncoding.encode(proofBytes))),
                        ("size", .int(Int64(proofBytes.count))),
                        ("valid", .bool(true)),
                        ("name", .string(name)),
                        ("domain", .string(domain)),
                        ("dnssecRequired", .bool(NameRules.requiresDNSSEC(name))),
                        ("bindingAddress", .string(bindingAddr.toBech32(network: network))),
                    ])
                } catch {
                    return .object([
                        ("proof", .string(HexEncoding.encode(proofBytes))),
                        ("size", .int(Int64(proofBytes.count))),
                        ("valid", .bool(false)),
                        ("message", .string("\(error)")),
                    ])
                }
            }

        // MARK: Protocol Params

        handlers["getprotocolparams"] = { _ in
                let np = NameParams.params(for: network)
                let cp = ConsensusParams.params(for: network)
                return .object([
                    ("openPeriod", .int(Int64(np.openPeriod))),
                    ("biddingPeriod", .int(Int64(np.biddingPeriod))),
                    ("revealPeriod", .int(Int64(np.revealPeriod))),
                    ("registerDeadline", .int(Int64(np.registerDeadline))),
                    ("renewalWindow", .int(Int64(np.renewalWindow))),
                    ("renewalPeriod", .int(Int64(np.renewalPeriod))),
                    ("renewalMaturity", .int(Int64(np.renewalMaturity))),
                    ("transferLockup", .int(Int64(np.transferLockup))),
                    ("auctionMaturity", .int(Int64(np.auctionMaturity))),
                    ("coinbaseMaturity", .int(Int64(cp.coinbaseMaturity))),
                    ("blockTimeSeconds", .int(120)),
                    ("registrationBurnPercent", .int(Int64(np.registrationBurnPercent))),
                    ("renewalFeePercent", .int(Int64(np.renewalFeePercent))),
                ])
            }

        return handlers
    }
}
