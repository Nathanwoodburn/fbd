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

    // MARK: - Name RPC Handlers

    func nameRPCHandlers(ctx: NodeContext, network: NetworkType, walletsDir: String) -> [String: RPCDispatcher.Handler] {
        var handlers: [String: RPCDispatcher.Handler] = [:]

        // MARK: Name Info

        handlers["getnameinfo"] = { req in
                let params = req.params
                let chain = try Self.requireChain(ctx)
                guard var name = params.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                // Strip trailing dots (DNS root notation)
                while name.hasSuffix(".") { name = String(name.dropLast()) }
                guard !name.isEmpty else { throw RPCError.invalidParams("expected name") }
                let nameHash = NameRules.hashName(name)
                // Name restriction info
                let restriction: String?
                if NameRules.blacklist.contains(NameRules.tldLabel(name)) {
                    restriction = "blacklisted"
                } else if NameRules.isICANNReserved(name) {
                    restriction = "ICANN reserved"
                } else if NameRules.isPremium(name) {
                    restriction = "premium"
                } else {
                    restriction = nil
                }

                let nameParams = NameParams.params(for: network)
                let isTLD = !NameRules.isSubdomain(name)
                let minBid = nameParams.minimumBid(atHeight: chain.storedHeight, name: name)

                guard let ns = try chain.getNameState(name: name) else {
                    // Name not found on chain -- check mempool for pending operations
                    let pending = ctx.mempool.map { !$0.contracts.txsForName(nameHash.asHash256).isEmpty } ?? false
                    let state = pending ? "PENDING" : "INACTIVE"

                    // For subdomains, check if parent chain is valid
                    // (each parent must exist and have auctionSubdomains enabled)
                    var parentIssue: String? = nil
                    if !isTLD && state == "INACTIVE" {
                        var current = name
                        while let parent = NameRules.parentName(current) {
                            if let parentNS = try chain.getNameState(name: parent) {
                                if !parentNS.auctionSubdomains {
                                    parentIssue = "parent \"\(parent)\" does not allow subdomain auctions"
                                    break
                                }
                            } else {
                                // Parent doesn't exist on chain
                                let parentTLD = NameRules.tldLabel(parent)
                                if NameRules.blacklist.contains(parentTLD) && parent == parentTLD {
                                    parentIssue = "parent \"\(parent)\" is blacklisted"
                                } else if NameRules.isICANNReserved(parentTLD) && parent == parentTLD {
                                    parentIssue = "parent \"\(parent)\" is ICANN reserved"
                                } else {
                                    parentIssue = "parent \"\(parent)\" is not registered"
                                }
                                break
                            }
                            current = parent
                        }
                    }

                    var result = RPCMethods.formatNameInfo(
                        name: name, nameHash: nameHash,
                        state: state, height: 0, renewal: 0,
                        owner: .null, value: 0, highest: 0
                    )
                    if case .object(var pairs) = result {
                        if let r = restriction {
                            pairs.append(("restriction", .string(r)))
                            pairs.append(("dnssecRequired", .bool(r == "premium" || r == "ICANN reserved")))
                        }
                        if let issue = parentIssue {
                            pairs.append(("parentIssue", .string(issue)))
                        }
                        pairs.append(("minimumBid", .int(minBid)))
                        // Rollout info -- premium/ICANN names and subdomains bypass rollout
                        if restriction == nil && isTLD {
                            let (rolloutHeight, _) = NameRules.getRollout(nameHash: nameHash, params: nameParams)
                            pairs.append(("rolloutHeight", .int(Int64(rolloutHeight))))
                        }
                        result = .object(pairs)
                    }
                    return result
                }
                // Build owner object with all fields consolidated
                let ownerJSON: JSONValue
                if let owner = ns.owner {
                    var ownerPairs: [(String, JSONValue)] = [
                        ("hash", .string(HexEncoding.encode(owner.hash))),
                        ("index", .int(Int64(owner.index))),
                    ]
                    if let coin = chain.getCoin(hash: Hash256(unchecked: owner.hash), index: UInt32(owner.index)) {
                        ownerPairs.append(("address", .string(coin.output.address.toBech32(network: network))))
                        ownerPairs.append(("locked", .int(Int64(coin.output.value))))
                    }
                    ownerJSON = .object(ownerPairs)
                } else {
                    ownerJSON = .null
                }
                // Apply maybeExpire on a copy so the displayed state
                // matches what connectBlock would actually see.
                var effectiveNS = ns
                let didExpire = effectiveNS.maybeExpire(at: chain.storedHeight + 1, params: nameParams)
                let auctionState = ns.state(at: chain.storedHeight, params: nameParams)
                let state: String
                if didExpire {
                    state = "EXPIRED"
                } else if ns.transfer != 0 && auctionState == .closed {
                    state = "TRANSFER"
                } else {
                    state = "\(auctionState)".uppercased()
                }
                var result = RPCMethods.formatNameInfo(
                    name: name, nameHash: nameHash,
                    state: state, height: ns.height, renewal: ns.renewal,
                    owner: ownerJSON, value: ns.value, highest: ns.highest
                )
                if case .object(var pairs) = result {
                    if let r = restriction {
                        pairs.append(("restriction", .string(r)))
                        pairs.append(("dnssecRequired", .bool(r == "premium" || r == "ICANN reserved")))
                    }
                    // Auction timeline (zeroed for genesis-registered names)
                    let isGenesis = ns.registered && ns.height == 0 && ns.value == 0
                    let openEnd = isGenesis ? 0 : ns.height + nameParams.openPeriod
                    let bidEnd = isGenesis ? 0 : openEnd + nameParams.biddingPeriod
                    let revealEnd = isGenesis ? 0 : bidEnd + nameParams.revealPeriod
                    pairs.append(("auction", .object([
                        ("openEnd", .int(Int64(openEnd))),
                        ("biddingEnd", .int(Int64(bidEnd))),
                        ("revealEnd", .int(Int64(revealEnd))),
                    ])))
                    // Expiration height — covers all expiry paths
                    if let expHeight = ns.expirationHeight(params: nameParams) {
                        pairs.append(("expirationHeight", .int(Int64(expHeight))))
                    }
                    pairs.append(("registered", .bool(ns.registered)))
                    pairs.append(("minimumBid", .int(isGenesis ? 0 : minBid)))
                    pairs.append(("auctionSubdomains", .bool(ns.auctionSubdomains)))
                    if ns.parentHash != .zero {
                        pairs.append(("parentHash", .string(ns.parentHash.hex)))
                    }

                    // Progress (0.0–1.0) through the current auction phase
                    let tipHeight = chain.storedHeight
                    let progress: Double
                    if didExpire || state == "EXPIRED" {
                        progress = 1.0
                    } else {
                        switch auctionState {
                        case .opening:
                            let op = nameParams.openPeriod
                            progress = op > 0 ? min(max(Double(tipHeight - ns.height) / Double(op), 0.0), 1.0) : 1.0
                        case .bidding:
                            let bp = nameParams.biddingPeriod
                            progress = bp > 0 ? min(max(Double(tipHeight - openEnd) / Double(bp), 0.0), 1.0) : 1.0
                        case .reveal:
                            let rp = nameParams.revealPeriod
                            progress = rp > 0 ? min(max(Double(tipHeight - bidEnd) / Double(rp), 0.0), 1.0) : 1.0
                        case .closed, .revoked:
                            progress = 1.0
                        }
                    }
                    pairs.append(("progress", .double(progress)))

                    // Current stage as a human-readable string
                    let currentStage: String
                    if didExpire {
                        currentStage = "EXPIRED"
                    } else if ns.transfer != 0 && auctionState == .closed {
                        currentStage = "TRANSFER"
                    } else if ns.revoked != 0 {
                        currentStage = "REVOKED"
                    } else {
                        currentStage = "\(auctionState)".uppercased()
                    }
                    pairs.append(("currentStage", .string(currentStage)))

                    // Pending mempool action for this name
                    if let mp = ctx.mempool {
                        let mempoolTxs = mp.contracts.txsForName(nameHash.asHash256)
                        if !mempoolTxs.isEmpty {
                            var pendingAction: String? = nil
                            outer: for txHash in mempoolTxs {
                                if let entry = mp.map[txHash] {
                                    for output in entry.tx.outputs {
                                        let ct = output.covenant.type
                                        guard ct != .none else { continue }
                                        pendingAction = "\(ct)".uppercased()
                                        break outer
                                    }
                                }
                            }
                            if let action = pendingAction {
                                pairs.append(("pendingAction", .string(action)))
                            }
                        }
                    }

                    // Whether the name can be registered right now
                    let canRegister = auctionState == .closed
                        && !ns.registered
                        && !didExpire
                        && !ns.isExpired(at: tipHeight, params: nameParams)
                        && ns.owner != nil
                    pairs.append(("canRegister", .bool(canRegister)))

                    result = .object(pairs)
                }
                return result
            }

        handlers["getnamebyhash"] = { req in
                let params = req.params
                let chain = try Self.requireChain(ctx)
                guard let hexStr = params.first?.stringValue, hexStr.count == 64 else {
                    throw RPCError.invalidParams("expected 32-byte hex name hash")
                }
                let nameHash = try NameHash.fromHex(hexStr)
                guard let ns = try chain.getNameState(nameHash: nameHash) else {
                    return .null
                }
                guard let name = String(bytes: ns.name, encoding: .utf8) else {
                    return .null
                }
                return .string(name)
            }

        handlers["getnameresource"] = { req in
                let params = req.params
                let chain = try Self.requireChain(ctx)
                guard let name = params.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                let nameParams = NameParams.params(for: network)
                let height = chain.tip.height
                // Try exact name first (TLD or auctioned subdomain)
                if let ns = try chain.getNameState(name: name), ns.registered,
                   ns.revoked == 0, !ns.isExpired(at: height, params: nameParams),
                   !ns.data.isEmpty {
                    let resource = try Resource.decode(from: ns.data)
                    return Self.formatResource(resource)
                }
                // If name has a dot, check parent's SUB records
                if let dotIdx = name.firstIndex(of: ".") {
                    let subLabel = String(name[name.startIndex..<dotIdx])
                    let parent = String(name[name.index(after: dotIdx)...])
                    if let parentNS = try chain.getNameState(name: parent),
                       parentNS.registered, parentNS.revoked == 0,
                       !parentNS.isExpired(at: height, params: nameParams),
                       !parentNS.data.isEmpty {
                        let parentResource = try Resource.decode(from: parentNS.data)
                        if let subRecords = parentResource.subRecords(for: subLabel) {
                            return Self.formatResource(Resource(records: subRecords))
                        }
                    }
                }
                return .null
            }

        // MARK: Name Auctions (send*)

        handlers["sendopen"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                guard NameRules.verifyName(name) else {
                    throw RPCError.invalidParams("invalid name: \(name)")
                }

                let nameHash = NameRules.hashName(name)
                let nameParams = NameParams.params(for: network)

                // Check rollout availability (premium/ICANN names bypass rollout)
                guard NameRules.isAvailable(nameHash: nameHash, height: chain.storedHeight, params: nameParams, rawName: Array(name.utf8)) else {
                    throw RPCError.invalidParams("name not yet available for auction")
                }

                // Check name is not already in auction or registered
                if let ns = try chain.getNameState(name: name) {
                    let st = ns.state(at: chain.storedHeight, params: nameParams)
                    guard st == .closed && ns.isExpired(at: chain.storedHeight, params: nameParams) else {
                        throw RPCError.invalidParams("name already in auction or registered (state: \(st))")
                    }
                }

                let covenant: Covenant
                let addr: Address
                if NameRules.requiresDNSSEC(name) {
                    // Premium or ICANN reserved: require domain param for DNSSEC proof
                    guard rest.count >= 2, let domain = rest[1].stringValue, !domain.isEmpty else {
                        let recvAddr = try wallet.getReceiveAddress()
                        let bech32 = recvAddr.toBech32(network: network)
                        throw RPCError.invalidParams("DNSSEC proof required for \(NameRules.dnssecReason(name)) \"\(name)\"", data: .object([
                            ("type", .string("TXT")),
                            ("name", .string("_fbd")),
                            ("content", .string("fbd=\(name):\(bech32)"))
                        ]))
                    }
                    let proofBytes: [UInt8]
                    do {
                        proofBytes = try DNSSECProber.buildProof(name: name, domain: domain)
                    } catch {
                        let recvAddr = try wallet.getReceiveAddress()
                        let bech32 = recvAddr.toBech32(network: network)
                        throw RPCError.internalError(
                            "\(error)\n\nTo fix: add a TXT record at _fbd.\(domain) with value:\n  fbd=\(name):\(bech32)\n\nThen enable DNSSEC on \(domain) and retry."
                        )
                    }
                    // Extract binding address from proof and verify wallet owns it
                    let binding = try DNSSECProofValidator.validateProof(
                        proofBytes, claimedName: name,
                        blockTime: UInt64(Date().timeIntervalSince1970), gracePeriod: 86_400,
                        expectedAddressHRP: network.addressHRP
                    )
                    let bindingAddr = Address(unchecked: binding.version, hash: binding.hash)
                    guard wallet.ismine(bindingAddr) else {
                        throw RPCError.invalidParams("DNSSEC proof binds to address \(bindingAddr.toBech32(network: network)) which is not in this wallet")
                    }
                    addr = bindingAddr
                    covenant = CovenantData.makePremiumOpen(nameHash: nameHash, name: Array(name.utf8), dnssecProof: proofBytes)
                } else if NameRules.isSubdomain(name) {
                    // Subdomain: compute parent hash and include in covenant
                    guard let parentName = NameRules.parentName(name) else {
                        throw RPCError.invalidParams("cannot extract parent from subdomain name")
                    }
                    let parentHash = NameRules.hashName(parentName)
                    // Verify parent exists and allows subdomains
                    guard let parentNS = try chain.getNameState(name: parentName) else {
                        throw RPCError.invalidParams("parent name \"\(parentName)\" not found")
                    }
                    guard parentNS.auctionSubdomains else {
                        throw RPCError.invalidParams("parent name \"\(parentName)\" does not allow subdomains")
                    }
                    addr = try wallet.getReceiveAddress()
                    covenant = CovenantData.makeSubdomainOpen(nameHash: nameHash, name: Array(name.utf8), parentHash: parentHash)
                } else {
                    addr = try wallet.getReceiveAddress()
                    covenant = CovenantData.makeOpen(nameHash: nameHash, name: Array(name.utf8))
                }
                let tx = try wallet.createCovenantTransaction(
                    covenant: covenant, value: 0, address: addr,
                    currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        handlers["sendbid"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                guard rest.count >= 2, let bidFBD = rest[1].doubleValue, bidFBD >= 0 else {
                    throw RPCError.invalidParams("expected bid amount (FBC)")
                }
                guard rest.count >= 3, let lockupFBD = rest[2].doubleValue, lockupFBD > 0 else {
                    throw RPCError.invalidParams("expected positive lockup amount (FBC)")
                }
                let bid = UInt64(bidFBD * 1_000_000)
                let lockup = UInt64(lockupFBD * 1_000_000)
                guard lockup >= bid else {
                    throw RPCError.invalidParams("lockup must be >= bid")
                }

                let nameHash = NameRules.hashName(name)
                let nameParams = NameParams.params(for: network)

                // Verify name is in BIDDING state
                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found (send open first)")
                }
                let st = ns.state(at: chain.storedHeight, params: nameParams)
                guard st == .bidding else {
                    throw RPCError.invalidParams("name not in bidding state (state: \(st))")
                }

                // Enforce minimum bid
                let minBid = nameParams.minimumBid(atHeight: chain.storedHeight, name: name)
                if minBid > 0 && Int64(bid) < minBid {
                    let minFBC = Double(minBid) / 1_000_000.0
                    throw RPCError.invalidParams("bid too low: minimum is \(minFBC) FBC")
                }

                // Determine bid address and DNSSEC proof (if needed)
                let addr: Address
                var dnssecProof: [UInt8]?
                if NameRules.requiresDNSSEC(name) {
                    guard rest.count >= 4, let domain = rest[3].stringValue, !domain.isEmpty else {
                        let recvAddr = try wallet.getReceiveAddress()
                        let bech32 = recvAddr.toBech32(network: network)
                        throw RPCError.invalidParams("DNSSEC proof required for \(NameRules.dnssecReason(name)) \"\(name)\"", data: .object([
                            ("type", .string("TXT")),
                            ("name", .string("_fbd")),
                            ("content", .string("fbd=\(name):\(bech32)"))
                        ]))
                    }
                    let proofBytes: [UInt8]
                    do {
                        proofBytes = try DNSSECProber.buildProof(name: name, domain: domain)
                    } catch {
                        let recvAddr = try wallet.getReceiveAddress()
                        let bech32 = recvAddr.toBech32(network: network)
                        throw RPCError.internalError(
                            "\(error)\n\nTo fix: add a TXT record at _fbd.\(domain) with value:\n  fbd=\(name):\(bech32)\n\nThen enable DNSSEC on \(domain) and retry."
                        )
                    }
                    let binding = try DNSSECProofValidator.validateProof(
                        proofBytes, claimedName: name,
                        blockTime: UInt64(Date().timeIntervalSince1970), gracePeriod: 86_400,
                        expectedAddressHRP: network.addressHRP
                    )
                    let bindingAddr = Address(unchecked: binding.version, hash: binding.hash)
                    guard wallet.ismine(bindingAddr) else {
                        throw RPCError.invalidParams("DNSSEC proof binds to address \(bindingAddr.toBech32(network: network)) which is not in this wallet")
                    }
                    addr = bindingAddr
                    dnssecProof = proofBytes
                } else {
                    addr = try wallet.getReceiveAddress()
                }

                // Derive deterministic nonce from wallet key + name hash
                guard let nonce = try wallet.deriveNonce(address: addr, nameHash: nameHash) else {
                    throw RPCError.internalError("failed to derive bid nonce")
                }
                let blind = try BlindBid.blind(value: bid, nonce: nonce)

                // Build covenant
                let covenant: Covenant
                if let proof = dnssecProof {
                    covenant = CovenantData.makePremiumBid(
                        nameHash: nameHash, startHeight: ns.height,
                        name: Array(name.utf8), blind: blind, dnssecProof: proof
                    )
                } else if NameRules.isSubdomain(name) {
                    guard let parentName = NameRules.parentName(name) else {
                        throw RPCError.invalidParams("cannot extract parent from subdomain name")
                    }
                    let parentHash = NameRules.hashName(parentName)
                    covenant = CovenantData.makeSubdomainBid(
                        nameHash: nameHash, startHeight: ns.height,
                        name: Array(name.utf8), blind: blind, parentHash: parentHash
                    )
                } else {
                    covenant = CovenantData.makeBid(
                        nameHash: nameHash, startHeight: ns.height,
                        name: Array(name.utf8), blind: blind
                    )
                }
                let tx = try wallet.createCovenantTransaction(
                    covenant: covenant, value: lockup, address: addr,
                    currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                // Save nonce BEFORE broadcasting (critical -- lost nonce = lost funds)
                let bidOutpoint = Outpoint(hash: txHash, index: 0)
                let bidRecord = BidRecord(
                    nameHash: nameHash, outpoint: bidOutpoint,
                    nonce: nonce, value: bid, lockup: lockup
                )
                try wallet.saveBid(bidRecord)

                do {
                    try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                } catch {
                    // Mempool rejected -- remove orphan bid record
                    try? wallet.removeBid(nameHash: bidRecord.nameHash, outpoint: bidRecord.outpoint)
                    throw error
                }
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([
                    ("txid", .string(txHash.hex)),
                    ("name", .string(name)),
                    ("bid", .int(Int64(bid))),
                    ("lockup", .int(Int64(lockup))),
                ])
            }

        handlers["sendreveal"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                let nameParams = NameParams.params(for: network)
                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected: sendreveal <name>")
                }

                let nh = NameRules.hashName(name)
                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                let st = ns.state(at: chain.storedHeight, params: nameParams)
                guard st == .reveal else {
                    throw RPCError.invalidParams("name not in reveal state (state: \(st))")
                }
                let bids = try wallet.getBidsForName(nameHash: nh)
                guard !bids.isEmpty else {
                    throw RPCError.invalidParams("no bids found to reveal for \(name)")
                }

                var txids = [JSONValue]()
                let bidCoins = try wallet.findNameCoins(nameHash: nh, covenantType: .bid)
                for bid in bids {
                    guard let bidCoin = bidCoins.first(where: { $0.outpoint == bid.outpoint }) else { continue }

                    let covenant = CovenantData.makeReveal(
                        nameHash: nh,
                        startHeight: ns.height,
                        nonce: bid.nonce
                    )
                    let addr = try wallet.getReceiveAddress()

                    let tx = try wallet.createCovenantTransaction(
                        covenant: covenant, value: bid.value, address: addr,
                        linkedCoin: bidCoin, currentHeight: chain.storedHeight
                    )
                    let txHash = tx.txHash()

                    try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                    ctx.peerManager?.broadcastTx(txHash: txHash)

                    txids.append(.string(txHash.hex))
                }

                if txids.isEmpty {
                    throw RPCError.invalidParams("no bids found to reveal for \(name)")
                }
                return .object([("txids", .array(txids))])
            }

        handlers["sendredeem"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                let nameParams = NameParams.params(for: network)
                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected: sendredeem <name>")
                }

                let nh = NameRules.hashName(name)
                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                var nsCheck = ns
                nsCheck.maybeExpire(at: chain.storedHeight + 1, params: nameParams)
                let st = nsCheck.state(at: chain.storedHeight, params: nameParams)
                guard st == .closed else {
                    throw RPCError.invalidParams("name auction not closed (state: \(st))")
                }
                guard !nsCheck.isExpired(at: chain.storedHeight + 1, params: nameParams) else {
                    throw RPCError.invalidParams("name has expired — coins are forfeited")
                }

                // Find losing REVEAL UTXOs to redeem
                var revealCoins = [WalletCoin]()
                let coins = try wallet.findNameCoins(nameHash: nh, covenantType: .reveal)
                // Only redeem coins that aren't the winning bid (not the owner)
                for coin in coins {
                    if let owner = ns.owner, coin.outpoint.hash.bytes == owner.hash && coin.outpoint.index == UInt32(owner.index) {
                        continue // Skip winner
                    }
                    revealCoins.append(coin)
                }

                guard !revealCoins.isEmpty else {
                    throw RPCError.invalidParams("no redeemable reveals found")
                }

                var txids = [JSONValue]()
                for coin in revealCoins {
                    guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32 else { continue }
                    // Extract startHeight from covenant item[1]
                    guard coin.covenant.items.count >= 2 else { continue }
                    let heightBytes = coin.covenant.items[1]
                    guard heightBytes.count == 4 else { continue }
                    let startHeight = Int(UInt32(heightBytes[0]) | UInt32(heightBytes[1]) << 8
                        | UInt32(heightBytes[2]) << 16 | UInt32(heightBytes[3]) << 24)

                    let covenant = CovenantData.makeRedeem(nameHash: NameHash(unchecked: nhBytes), startHeight: startHeight)
                    let addr = try wallet.getReceiveAddress()

                    let tx = try wallet.createCovenantTransaction(
                        covenant: covenant, value: 0, address: addr,
                        linkedCoin: coin, currentHeight: chain.storedHeight
                    )
                    let txHash = tx.txHash()

                    try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                    ctx.peerManager?.broadcastTx(txHash: txHash)

                    txids.append(.string(txHash.hex))
                }

                if txids.isEmpty {
                    throw RPCError.invalidParams("no reveals could be redeemed")
                }
                return .object([("txids", .array(txids))])
            }

        handlers["sendregister"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                let nameHash = NameRules.hashName(name)
                let nameParams = NameParams.params(for: network)

                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                // Check expiry on a copy (maybeExpire mutates state)
                var expiryCopy = ns
                let didExpire = expiryCopy.maybeExpire(at: chain.storedHeight + 1, params: nameParams)
                guard !didExpire else {
                    throw RPCError.invalidParams("name has expired")
                }
                let st = ns.state(at: chain.storedHeight, params: nameParams)
                guard st == .closed else {
                    throw RPCError.invalidParams("name auction not closed (state: \(st))")
                }

                // Find our winning REVEAL UTXO
                let revealCoins = try wallet.findNameCoins(nameHash: nameHash, covenantType: .reveal)
                guard let revealCoin = revealCoins.first(where: { coin in
                    guard let owner = ns.owner else { return false }
                    guard coin.outpoint.hash.bytes == owner.hash && coin.outpoint.index == UInt32(owner.index) else { return false }
                    // Must be from the current auction round
                    guard coin.height >= ns.height else { return false }
                    return true
                }) else {
                    throw RPCError.invalidParams("no winning reveal found for name")
                }

                // Parse resource JSON if provided
                var resourceData = [UInt8]()
                if rest.count >= 2 {
                    let resource = Self.parseResourceJSON(rest[1])
                    try Self.validateResource(resource, network: network)
                    resourceData = try resource.encode()
                }

                // Get a recent block hash for renewal proof
                let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                    throw RPCError.internalError("cannot find block for renewal proof")
                }

                let covenant = CovenantData.makeRegister(
                    nameHash: nameHash, startHeight: ns.height,
                    resource: resourceData, blockHash: renewalEntry.hash.bytes
                )
                let addr = try wallet.getReceiveAddress()

                // Registration price: max(second-price, minimum bid)
                let regMinBid = nameParams.minimumBid(atHeight: chain.storedHeight, name: name)
                let regPrice = max(ns.value, regMinBid)

                // Split: 50% burn, remainder to dev fund (TLD) or ancestors+dev (subdomain)
                let burnShare = regPrice * Int64(nameParams.registrationBurnPercent) / 100
                let totalNonBurn = regPrice - burnShare

                let cp = chain.params
                let devFundAddr = CovenantProcessor.resolveDevFundAddress(nameDB: chain.nameDBRef, network: network, consensusParams: cp)

                // REGISTER output value must be 0
                var ops = [WalletDB.CovenantOp]()
                ops.append(WalletDB.CovenantOp(
                    covenant: covenant, value: 0,
                    address: addr, linkedCoin: revealCoin
                ))
                if burnShare > 0 {
                    ops.append(WalletDB.CovenantOp(
                        covenant: Covenant.none, value: UInt64(burnShare),
                        address: .null
                    ))
                }

                if ns.parentHash != .zero {
                    // SLD: 25% to ancestors, 25% to dev fund
                    // All non-burn payments unified per address (mirrors consensus)
                    let parentShare = totalNonBurn / 2
                    var devExtra: Int64 = 0

                    let ancestorHashes = NameRules.ancestorHashes(name)
                    let ancestorCount = ancestorHashes.count
                    var payments: [Address: Int64] = [:]

                    if ancestorCount > 0 && parentShare > 0 {
                        let perAncestor = parentShare / Int64(ancestorCount)
                        var unclaimedParentShare = parentShare

                        for ancestorHash in ancestorHashes {
                            let share = perAncestor
                            guard share > 0 else { continue }

                            if let ancestorNS = try chain.getNameState(nameHash: ancestorHash),
                               let ownerOutpoint = ancestorNS.owner,
                               !ancestorNS.isExpired(at: chain.storedHeight, params: nameParams),
                               let ownerCoin = chain.getCoin(hash: Hash256(unchecked: ownerOutpoint.hash), index: UInt32(ownerOutpoint.index)) {
                                payments[ownerCoin.output.address, default: 0] += share
                                unclaimedParentShare -= share
                            }
                        }
                        devExtra = unclaimedParentShare
                    } else {
                        devExtra = parentShare
                    }

                    let devShare = (totalNonBurn - parentShare) + devExtra
                    if devShare > 0 {
                        payments[devFundAddr, default: 0] += devShare
                    }

                    for (addr, amount) in payments {
                        ops.append(WalletDB.CovenantOp(
                            covenant: Covenant.none, value: UInt64(amount),
                            address: addr
                        ))
                    }
                } else {
                    // TLD: 50% burn (above), 50% dev fund
                    if totalNonBurn > 0 {
                        ops.append(WalletDB.CovenantOp(
                            covenant: Covenant.none, value: UInt64(totalNonBurn),
                            address: devFundAddr
                        ))
                    }
                }

                let tx = try wallet.createBatchCovenantTransaction(
                    ops: ops, currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        handlers["sendupdate"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                guard rest.count >= 2 else {
                    throw RPCError.invalidParams("expected resource JSON")
                }

                let nameHash = NameRules.hashName(name)
                let nameParams = NameParams.params(for: network)

                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                let st = ns.state(at: chain.storedHeight, params: nameParams)
                guard st == .closed else {
                    throw RPCError.invalidParams("name not in closed state (state: \(st))")
                }

                guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                    throw RPCError.invalidParams("no name UTXO found (do you own this name?)")
                }

                let resource = Self.parseResourceJSON(rest[1])
                try Self.validateResource(resource, network: network)
                let resourceData = try resource.encode()

                // Optional flags parameter: {"auctionSubdomains": true/false}
                let covenant: Covenant
                var effectiveFlags = ns.flags
                if rest.count >= 3, case .object(let flagPairs) = rest[2] {
                    let flagDict = Dictionary(flagPairs, uniquingKeysWith: { _, b in b })
                    if let allow = flagDict["auctionSubdomains"]?.boolValue {
                        if allow { effectiveFlags |= 1 } else if !ns.auctionSubdomains { effectiveFlags &= ~1 }
                        else { throw RPCError.invalidParams("auctionSubdomains cannot be disabled once enabled") }
                    }
                }
                // Reject delegation/SUB records when auctionSubdomains is or will be enabled
                if effectiveFlags & 1 != 0 && !resourceData.isEmpty {
                    guard !NameRules.containsDelegationRecords(resourceData) else {
                        throw RPCError.invalidParams("delegation and SUB records are not allowed when subdomain auctions are enabled")
                    }
                }
                if effectiveFlags != ns.flags {
                    covenant = CovenantData.makeUpdate(
                        nameHash: nameHash, startHeight: ns.height,
                        resource: resourceData, flags: effectiveFlags
                    )
                } else {
                    covenant = CovenantData.makeUpdate(
                        nameHash: nameHash, startHeight: ns.height,
                        resource: resourceData
                    )
                }

                let tx = try wallet.createCovenantTransaction(
                    covenant: covenant, value: nameCoin.value, address: nameCoin.address,
                    linkedCoin: nameCoin, currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        handlers["sendrenew"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                let nameHash = NameRules.hashName(name)
                let nameParams = NameParams.params(for: network)
                let cp = ConsensusParams.params(for: network)

                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                let st = ns.state(at: chain.storedHeight, params: nameParams)
                guard st == .closed else {
                    throw RPCError.invalidParams("name not in closed state (state: \(st))")
                }

                guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                    throw RPCError.invalidParams("no name UTXO found (do you own this name?)")
                }

                // Get a recent block hash for renewal proof
                let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                    throw RPCError.internalError("cannot find block for renewal proof")
                }

                let covenant = CovenantData.makeRenew(
                    nameHash: nameHash, startHeight: ns.height,
                    blockHash: renewalEntry.hash.bytes
                )

                // Compute renewal fee: max(1% of registration value, minimum bid)
                let percentFee = ns.value * Int64(nameParams.renewalFeePercent) / 100
                let minFee = nameParams.minimumBid(atHeight: chain.storedHeight, rawName: ns.name)
                let renewalFee = max(percentFee, minFee)

                let devFundAddr = CovenantProcessor.resolveDevFundAddress(nameDB: chain.nameDBRef, network: network, consensusParams: cp)

                var ops = [WalletDB.CovenantOp]()
                ops.append(WalletDB.CovenantOp(
                    covenant: covenant, value: nameCoin.value,
                    address: nameCoin.address, linkedCoin: nameCoin
                ))
                if renewalFee > 0 {
                    if ns.parentHash != .zero {
                        // Subdomain: 50% dev fund, 50% ancestors (no burn)
                        let ancestorShare = renewalFee / 2
                        let devShare = renewalFee - ancestorShare
                        let renewName = String(decoding: ns.name, as: UTF8.self)
                        let ancestorHashes = NameRules.ancestorHashes(renewName)
                        var devExtra: Int64 = 0
                        if !ancestorHashes.isEmpty && ancestorShare > 0 {
                            let perAncestor = ancestorShare / Int64(ancestorHashes.count)
                            var unclaimed = ancestorShare
                            for ancestorHash in ancestorHashes {
                                guard perAncestor > 0 else { continue }
                                if let aNS = try chain.getNameState(nameHash: ancestorHash),
                                   let ownerOP = aNS.owner,
                                   !aNS.isExpired(at: chain.storedHeight, params: nameParams),
                                   let ownerCoin = chain.getCoin(hash: Hash256(unchecked: ownerOP.hash), index: UInt32(ownerOP.index)) {
                                    ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(perAncestor), address: ownerCoin.output.address))
                                    unclaimed -= perAncestor
                                }
                            }
                            devExtra = unclaimed
                        } else {
                            devExtra = ancestorShare
                        }
                        ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(devShare + devExtra), address: devFundAddr))
                    } else {
                        // TLD: all to dev fund
                        ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(renewalFee), address: devFundAddr))
                    }
                }

                let tx = try wallet.createBatchCovenantTransaction(
                    ops: ops, currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        handlers["sendtransfer"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                guard rest.count >= 2, let addrStr = rest[1].stringValue, !addrStr.isEmpty else {
                    throw RPCError.invalidParams("expected destination address")
                }
                let destination = try Address(bech32: addrStr, network: network)

                let nameHash = NameRules.hashName(name)
                let nameParams = NameParams.params(for: network)

                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                let st = ns.state(at: chain.storedHeight, params: nameParams)
                guard st == .closed else {
                    throw RPCError.invalidParams("name not in closed state (state: \(st))")
                }

                guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                    throw RPCError.invalidParams("no name UTXO found (do you own this name?)")
                }

                let covenant = CovenantData.makeTransfer(
                    nameHash: nameHash, startHeight: ns.height,
                    version: destination.version, addressHash: destination.hash
                )
                let addr = try wallet.getReceiveAddress()

                let tx = try wallet.createCovenantTransaction(
                    covenant: covenant, value: nameCoin.value, address: addr,
                    linkedCoin: nameCoin, currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        handlers["sendfinalize"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                let nameHash = NameRules.hashName(name)
                let nameParams = NameParams.params(for: network)

                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }

                // Must have a pending transfer
                guard ns.transfer != 0 else {
                    throw RPCError.invalidParams("no pending transfer for name")
                }

                // Check transfer lockup period
                guard chain.storedHeight >= ns.transfer + nameParams.transferLockup else {
                    let remaining = ns.transfer + nameParams.transferLockup - chain.storedHeight
                    throw RPCError.invalidParams("transfer lockup not met (\(remaining) blocks remaining)")
                }

                // Find the TRANSFER UTXO
                let transferCoins = try wallet.findNameCoins(nameHash: nameHash, covenantType: .transfer)
                guard let transferCoin = transferCoins.first else {
                    throw RPCError.invalidParams("no TRANSFER UTXO found")
                }

                // Extract destination from TRANSFER covenant: items[2]=version, items[3]=addressHash
                guard transferCoin.covenant.items.count >= 4 else {
                    throw RPCError.internalError("malformed TRANSFER covenant")
                }
                let destVersion = transferCoin.covenant.items[2]
                let destHash = transferCoin.covenant.items[3]
                guard destVersion.count == 1 else {
                    throw RPCError.internalError("invalid TRANSFER address version")
                }
                let destAddr = Address(unchecked: destVersion[0], hash: destHash)

                // Get a recent block hash for renewal proof
                let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                    throw RPCError.internalError("cannot find block for renewal proof")
                }

                let flags: UInt8 = ns.flags
                let covenant = CovenantData.makeFinalize(
                    nameHash: nameHash, startHeight: ns.height,
                    name: Array(name.utf8), flags: flags,
                    claimed: 0, renewals: ns.renewals,
                    blockHash: renewalEntry.hash.bytes
                )

                // FINALIZE output goes to the destination address
                let tx = try wallet.createCovenantTransaction(
                    covenant: covenant, value: transferCoin.value, address: destAddr,
                    linkedCoin: transferCoin, currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        handlers["sendrevoke"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected name")
                }
                let nameHash = NameRules.hashName(name)
                let nameParams = NameParams.params(for: network)

                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                let st = ns.state(at: chain.storedHeight, params: nameParams)
                guard st == .closed else {
                    throw RPCError.invalidParams("name not in closed state (state: \(st))")
                }

                guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                    throw RPCError.invalidParams("no name UTXO found (do you own this name?)")
                }

                let covenant = CovenantData.makeRevoke(
                    nameHash: nameHash, startHeight: ns.height
                )

                // REVOKE burns the name -- output value goes to miners (unspendable)
                let tx = try wallet.createCovenantTransaction(
                    covenant: covenant, value: nameCoin.value, address: nameCoin.address,
                    linkedCoin: nameCoin, currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        // MARK: Name Queries

        handlers["getnames"] = { req in
                let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else { throw RPCError.internalError("wallet not initialized") }
                let chain = try Self.requireChain(ctx)
                let nameParams = NameParams.params(for: network)

                let owned = try wallet.getOwnedNames()
                var results = [JSONValue]()
                for (nameHash, coin) in owned {
                    var nameObj: [(String, JSONValue)] = [
                        ("hash", .string(nameHash.hex)),
                    ]
                    var obj: [(String, JSONValue)] = [
                        ("value", .int(Int64(coin.value))),
                        ("covenantType", .string("\(coin.covenant.type)".uppercased())),
                    ]
                    if let ns = try? chain.getNameState(nameHash: nameHash) {
                        var copy = ns
                        let didExpire = copy.maybeExpire(at: chain.storedHeight, params: nameParams)
                        if didExpire { continue }
                        let stateStr = "\(ns.state(at: chain.storedHeight, params: nameParams))".uppercased()
                        if !ns.name.isEmpty {
                            nameObj.append(("string", .string(String(bytes: ns.name, encoding: .utf8) ?? "")))
                        }
                        nameObj.append(("state", .string(stateStr)))
                        nameObj.append(("height", .int(Int64(ns.height))))
                        nameObj.append(("renewal", .int(Int64(ns.renewal))))
                    } else {
                        // No chain state yet -- extract name from covenant data (mempool/pending)
                        let ct = coin.covenant.type
                        if (ct == .open || ct == .bid) && coin.covenant.items.count >= 3 {
                            if let n = String(bytes: coin.covenant.items[2], encoding: .utf8), !n.isEmpty {
                                nameObj.append(("string", .string(n)))
                            }
                        }
                        nameObj.append(("state", .string("PENDING")))
                        nameObj.append(("height", .int(0)))
                        nameObj.append(("renewal", .int(0)))
                    }
                    obj.append(("name", .object(nameObj)))
                    results.append(.object(obj))
                }
                return .array(results)
            }

        handlers["getbids"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else { throw RPCError.internalError("wallet not initialized") }
                let chain = try Self.requireChain(ctx)
                let nameParams = NameParams.params(for: network)

                let allBids: [BidRecord]
                if let name = rest.first?.stringValue, !name.isEmpty {
                    let nh = NameRules.hashName(name)
                    allBids = try wallet.getBidsForName(nameHash: nh)
                } else {
                    allBids = try wallet.getAllBids()
                }

                let allCoins = try wallet.listUnspent()
                let bidCoins = allCoins.filter { $0.covenant.type == .bid }
                let revealCoins = allCoins.filter { $0.covenant.type == .reveal }
                let mp = ctx.mempool

                var results = [JSONValue]()
                for bid in allBids {
                    let hasBidCoin = bidCoins.contains { $0.outpoint == bid.outpoint }
                    let inMempool = mp?.has(bid.outpoint.hash) ?? false
                    // Only match reveal coins from the current auction round
                    let nsHeight = (try? chain.getNameState(nameHash: bid.nameHash))?.height ?? 0
                    let bidNHBytes = bid.nameHash.bytes
                    let hasRevealCoin = revealCoins.contains(where: { coin in
                        guard let nh = coin.covenant.items.first else { return false }
                        return nh == bidNHBytes && coin.height >= nsHeight
                    })

                    // Bid not yet confirmed and not in local mempool -- still show it
                    // (it may be in peers' mempools after a restart)
                    let bidPending = !hasBidCoin && !hasRevealCoin && !inMempool

                    // Skip bids from previous auction rounds.
                    // Only clean up after the register deadline has passed to avoid
                    // accidentally deleting current-round bids.
                    let bidCoin = bidCoins.first { $0.outpoint == bid.outpoint }
                    let coinHeight: Int
                    if let h = bidCoin?.height, h > 0 {
                        coinHeight = h
                    } else if bid.height > 0 {
                        coinHeight = bid.height
                    } else if chain.hasTxIndex, let loc = chain.getTxLocation(txHash: bid.outpoint.hash) {
                        coinHeight = loc.height
                    } else if let ai = ctx.auctionIndex {
                        let nhHex2 = bid.nameHash.hex
                        let txHex2 = bid.outpoint.hash.hex
                        let outIdx2 = Int(bid.outpoint.index)
                        let aiBids = ai.getBids(nameHash: nhHex2)
                        let match = aiBids.first(where: { $0.txHash == txHex2 && $0.outputIndex == outIdx2 })
                        coinHeight = match?.height ?? -1
                    } else {
                        coinHeight = -1
                    }
                    let needsRepair = bid.nonce == .zero && bid.value == 0
                    let bidActive = hasBidCoin || inMempool
                    let isRevealed = hasRevealCoin && !bidActive

                    if let ns = try? chain.getNameState(nameHash: bid.nameHash) {
                        // Skip bids from prior rounds
                        if coinHeight > 0 && coinHeight < ns.height {
                            continue
                        }
                        // If height is unknown and bid is revealed, check auction index
                        // to see if it's from the current round. If not found, skip it.
                        if coinHeight <= 0 && isRevealed {
                            if let ai = ctx.auctionIndex {
                                let nhHex = bid.nameHash.hex
                                let txHex = bid.outpoint.hash.hex
                                let outIdx = Int(bid.outpoint.index)
                                let aiBids = ai.getBids(nameHash: nhHex)
                                let found = aiBids.contains(where: { $0.txHash == txHex && $0.outputIndex == outIdx })
                                if !found { continue }
                            }
                        }
                    }
                    var nameObj: [(String, JSONValue)] = [
                        ("hash", .string(bid.nameHash.hex)),
                    ]
                    var obj: [(String, JSONValue)] = [
                        ("outpoint", .object([
                            ("hash", .string(bid.outpoint.hash.hex)),
                            ("index", .int(Int64(bid.outpoint.index))),
                        ])),
                        ("value", .int(Int64(bid.value))),
                        ("lockup", .int(Int64(bid.lockup))),
                        ("height", .int(Int64(coinHeight))),
                        ("own", .bool(hasBidCoin || hasRevealCoin || inMempool || bidPending)),
                        ("revealed", .bool(isRevealed)),
                        ("needsRepair", .bool(needsRepair)),
                        ("nonce", .string(bid.nonce.hex)),
                    ]
                    if let ns = try? chain.getNameState(nameHash: bid.nameHash) {
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        if !ns.name.isEmpty {
                            nameObj.append(("string", .string(String(bytes: ns.name, encoding: .utf8) ?? "")))
                        }
                        // Report EXPIRED when applicable (matches getnameinfo behavior)
                        var effectiveNS = ns
                        let didExpire = effectiveNS.maybeExpire(at: chain.storedHeight + 1, params: nameParams)
                        if didExpire {
                            nameObj.append(("state", .string("EXPIRED")))
                        } else {
                            nameObj.append(("state", .string("\(st)".uppercased())))
                        }
                        nameObj.append(("registered", .bool(ns.registered)))

                        // Detect forfeited bids
                        var isForfeited = false
                        if isRevealed {
                            let revealCoin = revealCoins.first { coin in
                                guard let nh = coin.covenant.items.first else { return false }
                                return nh == bid.nameHash.bytes && coin.height >= ns.height
                            }
                            if let rc = revealCoin {
                                if !ns.registered && ns.isExpired(at: chain.storedHeight, params: nameParams) {
                                    // Unregistered expired name -- winning reveal is forfeited
                                    if let owner = ns.owner,
                                       rc.outpoint.hash.bytes == owner.hash &&
                                       rc.outpoint.index == UInt32(owner.index) {
                                        isForfeited = true
                                    }
                                }
                            }
                        } else if hasBidCoin && coinHeight > 0 && st == .closed {
                            // Unrevealed bid in closed auction -- reveal window passed
                            isForfeited = true
                        }

                        let bidComplete = !hasBidCoin && !isRevealed && !isForfeited && !inMempool
                        let isRedeemed = bidComplete && !ns.registered
                        obj.append(("forfeited", .bool(isForfeited)))
                        obj.append(("redeemed", .bool(isRedeemed)))
                        obj.append(("registered", .bool(bidComplete && ns.registered)))

                        // Registration eligibility for this bid's name
                        let bidCanRegister = st == .closed
                            && !ns.registered
                            && !ns.isExpired(at: chain.storedHeight, params: nameParams)
                            && ns.owner != nil
                        obj.append(("canRegister", .bool(bidCanRegister)))
                        obj.append(("registerDeadline", .int(Int64(ns.registerDeadlineHeight(params: nameParams)))))
                    } else {
                        // Name not on chain yet -- check mempool, extract name from bid tx
                        let pending = ctx.mempool.map { !$0.contracts.txsForName(bid.nameHash.asHash256).isEmpty } ?? false
                        nameObj.append(("state", .string(pending ? "PENDING" : "UNKNOWN")))
                        nameObj.append(("registered", .bool(false)))
                        // Try to extract name from the bid transaction in mempool
                        if let mp = ctx.mempool, let entry = mp.map[bid.outpoint.hash] {
                            for output in entry.tx.outputs {
                                if output.covenant.type == .bid && output.covenant.items.count >= 3 {
                                    if let n = String(bytes: output.covenant.items[2], encoding: .utf8), !n.isEmpty {
                                        nameObj.append(("string", .string(n)))
                                        break
                                    }
                                }
                            }
                        }
                        obj.append(("forfeited", .bool(false)))
                        obj.append(("redeemed", .bool(false)))
                        obj.append(("canRegister", .bool(false)))
                        obj.append(("registerDeadline", .int(0)))
                    }
                    obj.append(("name", .object(nameObj)))
                    results.append(.object(obj))
                }
                return .array(results)
            }

        handlers["repairbid"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                guard wallet.isUnlocked else {
                    throw RPCError.internalError("wallet is locked; call walletpassphrase first")
                }
                // repairbid <name> [value_fbc]
                // Derives the nonce from the wallet's private key.
                // If value is omitted, brute-forces it (tries whole FBC first, then bumps).
                guard let name = rest.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected: repairbid <name> [value_fbc]")
                }
                let explicitValue: UInt64? = rest.count >= 2 && rest[1].doubleValue != nil
                    ? UInt64((rest[1].doubleValue! * 1_000_000).rounded()) : nil
                let nameHash = NameRules.hashName(name)

                let allCoins = try wallet.listUnspent()
                let bidCoins = allCoins.filter {
                    $0.covenant.type == .bid &&
                    $0.covenant.items.count >= 4 &&
                    $0.covenant.items[0] == nameHash.bytes
                }
                guard !bidCoins.isEmpty else {
                    throw RPCError.invalidParams("no BID coins found for '\(name)' in this wallet")
                }

                var repaired = 0
                var foundValue: UInt64 = 0
                for coin in bidCoins {
                    guard let nonce = try wallet.deriveNonce(address: coin.address, nameHash: nameHash) else {
                        continue
                    }
                    let coinBlind = coin.covenant.items[3]

                    if let value = explicitValue {
                        // User provided exact value
                        let blind = try BlindBid.blind(value: value, nonce: nonce)
                        guard coinBlind == blind else { continue }
                        foundValue = value
                    } else {
                        // Brute-force at multiple granularities.
                        // Tries whole FBC first (~1K iterations), then 0.01 FBC
                        // steps (~100K iterations), then 0.0001 FBC steps (~10M).
                        // Covers all realistic bid amounts without trying every bump.
                        let maxBumps = coin.value
                        var found = false
                        let granularities: [UInt64] = [1_000_000, 10_000, 100, 1]
                        for step in granularities {
                            if found { break }
                            for candidate in stride(from: UInt64(0), through: maxBumps, by: Int(step)) {
                                let blind = try BlindBid.blind(value: candidate, nonce: nonce)
                                if blind == coinBlind {
                                    foundValue = candidate
                                    found = true
                                    break
                                }
                            }
                        }
                        guard found else { continue }
                    }

                    let record = BidRecord(
                        nameHash: nameHash,
                        outpoint: coin.outpoint,
                        nonce: nonce,
                        value: foundValue,
                        lockup: coin.value
                    )
                    try wallet.saveBid(record)
                    repaired += 1
                }
                guard repaired > 0 else {
                    throw RPCError.invalidParams("could not recover bid -- blind hash does not match")
                }
                return .object([
                    ("repaired", .int(Int64(repaired))),
                    ("name", .string(name)),
                    ("value", .int(Int64(foundValue))),
                ])
            }

        // MARK: Auction Index

        handlers["getauctions"] = { req in
                guard let auctionIndex = ctx.auctionIndex else {
                    throw RPCError.internalError("auction index not ready")
                }
                let params = req.params
                // getauctions [state] [count] [offset]
                var stateFilter: AuctionState?
                if let stateStr = params.first?.stringValue, !stateStr.isEmpty {
                    stateFilter = AuctionState(rawValue: stateStr.lowercased())
                    if stateFilter == nil {
                        throw RPCError.invalidParams("invalid state: \(stateStr) (valid: opening, bidding, reveal, closed)")
                    }
                }
                let count = params.count > 1 ? (params[1].intValue.map(Int.init) ?? 100) : 100
                let offset = params.count > 2 ? (params[2].intValue.map(Int.init) ?? 0) : 0

                let entries = auctionIndex.getAuctions(state: stateFilter, count: count, offset: offset)
                let results: [JSONValue] = entries.map { entry in
                    .object([
                        ("name", .object([
                            ("hash", .string(entry.nameHash)),
                            ("string", .string(entry.name)),
                            ("state", .string(entry.state.rawValue)),
                        ])),
                        ("auction", .object([
                            ("height", .int(Int64(entry.openHeight))),
                            ("openEnd", .int(Int64(entry.openEnd))),
                            ("biddingEnd", .int(Int64(entry.biddingEnd))),
                            ("revealEnd", .int(Int64(entry.revealEnd))),
                            ("bidCount", .int(Int64(entry.bidCount))),
                            ("highestRevealed", .int(Int64(entry.highestRevealed))),
                            ("highestLockup", .int(Int64(entry.highestLockup))),
                        ])),
                    ])
                }
                return .array(results)
            }

        handlers["getauctionbids"] = { req in
                guard let auctionIndex = ctx.auctionIndex else {
                    throw RPCError.internalError("auction index not ready")
                }
                let params = req.params
                guard let name = params.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected: getauctionbids <name>")
                }
                // Hash the name to look up bids.
                let nh = NameRules.hashName(name)
                let nhHex = nh.hex
                let bidList = auctionIndex.getBids(nameHash: nhHex)
                let results: [JSONValue] = bidList.map { bid in
                    var obj: [(String, JSONValue)] = [
                        ("name", .object([("hash", .string(bid.nameHash))])),
                        ("txHash", .string(bid.txHash)),
                        ("outputIndex", .int(Int64(bid.outputIndex))),
                        ("height", .int(Int64(bid.height))),
                        ("lockup", .int(Int64(bid.lockup))),
                        ("blindHash", .string(bid.blindHash)),
                        ("address", .string(bid.address)),
                    ]
                    if let v = bid.revealedValue {
                        obj.append(("revealedValue", .int(Int64(v))))
                    }
                    if let h = bid.revealTxHash {
                        obj.append(("revealTxHash", .string(h)))
                    }
                    if let rh = bid.revealHeight {
                        obj.append(("revealHeight", .int(Int64(rh))))
                    }
                    return .object(obj)
                }
                return .array(results)
            }

        // MARK: Resolve Address

        handlers["resolveaddress"] = { req in
                let params = req.params
                let chain = try Self.requireChain(ctx)
                guard let input = params.first?.stringValue, !input.isEmpty else {
                    throw RPCError.invalidParams("expected: resolveaddress <name>")
                }

                let nameParams = NameParams.params(for: network)
                let height = chain.storedHeight

                // Helper: extract WALLET record address from a name's resource data
                func walletAddress(fromName name: String) -> String? {
                    guard let ns = try? chain.getNameState(name: name),
                          ns.registered, ns.revoked == 0,
                          !ns.isExpired(at: height, params: nameParams),
                          !ns.data.isEmpty,
                          let resource = try? Resource.decode(from: ns.data) else {
                        return nil
                    }
                    for record in resource.records {
                        if case .wallet(let addr) = record { return addr }
                    }
                    return nil
                }

                // Helper: get the owner address of a name
                func ownerAddress(forName name: String) -> String? {
                    guard let ns = try? chain.getNameState(name: name),
                          ns.registered, ns.revoked == 0,
                          !ns.isExpired(at: height, params: nameParams),
                          let owner = ns.owner,
                          let coin = chain.getCoin(hash: Hash256(unchecked: owner.hash), index: UInt32(owner.index)) else {
                        return nil
                    }
                    return coin.output.address.toBech32(network: network)
                }

                // 1. Try WALLET record for the exact name
                if let addr = walletAddress(fromName: input) {
                    return .string(addr)
                }

                // 3. If subdomain, try parent's WALLET record via SUB records
                let isSubdomain = input.contains(".")
                if isSubdomain, let dotIdx = input.firstIndex(of: ".") {
                    let subLabel = String(input[input.startIndex..<dotIdx])
                    let parent = String(input[input.index(after: dotIdx)...])

                    // Check parent's SUB records for a WALLET in the subdomain
                    if let parentNS = try? chain.getNameState(name: parent),
                       parentNS.registered, parentNS.revoked == 0,
                       !parentNS.isExpired(at: height, params: nameParams),
                       !parentNS.data.isEmpty,
                       let parentResource = try? Resource.decode(from: parentNS.data),
                       let subRecords = parentResource.subRecords(for: subLabel) {
                        for record in subRecords {
                            if case .wallet(let addr) = record {
                                return .string(addr)
                            }
                        }
                    }
                }

                // 3. Fall back to name owner address
                if let addr = ownerAddress(forName: input) {
                    return .string(addr)
                }

                throw RPCError.invalidParams("could not resolve address for '\(input)'")
            }

        return handlers
    }
}
