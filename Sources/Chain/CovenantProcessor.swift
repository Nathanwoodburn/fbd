import Base
import Protocol
import Consensus
import Covenants

/// Validates and processes name covenants within a block transaction.
public enum CovenantProcessor {

    /// Verify and process all covenants in a transaction.
    ///
    /// For each output with a name covenant, validates the rules and updates
    /// the corresponding NameState in the NameDB.
    public static func processCovenants(
        tx: Transaction,
        txIndex: Int,
        coinView: CoinView,
        nameDB: NameDB,
        height: Int,
        network: NetworkType,
        nameParams: NameParams,
        chain: Chain,
        blockTime: UInt64 = 0,
        consensusParams: ConsensusParams,
        cachedDevFundAddress: Address? = nil
    ) throws {
        let txHash = tx.txHash()

        // Accumulated payment requirements across all REGISTERs in this tx.
        // Validated after all covenants are processed so combined outputs work.
        var deferredPayments: [Address: Int64] = [:]
        var deferredBurn: Int64 = 0

        for (outputIdx, output) in tx.outputs.enumerated() {
            let covenant = output.covenant
            guard covenant.type.isName else { continue }

            let nameHash = try CovenantData.nameHash(from: covenant)

            // Get or create NameState (matches hsd flow)
            var ns = try nameDB.getNameState(nameHash)
            if ns == nil || ns!.height == 0 && ns!.renewal == 0 && ns!.owner == nil
                && ns!.value == 0 && ns!.highest == 0 {
                // Name is null/new — only OPEN can create
                if covenant.type == .open {
                    let rawName = try CovenantData.rawName(from: covenant)
                    var newNS = NameState(nameHash: nameHash, name: rawName)
                    newNS.height = height
                    newNS.renewal = height
                    ns = newNS
                }
            }

            guard var ns = ns else {
                throw CovenantsError.wrongAuctionState("no name state for \(covenant.type)")
            }

            // Check for expiration before processing (matches hsd maybeExpire)
            ns.maybeExpire(at: height, params: nameParams)

            switch covenant.type {
            case .open:
                let state = ns.state(at: height, params: nameParams)
                guard state == .opening else {
                    throw CovenantsError.wrongAuctionState("bad OPEN state")
                }
                guard ns.height == height else {
                    throw CovenantsError.wrongAuctionState("duplicate OPEN")
                }
                let rawName = try CovenantData.rawName(from: covenant)
                // Verify nameHash matches SHA3(rawName) — prevents hash-slot squatting
                let nameStr = String(decoding: rawName, as: UTF8.self)
                let expectedHash = NameRules.hashName(nameStr)
                guard nameHash == expectedHash else {
                    throw CovenantsError.malformedCovenant("nameHash does not match rawName")
                }
                // Validate name characters/structure at consensus level
                guard NameRules.verifyName(nameStr) else {
                    throw CovenantsError.malformedCovenant("invalid name")
                }
                // Premium and ICANN reserved names bypass rollout
                guard NameRules.isAvailable(nameHash: nameHash, height: height, params: nameParams, rawName: rawName) else {
                    throw CovenantsError.nameNotYetAvailable
                }

                // Subdomain validation: parent must exist, be registered, and allow subdomains
                if let parentHash = CovenantData.parentHash(fromOpen: covenant) {
                    guard NameRules.isSubdomain(rawName: rawName) else {
                        throw CovenantsError.malformedCovenant("parentHash on non-subdomain OPEN")
                    }
                    // Verify parentHash matches the expected parent
                    let expectedParent = NameRules.parentName(rawName: rawName)
                    guard let expectedParent = expectedParent else {
                        throw CovenantsError.malformedCovenant("cannot extract parent from name")
                    }
                    let expectedHash = NameRules.hashName(String(decoding: expectedParent, as: UTF8.self))
                    guard parentHash == expectedHash else {
                        throw CovenantsError.malformedCovenant("parentHash does not match parent name")
                    }
                    // Look up parent name state — must exist and have auctionSubdomains.
                    // Parent can be expired (flags preserved through expiration).
                    guard let parentNS = try nameDB.getNameState(parentHash) else {
                        throw CovenantsError.parentNameNotFound
                    }
                    guard parentNS.auctionSubdomains else {
                        throw CovenantsError.parentSubdomainsNotAllowed
                    }
                    // Store parent linkage
                    ns.parentHash = parentHash
                } else if NameRules.isSubdomain(rawName: rawName) {
                    throw CovenantsError.malformedCovenant("subdomain OPEN missing parentHash")
                }

                // DNSSEC: premium and ICANN reserved names require proof
                // For subdomains, DNSSEC only applies to the TLD label
                let tldName = NameRules.tldLabel(String(decoding: rawName, as: UTF8.self))
                if nameParams.requireDNSSEC && !NameRules.isSubdomain(rawName: rawName) && NameRules.requiresDNSSEC(tldName) {
                    let dnssecIdx = NameRules.isSubdomain(rawName: rawName) ? 4 : 3
                    guard covenant.items.count > dnssecIdx else {
                        throw CovenantsError.dnssecProofRequired
                    }
                    let proofBytes = covenant.items[dnssecIdx]
                    let binding = try DNSSECProofValidator.validateProof(
                        proofBytes,
                        claimedName: String(decoding: rawName, as: UTF8.self),
                        blockTime: blockTime,
                        gracePeriod: nameParams.dnssecGracePeriod,
                        expectedAddressHRP: network.addressHRP
                    )
                    // Verify binding address matches output address
                    guard output.address.version == binding.version &&
                          output.address.hash == binding.hash else {
                        throw CovenantsError.addressBindingMismatch
                    }
                }
                // OPEN is validated but doesn't change state beyond the initial set
                nameDB.putNameState(nameHash, ns)

            case .bid:
                let covHeight = try CovenantData.height(from: covenant)
                guard ns.state(at: height, params: nameParams) == .bidding else {
                    throw CovenantsError.wrongAuctionState("name not in bidding state for BID")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("BID covenant height mismatch")
                }
                // Enforce minimum bid
                let minBid = nameParams.minimumBid(atHeight: height, rawName: ns.name)
                if minBid > 0 {
                    guard Int64(output.value) >= minBid else {
                        throw CovenantsError.bidTooLow(minimum: minBid, actual: Int64(output.value))
                    }
                }

                // DNSSEC: premium and ICANN reserved TLDs require proof in item 4
                if nameParams.requireDNSSEC && !NameRules.isSubdomain(rawName: ns.name) && NameRules.requiresDNSSEC(rawName: ns.name) {
                    guard covenant.items.count >= 5 else {
                        throw CovenantsError.dnssecProofRequired
                    }
                    let proofBytes = covenant.items[4]
                    let binding = try DNSSECProofValidator.validateProof(
                        proofBytes,
                        claimedName: String(decoding: ns.name, as: UTF8.self),
                        blockTime: blockTime,
                        gracePeriod: nameParams.dnssecGracePeriod,
                        expectedAddressHRP: network.addressHRP
                    )
                    // Verify binding address matches output address
                    guard output.address.version == binding.version &&
                          output.address.hash == binding.hash else {
                        throw CovenantsError.addressBindingMismatch
                    }
                }
                // BID doesn't update state

            case .reveal:
                let covHeight = try CovenantData.height(from: covenant)
                let nonce = try CovenantData.nonce(from: covenant)

                guard ns.state(at: height, params: nameParams) == .reveal else {
                    throw CovenantsError.wrongAuctionState("name not in reveal state")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("REVEAL covenant height mismatch")
                }

                // Verify blind: matching input must be a BID, and blind must match
                guard outputIdx < tx.inputs.count else {
                    throw CovenantsError.malformedCovenant("REVEAL missing matching input")
                }
                let revealInput = tx.inputs[outputIdx]
                guard let bidCoin = coinView.getEntry(revealInput.prevout) else {
                    throw CovenantsError.malformedCovenant("REVEAL input coin not found")
                }
                guard bidCoin.output.covenant.type == .bid else {
                    throw CovenantsError.invalidStateTransition("REVEAL input must be BID")
                }
                let blind = try CovenantData.blindHash(from: bidCoin.output.covenant)
                let computedBlind = try BlindBid.blind(value: output.value, nonce: nonce)
                guard blind == computedBlind else {
                    throw CovenantsError.malformedCovenant("REVEAL blind mismatch")
                }

                // Vickrey auction: track highest and second-highest
                // owner == nil means first reveal (always becomes highest)
                let bidValue = Int64(output.value)
                if ns.owner == nil || bidValue > ns.highest {
                    ns.value = ns.highest
                    ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                    ns.highest = bidValue
                } else if bidValue > ns.value {
                    ns.value = bidValue
                }

                nameDB.putNameState(nameHash, ns)

            case .redeem:
                let covHeight = try CovenantData.height(from: covenant)
                let st = ns.state(at: height, params: nameParams)
                guard st == .closed || st == .revoked else {
                    throw CovenantsError.wrongAuctionState("name not closed/revoked for REDEEM")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("REDEEM covenant height mismatch")
                }
                // Input must exist at matching index and be a REVEAL
                guard outputIdx < tx.inputs.count else {
                    throw CovenantsError.malformedCovenant("REDEEM missing matching input")
                }
                let redeemInput = tx.inputs[outputIdx]
                guard let redeemInputCoin = coinView.getEntry(redeemInput.prevout) else {
                    throw CovenantsError.malformedCovenant("REDEEM input coin not found")
                }
                guard CovenantVerifier.isValidTransition(from: redeemInputCoin.output.covenant.type, to: .redeem) else {
                    throw CovenantsError.invalidStateTransition("REDEEM input must be REVEAL")
                }
                // REDEEM doesn't update state

            case .register:
                let covHeight = try CovenantData.height(from: covenant)
                let resource = try CovenantData.resource(from: covenant, itemIndex: 2)

                let regState = ns.state(at: height, params: nameParams)
                guard regState == .closed else {
                    let nameStr = String(decoding: ns.name, as: UTF8.self)
                    throw CovenantsError.wrongAuctionState(
                        "\(nameStr) not closed for REGISTER (state=\(regState), height=\(height), nsHeight=\(ns.height), expired=\(ns.expired))")
                }
                guard height <= ns.registerDeadlineHeight(params: nameParams) else {
                    let nameStr = String(decoding: ns.name, as: UTF8.self)
                    throw CovenantsError.wrongAuctionState(
                        "\(nameStr) REGISTER deadline has passed (height=\(height), deadline=\(ns.registerDeadlineHeight(params: nameParams)))")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("REGISTER covenant height mismatch")
                }

                // Matching input must have REVEAL covenant
                guard outputIdx < tx.inputs.count else {
                    throw CovenantsError.malformedCovenant("REGISTER missing matching input")
                }
                let input = tx.inputs[outputIdx]
                guard let coin = coinView.getEntry(input.prevout) else {
                    throw CovenantsError.malformedCovenant("REGISTER input coin not found")
                }
                guard coin.output.covenant.type == .reveal else {
                    throw CovenantsError.invalidStateTransition("REGISTER input must be REVEAL")
                }

                // Must be the owner
                guard let owner = ns.owner, toNameOutpoint(input.prevout) == owner else {
                    throw CovenantsError.wrongAuctionState("only owner can REGISTER")
                }

                // Registration value goes to dev fund (REGISTER output value = 0)
                guard Int64(output.value) == 0 else {
                    throw CovenantsError.valueNotPreserved
                }
                // Registration fee: max(second-price, minimum bid)
                let regMinBid = nameParams.minimumBid(atHeight: height, rawName: ns.name)
                let regPrice = max(ns.value, regMinBid)
                if regPrice > 0 {
                    let burnShare = regPrice * Int64(nameParams.registrationBurnPercent) / 100
                    let totalNonBurn = regPrice - burnShare

                    // Accumulate required payments — validated after all covenants are processed
                    deferredBurn += burnShare

                    if ns.parentHash != .zero {
                        let parentShare = totalNonBurn / 2
                        let devShare = totalNonBurn - parentShare
                        let name = String(decoding: ns.name, as: UTF8.self)
                        let ancestorHashes = NameRules.ancestorHashes(name)
                        let devFundAddr = cachedDevFundAddress ?? resolveDevFundAddress(nameDB: nameDB, network: network, consensusParams: consensusParams)

                        if !ancestorHashes.isEmpty && parentShare > 0 {
                            let perAncestor = parentShare / Int64(ancestorHashes.count)
                            var unclaimed = parentShare
                            for ancestorHash in ancestorHashes {
                                guard perAncestor > 0 else { continue }
                                if let ancestorNS = try nameDB.getNameState(ancestorHash),
                                   let ownerOutpoint = ancestorNS.owner,
                                   !ancestorNS.isExpired(at: height, params: nameParams) {
                                    // Look up ancestor coin from the full UTXO set, not coinView
                                    // (the ancestor's coin isn't an input to this tx)
                                    let ancestorOP = Outpoint(hash: Hash256(unchecked: ownerOutpoint.hash), index: UInt32(ownerOutpoint.index))
                                    let ownerCoin = coinView.getEntry(ancestorOP) ?? chain._getCoin(ancestorOP)
                                    if let coin = ownerCoin {
                                        deferredPayments[coin.output.address, default: 0] += perAncestor
                                        unclaimed -= perAncestor
                                    }
                                }
                            }
                            deferredPayments[devFundAddr, default: 0] += devShare + unclaimed
                        } else {
                            deferredPayments[devFundAddr, default: 0] += totalNonBurn
                        }
                    } else {
                        let devFundAddr = cachedDevFundAddress ?? resolveDevFundAddress(nameDB: nameDB, network: network, consensusParams: consensusParams)
                        deferredPayments[devFundAddr, default: 0] += totalNonBurn
                    }
                }

                let blockHashBytes = try CovenantData.blockHash(from: covenant, itemIndex: 3)
                let renewalHash = Hash256(unchecked: blockHashBytes)
                guard verifyRenewal(hash: renewalHash, height: height, params: nameParams, chain: chain) else {
                    throw CovenantsError.wrongAuctionState("REGISTER invalid renewal block")
                }

                // Apply state before delegation check so flags are current
                ns.registered = true
                ns.value = regPrice
                ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                ns.data = resource
                ns.renewal = height

                // Permanence check + optional flags (item 4)
                if let newFlags = CovenantData.registerFlags(from: covenant) {
                    if ns.auctionSubdomains && (newFlags & 1) == 0 {
                        throw CovenantsError.subdomainFlagPermanent
                    }
                    ns.flags = newFlags
                }

                // Block delegation records on names with auctionSubdomains
                if ns.auctionSubdomains && !resource.isEmpty {
                    guard !NameRules.containsDelegationRecords(resource) else {
                        throw CovenantsError.delegationNotAllowedWithSubdomains
                    }
                }

                nameDB.putNameState(nameHash, ns)

            case .update:
                let covHeight = try CovenantData.height(from: covenant)
                let resource = try CovenantData.resource(from: covenant, itemIndex: 2)

                guard ns.state(at: height, params: nameParams) == .closed else {
                    throw CovenantsError.wrongAuctionState("name not closed for UPDATE")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("UPDATE covenant height mismatch")
                }

                // Owner outpoint + state transition checks
                guard outputIdx < tx.inputs.count else {
                    throw CovenantsError.malformedCovenant("UPDATE missing matching input")
                }
                let input = tx.inputs[outputIdx]
                guard let inputCoin = coinView.getEntry(input.prevout) else {
                    throw CovenantsError.malformedCovenant("UPDATE input coin not found")
                }
                guard CovenantVerifier.isValidTransition(from: inputCoin.output.covenant.type, to: .update) else {
                    throw CovenantsError.invalidStateTransition("UPDATE input must be REGISTER/UPDATE/RENEW/TRANSFER/FINALIZE")
                }
                guard let owner = ns.owner, toNameOutpoint(input.prevout) == owner else {
                    throw CovenantsError.wrongAuctionState("only owner can UPDATE")
                }

                // Output address must match input coin address
                guard output.address == inputCoin.output.address else {
                    throw CovenantsError.wrongAuctionState("UPDATE output address mismatch")
                }

                // Subdomain delegation rules
                if let newFlags = CovenantData.flags(from: covenant) {
                    // auctionSubdomains is permanent — cannot be unset once enabled
                    if ns.auctionSubdomains && (newFlags & 1) == 0 {
                        throw CovenantsError.subdomainFlagPermanent
                    }

                    ns.flags = newFlags
                }

                // Names with auctionSubdomains (including just-enabled) cannot have
                // delegation records. Check the new resource data being written.
                if ns.auctionSubdomains && !resource.isEmpty {
                    guard !NameRules.containsDelegationRecords(resource) else {
                        throw CovenantsError.delegationNotAllowedWithSubdomains
                    }
                }
                ns.data = resource

                ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                ns.transfer = 0

                nameDB.putNameState(nameHash, ns)

            case .renew:
                let covHeight = try CovenantData.height(from: covenant)
                let blockHashBytes = try CovenantData.blockHash(from: covenant, itemIndex: 2)

                guard ns.state(at: height, params: nameParams) == .closed else {
                    throw CovenantsError.wrongAuctionState("name not closed for RENEW")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("RENEW covenant height mismatch")
                }

                // Owner outpoint + state transition checks
                guard outputIdx < tx.inputs.count else {
                    throw CovenantsError.malformedCovenant("RENEW missing matching input")
                }
                let renewInput = tx.inputs[outputIdx]
                guard let renewInputCoin = coinView.getEntry(renewInput.prevout) else {
                    throw CovenantsError.malformedCovenant("RENEW input coin not found")
                }
                guard CovenantVerifier.isValidTransition(from: renewInputCoin.output.covenant.type, to: .renew) else {
                    throw CovenantsError.invalidStateTransition("RENEW input must be REGISTER/UPDATE/RENEW/TRANSFER/FINALIZE")
                }
                guard let renewOwner = ns.owner, toNameOutpoint(renewInput.prevout) == renewOwner else {
                    throw CovenantsError.wrongAuctionState("only owner can RENEW")
                }

                let renewalHash = Hash256(unchecked: blockHashBytes)
                guard verifyRenewal(hash: renewalHash, height: height, params: nameParams, chain: chain) else {
                    throw CovenantsError.wrongAuctionState("RENEW invalid renewal block")
                }

                // Output address must match input coin address
                guard output.address == renewInputCoin.output.address else {
                    throw CovenantsError.wrongAuctionState("RENEW output address mismatch")
                }

                // Renewal fee: percentage of registration value, with minimum floor.
                // Split between dev fund and ancestors (no burn).
                do {
                    let percentFee = ns.value * Int64(nameParams.renewalFeePercent) / 100
                    let minFee = nameParams.minimumBid(atHeight: height, rawName: ns.name)
                    let renewalFee = max(percentFee, minFee)
                    if renewalFee > 0 {
                        let devFundAddr = cachedDevFundAddress ?? resolveDevFundAddress(nameDB: nameDB, network: network, consensusParams: consensusParams)
                        if ns.parentHash != .zero {
                            // Subdomain: 50% dev fund, 50% ancestors
                            let ancestorShare = renewalFee / 2
                            let devShare = renewalFee - ancestorShare
                            let name = String(decoding: ns.name, as: UTF8.self)
                            let ancestorHashes = NameRules.ancestorHashes(name)
                            if !ancestorHashes.isEmpty && ancestorShare > 0 {
                                let perAncestor = ancestorShare / Int64(ancestorHashes.count)
                                var unclaimed = ancestorShare
                                for ancestorHash in ancestorHashes {
                                    guard perAncestor > 0 else { continue }
                                    if let ancestorNS = try nameDB.getNameState(ancestorHash),
                                       let ownerOutpoint = ancestorNS.owner,
                                       !ancestorNS.isExpired(at: height, params: nameParams) {
                                        let ancestorOP = Outpoint(hash: Hash256(unchecked: ownerOutpoint.hash), index: UInt32(ownerOutpoint.index))
                                        let ownerCoin = coinView.getEntry(ancestorOP) ?? chain._getCoin(ancestorOP)
                                        if let coin = ownerCoin {
                                            deferredPayments[coin.output.address, default: 0] += perAncestor
                                            unclaimed -= perAncestor
                                        }
                                    }
                                }
                                deferredPayments[devFundAddr, default: 0] += devShare + unclaimed
                            } else {
                                deferredPayments[devFundAddr, default: 0] += renewalFee
                            }
                        } else {
                            // TLD: all to dev fund
                            deferredPayments[devFundAddr, default: 0] += renewalFee
                        }
                    }
                }

                ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                ns.transfer = 0
                ns.renewal = height
                ns.renewals += 1

                nameDB.putNameState(nameHash, ns)

            case .transfer:
                let covHeight = try CovenantData.height(from: covenant)

                guard ns.state(at: height, params: nameParams) == .closed else {
                    throw CovenantsError.wrongAuctionState("name not closed for TRANSFER")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("TRANSFER covenant height mismatch")
                }

                // Owner outpoint + state transition checks
                guard outputIdx < tx.inputs.count else {
                    throw CovenantsError.malformedCovenant("TRANSFER missing matching input")
                }
                let transferInput = tx.inputs[outputIdx]
                guard let transferInputCoin = coinView.getEntry(transferInput.prevout) else {
                    throw CovenantsError.malformedCovenant("TRANSFER input coin not found")
                }
                guard CovenantVerifier.isValidTransition(from: transferInputCoin.output.covenant.type, to: .transfer) else {
                    throw CovenantsError.invalidStateTransition("TRANSFER input must be REGISTER/UPDATE/RENEW/FINALIZE")
                }
                guard let transferOwner = ns.owner, toNameOutpoint(transferInput.prevout) == transferOwner else {
                    throw CovenantsError.wrongAuctionState("only owner can TRANSFER")
                }

                ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                ns.transfer = height

                nameDB.putNameState(nameHash, ns)

            case .finalize:
                let covHeight = try CovenantData.height(from: covenant)
                let blockHashBytes = try CovenantData.blockHash(from: covenant, itemIndex: 6)

                guard ns.state(at: height, params: nameParams) == .closed else {
                    throw CovenantsError.wrongAuctionState("name not closed for FINALIZE")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("FINALIZE covenant height mismatch")
                }

                // Owner outpoint + state transition checks
                guard outputIdx < tx.inputs.count else {
                    throw CovenantsError.malformedCovenant("FINALIZE missing matching input")
                }
                let finalizeInput = tx.inputs[outputIdx]
                guard let finalizeInputCoin = coinView.getEntry(finalizeInput.prevout) else {
                    throw CovenantsError.malformedCovenant("FINALIZE input coin not found")
                }
                guard CovenantVerifier.isValidTransition(from: finalizeInputCoin.output.covenant.type, to: .finalize) else {
                    throw CovenantsError.invalidStateTransition("FINALIZE input must be TRANSFER")
                }
                guard let finalizeOwner = ns.owner, toNameOutpoint(finalizeInput.prevout) == finalizeOwner else {
                    throw CovenantsError.wrongAuctionState("only owner can FINALIZE")
                }

                guard ns.transfer != 0 else {
                    throw CovenantsError.transferLockupNotMet
                }
                guard height >= ns.transfer + nameParams.transferLockup else {
                    throw CovenantsError.transferLockupNotMet
                }

                let renewalHash = Hash256(unchecked: blockHashBytes)
                guard verifyRenewal(hash: renewalHash, height: height, params: nameParams, chain: chain) else {
                    throw CovenantsError.wrongAuctionState("FINALIZE invalid renewal block")
                }

                // Verify output address matches the TRANSFER covenant's target
                let transferCov = finalizeInputCoin.output.covenant
                guard transferCov.items.count >= 4 else {
                    throw CovenantsError.malformedCovenant("TRANSFER covenant missing address fields")
                }
                let targetVersion = transferCov.items[2]
                let targetHash = transferCov.items[3]
                guard targetVersion.count == 1,
                      output.address.version == targetVersion[0],
                      output.address.hash == targetHash else {
                    throw CovenantsError.wrongAuctionState("FINALIZE output address must match TRANSFER target")
                }

                ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                ns.transfer = 0
                // FINALIZE does NOT reset the renewal clock — only RENEW does.
                // This prevents free renewals via self-transfers.

                nameDB.putNameState(nameHash, ns)

            case .revoke:
                let covHeight = try CovenantData.height(from: covenant)

                guard ns.state(at: height, params: nameParams) == .closed else {
                    throw CovenantsError.wrongAuctionState("name not closed for REVOKE")
                }
                guard covHeight == ns.height else {
                    throw CovenantsError.wrongAuctionState("REVOKE covenant height mismatch")
                }

                // Owner outpoint + state transition checks
                guard outputIdx < tx.inputs.count else {
                    throw CovenantsError.malformedCovenant("REVOKE missing matching input")
                }
                let revokeInput = tx.inputs[outputIdx]
                guard let revokeInputCoin = coinView.getEntry(revokeInput.prevout) else {
                    throw CovenantsError.malformedCovenant("REVOKE input coin not found")
                }
                guard CovenantVerifier.isValidTransition(from: revokeInputCoin.output.covenant.type, to: .revoke) else {
                    throw CovenantsError.invalidStateTransition("REVOKE input must be REGISTER/UPDATE/RENEW/TRANSFER/FINALIZE")
                }
                guard let revokeOwner = ns.owner, toNameOutpoint(revokeInput.prevout) == revokeOwner else {
                    throw CovenantsError.wrongAuctionState("only owner can REVOKE")
                }

                // Output address must match input coin address
                guard output.address == revokeInputCoin.output.address else {
                    throw CovenantsError.wrongAuctionState("REVOKE output address mismatch")
                }

                ns.revoked = height
                ns.transfer = 0
                ns.data = []

                nameDB.putNameState(nameHash, ns)

            case .none:
                break
            }
        }

        // Validate deferred payment requirements (accumulated across all REGISTERs).
        // Sum available outputs per address, then check each requirement is met.
        if !deferredPayments.isEmpty || deferredBurn > 0 {
            // Sum all non-covenant outputs by address
            var availableByAddress: [Address: Int64] = [:]
            for output in tx.outputs where output.covenant.type == .none {
                availableByAddress[output.address, default: 0] += Int64(output.value)
            }

            // Check burn (null address)
            if deferredBurn > 0 {
                let available = availableByAddress[.null] ?? 0
                guard available >= deferredBurn else {
                    throw CovenantsError.burnPaymentInsufficient
                }
            }

            // Check each required payment address
            for (addr, required) in deferredPayments {
                guard required > 0 else { continue }
                let available = availableByAddress[addr] ?? 0
                guard available >= required else {
                    throw CovenantsError.devFundPaymentInsufficient(
                        "need \(required) to \(addr.toBech32(network: network)), have \(available)"
                    )
                }
            }
        }
    }

    // MARK: - Replay (state-only, no validation)

    /// Replay covenant state updates for a block without input coin validation.
    ///
    /// Used during startup to rebuild the Urkel tree from stored blocks.
    /// Trusts that blocks are valid (already verified by PoW) and only
    /// applies state changes based on output covenants.
    public static func replayCovenants(
        block: Block,
        nameDB: NameDB,
        height: Int,
        nameParams: NameParams
    ) throws {
        for (_, tx) in block.transactions.enumerated() {
            let txHash = tx.txHash()
            for (outputIdx, output) in tx.outputs.enumerated() {
                let covenant = output.covenant
                guard covenant.type.isName else { continue }

                let nameHash = try CovenantData.nameHash(from: covenant)

                // Get or create NameState (matches hsd flow)
                var ns: NameState
                if let existing = try nameDB.getNameState(nameHash) {
                    ns = existing
                } else if covenant.type == .open {
                    let rawName = try CovenantData.rawName(from: covenant)
                    ns = NameState(nameHash: nameHash, name: rawName)
                    ns.height = height
                    ns.renewal = height
                } else {
                    ns = NameState(nameHash: nameHash)
                }

                // Check for expiration (matches hsd maybeExpire)
                ns.maybeExpire(at: height, params: nameParams)

                switch covenant.type {
                case .open:
                    // Store parent linkage for subdomains
                    if let parentHash = CovenantData.parentHash(fromOpen: covenant) {
                        ns.parentHash = parentHash
                    }
                    nameDB.putNameState(nameHash, ns)

                case .bid:
                    break // No state change

                case .reveal:
                    let bidValue = Int64(output.value)
                    if ns.owner == nil || bidValue > ns.highest {
                        ns.value = ns.highest
                        ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                        ns.highest = bidValue
                    } else if bidValue > ns.value {
                        ns.value = bidValue
                    }
                    nameDB.putNameState(nameHash, ns)

                case .redeem:
                    break // No state change

                case .register:
                    let resource = try CovenantData.resource(from: covenant, itemIndex: 2)
                    let replayMinBid = nameParams.minimumBid(atHeight: height, rawName: ns.name)
                    ns.registered = true
                    ns.value = max(ns.value, replayMinBid)
                    ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                    ns.data = resource
                    ns.renewal = height
                    if let newFlags = CovenantData.registerFlags(from: covenant) {
                        ns.flags = newFlags
                    }
                    nameDB.putNameState(nameHash, ns)

                case .update:
                    let resource = try CovenantData.resource(from: covenant, itemIndex: 2)
                    if let newFlags = CovenantData.flags(from: covenant) {
                        ns.flags = newFlags
                    }
                    ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                    ns.data = resource
                    ns.transfer = 0
                    nameDB.putNameState(nameHash, ns)

                case .renew:
                    ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                    ns.transfer = 0
                    ns.renewal = height
                    ns.renewals += 1
                    nameDB.putNameState(nameHash, ns)

                case .transfer:
                    ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                    ns.transfer = height
                    nameDB.putNameState(nameHash, ns)

                case .finalize:
                    ns.owner = toNameOutpoint(txHash, UInt32(outputIdx))
                    ns.transfer = 0
                    nameDB.putNameState(nameHash, ns)

                case .revoke:
                    ns.revoked = height
                    ns.transfer = 0
                    ns.data = []
                    nameDB.putNameState(nameHash, ns)

                case .none:
                    break
                }
            }
        }
    }

    // MARK: - Helpers

    /// Verify that a renewal block hash references a valid, mature block on the main chain.
    public static func verifyRenewal(hash: Hash256, height: Int, params: NameParams, chain: Chain) -> Bool {
        // Early chain: skip renewal verification
        if height < params.renewalMaturity {
            return true
        }

        // Block must exist on the main chain
        guard let entry = chain._getEntry(hash: hash) else {
            return false
        }

        // Must be on the main chain (not a fork)
        guard chain._getEntryByHeight(entry.height)?.hash == hash else {
            return false
        }

        // Block age must be within [renewalMaturity, renewalPeriod]
        let age = height - entry.height
        return age >= params.renewalMaturity && age <= params.renewalPeriod
    }

    /// Convert a tx hash + output index to a NameState.Outpoint.
    private static func toNameOutpoint(_ txHash: Hash256, _ index: UInt32) -> NameState.Outpoint {
        NameState.Outpoint(hash: txHash.bytes, index: Int(index))
    }

    /// Convert an Protocol.Outpoint to a NameState.Outpoint.
    private static func toNameOutpoint(_ op: Outpoint) -> NameState.Outpoint {
        NameState.Outpoint(hash: op.hash.bytes, index: Int(op.index))
    }

    /// Resolve the dev fund address.
    ///
    /// Checks `_devfund.fistbump` for a WALLET record. If found, decodes the
    /// bech32 address and returns it. Otherwise falls back to the hardcoded
    /// address in consensus params.
    public static func resolveDevFundAddress(
        nameDB: NameDB,
        network: NetworkType,
        consensusParams cp: ConsensusParams
    ) -> Address {
        let fallback = Address(unchecked: cp.devFundVersion, hash: cp.devFundAddress)

        // Look up the "fistbump" TLD
        let fistbumpHash = NameRules.hashName("fistbump")
        guard let fistbumpNS = try? nameDB.getNameState(fistbumpHash),
              fistbumpNS.registered,
              !fistbumpNS.data.isEmpty else {
            return fallback
        }

        // Find WALLET address in _devfund SUB record by scanning raw bytes.
        // Resource format: [version:1] [records...] where each record is [type:1][data...]
        // SUB(13): [nameLen:1][name][count:1][nested records...]
        // WALLET(14): [len:1][address bytes...]
        guard let walletAddr = findDevFundWallet(in: fistbumpNS.data) else {
            return fallback
        }

        // Decode the bech32 address
        guard let addr = try? Address(bech32: walletAddr, network: network) else {
            return fallback
        }
        return addr
    }

    /// Scan raw resource data for a WALLET record inside a `_devfund` SUB record.
    private static func findDevFundWallet(in data: [UInt8]) -> String? {
        guard data.count >= 2, data[0] == 0 else { return nil } // version check
        var pos = 1
        var outerRecords = 0
        let maxRecords = 64 // cap to prevent CPU amplification from crafted resource data

        while pos < data.count && outerRecords < maxRecords {
            outerRecords += 1
            let recordType = data[pos]; pos += 1

            if recordType == 13 { // SUB
                guard pos < data.count else { return nil }
                let nameLen = Int(data[pos]); pos += 1
                guard pos + nameLen < data.count else { return nil }
                let name = String(decoding: data[pos..<(pos + nameLen)], as: UTF8.self)
                pos += nameLen
                guard pos < data.count else { return nil }
                let count = Int(data[pos]); pos += 1

                if name.lowercased() == "_devfund" {
                    // Scan nested records for WALLET(14)
                    for _ in 0..<count {
                        guard pos < data.count else { return nil }
                        let nestedType = data[pos]; pos += 1
                        if nestedType == 14 { // WALLET
                            guard pos < data.count else { return nil }
                            let len = Int(data[pos]); pos += 1
                            guard pos + len <= data.count else { return nil }
                            return String(decoding: data[pos..<(pos + len)], as: UTF8.self)
                        }
                        // Skip other nested record types
                        pos = skipRecord(type: nestedType, in: data, at: pos)
                        guard pos <= data.count else { return nil }
                    }
                    return nil // _devfund found but no WALLET
                } else {
                    // Skip nested records of non-matching SUB
                    for _ in 0..<count {
                        guard pos < data.count else { return nil }
                        let nt = data[pos]; pos += 1
                        pos = skipRecord(type: nt, in: data, at: pos)
                        guard pos <= data.count else { return nil }
                    }
                }
                continue
            }

            // Skip non-SUB records
            pos = skipRecord(type: recordType, in: data, at: pos)
            guard pos <= data.count else { return nil }
        }
        return nil
    }

    /// Skip past a record's data given its type byte. Returns new position.
    private static func skipRecord(type: UInt8, in data: [UInt8], at start: Int) -> Int {
        var pos = start
        switch type {
        case 0: // DS: keyTag(2) + algo(1) + digestType(1) + digestLen(1) + digest(N)
            guard pos + 5 <= data.count else { return data.count + 1 }
            let digestLen = Int(data[pos + 4])
            pos += 5 + digestLen
        case 1: // NS: DNS name
            pos = skipDNSName(data, pos)
        case 2: // GLUE4: DNS name + 4 bytes
            pos = skipDNSName(data, pos) + 4
        case 3: // GLUE6: DNS name + 16 bytes
            pos = skipDNSName(data, pos) + 16
        case 4: pos += 4   // SYNTH4
        case 5: pos += 16  // SYNTH6
        case 6: // TXT: count(1) + count*(len(1) + data(N))
            guard pos < data.count else { return data.count + 1 }
            let count = Int(data[pos]); pos += 1
            for _ in 0..<count {
                guard pos < data.count else { return data.count + 1 }
                let len = Int(data[pos]); pos += 1; pos += len
            }
        case 7:  pos += 4   // A
        case 8:  pos += 16  // AAAA
        case 9:  pos = skipDNSName(data, pos) // CNAME
        case 10: pos = skipDNSName(data, pos + 2) // MX: preference(2) + name
        case 11: // TLSA: port(2) + proto(1) + usage(1) + selector(1) + matchingType(1) + certLen(2) + cert(N)
            guard pos + 8 <= data.count else { return data.count + 1 }
            let certLen = Int(data[pos + 6]) << 8 | Int(data[pos + 7])
            pos += 8 + certLen
        case 12: // CAA: flags(1) + tagLen(1) + tag(N) + valueLen(2) + value(N)
            guard pos + 2 <= data.count else { return data.count + 1 }
            let tagLen = Int(data[pos + 1])
            pos += 2 + tagLen
            guard pos + 2 <= data.count else { return data.count + 1 }
            let valueLen = Int(data[pos]) << 8 | Int(data[pos + 1])
            pos += 2 + valueLen
        case 14: // WALLET: len(1) + address(N)
            guard pos < data.count else { return data.count + 1 }
            let len = Int(data[pos]); pos += 1; pos += len
        default:
            return data.count + 1 // unknown type, bail
        }
        return pos
    }

    /// Skip past a DNS-encoded name. Returns new position.
    private static func skipDNSName(_ data: [UInt8], _ start: Int) -> Int {
        var pos = start
        while pos < data.count {
            let c = data[pos]
            if c == 0 { return pos + 1 }
            if c & 0xC0 == 0xC0 { return pos + 2 }
            pos += 1 + Int(c)
        }
        return pos
    }
}
