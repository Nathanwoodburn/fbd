import Foundation
import Base
import Protocol
import Consensus
import ExtCrypto
import Script
import Covenants
import Urkel
import Storage

// MARK: - Block Validation & Connection

extension Chain {

    /// Internal unlocked connectBlock implementation.
    ///
    /// Performs all validation and UTXO work. Returns without firing callbacks.
    func _connectBlock(_ block: Block, height: Int) throws {
        // Verify header matches expected chain entry
        guard let entry = _getEntryByHeight(height) else {
            throw HeaderError.headerMismatch
        }

        guard block.header.prevBlock == entry.prevBlock
                && block.header.merkleRoot == entry.merkleRoot
                && block.header.nonce == entry.nonce
                && block.header.time == entry.time
                && block.header.bits == entry.bits else {
            throw HeaderError.headerMismatch
        }

        // Body checks (coinbase position, weight, tx sanity)
        try BlockValidator.checkBody(block)

        // Block-level covenant sanity check
        for tx in block.transactions {
            for output in tx.outputs {
                try CovenantVerifier.checkCovenantSanity(output.covenant)
            }
        }

        // Block-level sigops check
        var blockSigops: Int = 0
        for tx in block.transactions {
            for witness in tx.witnesses {
                let items = witness.items
                if items.isEmpty { continue }
                if items.count > 2, let ws = items.last {
                    let s = Script(ws)
                    blockSigops += s.sigops
                } else {
                    blockSigops += 1
                }
            }
        }
        guard blockSigops <= Constants.maxBlockSigops else {
            throw ConsensusError.tooManySigops
        }

        // Skip merkle/witness validation for genesis — it's hardcoded.
        if height > 0 {
            // Verify merkle root
            let txHashes = block.transactions.map { $0.txHash() }
            let computedMerkle = try MerkleTree.computeRoot(txHashes)
            if computedMerkle != block.header.merkleRoot {
                throw HeaderError.invalidMerkleRoot(
                    height: height,
                    expected: block.header.merkleRoot.hex,
                    computed: computedMerkle.hex,
                    txCount: block.transactions.count,
                    tx0Hash: txHashes.first?.hex ?? "none"
                )
            }

            // Verify witness root (reuse txHashes to avoid double serialization)
            let computedWitness = try MerkleTree.computeWitnessRoot(block.transactions, txHashes: txHashes)
            guard computedWitness == block.header.witnessRoot else {
                throw HeaderError.invalidWitnessRoot
            }
        }

        // Track undo coins for address indexing (populated during UTXO validation)
        var undoCoins: [CoinEntry] = []

        // Genesis: just add outputs to UTXO set without validation
        if let coinDB = coinDB, height == 0 {
            var view = CoinView()
            for tx in block.transactions {
                view.addTX(tx, height: 0)
            }
            try coinDB.saveView(view, height: 0, hash: entry.hash)

            // Register genesis names in the name database
            if let nameDB = nameDB {
                // Build nameHash → name lookup for genesis names
                var genesisNames = ["fistbump"]
                for char in "abcdefghijklmnopqrstuvwxyz0123456789" {
                    genesisNames.append(String(char))
                }
                var hashToName = [[UInt8]: [UInt8]]()
                for name in genesisNames {
                    let h = NameRules.hashName(name)
                    hashToName[h.bytes] = Array(name.utf8)
                }

                let cb = block.transactions[0]
                let txHash = cb.txHash()
                for (outputIdx, output) in cb.outputs.enumerated() {
                    if output.covenant.type == .register {
                        let nameHashBytes = output.covenant.items[0]
                        let nameHash = NameHash(unchecked: nameHashBytes)
                        let resource = output.covenant.items.count > 2 ? output.covenant.items[2] : []
                        let nameBytes = hashToName[nameHashBytes] ?? nameHashBytes
                        var ns = NameState()
                        ns.name = nameBytes
                        ns.nameHash = nameHash
                        ns.height = 0
                        ns.renewal = 0
                        ns.registered = true
                        ns.owner = NameState.Outpoint(hash: txHash.bytes, index: outputIdx)
                        ns.data = resource
                        ns.value = 0
                        ns.highest = 0
                        // Process flags from REGISTER covenant (e.g. auctionSubdomains)
                        if let flags = CovenantData.registerFlags(from: output.covenant) {
                            ns.flags = flags
                        }
                        nameDB.putNameState(nameHash, ns)
                    }
                }
                try nameDB.commit(height: 0)
            }
        }

        // Validate coinbase height commitment (BIP34-style)
        if height > 0 {
            let coinbaseTx = block.transactions[0]
            guard !coinbaseTx.witnesses.isEmpty,
                  !coinbaseTx.witnesses[0].items.isEmpty else {
                throw ConsensusError.invalidCoinbaseHeight
            }
            let heightBytes = coinbaseTx.witnesses[0].items[0]
            // Decode minimal-length LE height (inverse of CoinbaseBuilder.heightCommitment)
            var committedHeight = 0
            for i in 0..<heightBytes.count {
                committedHeight |= Int(heightBytes[i]) << (i * 8)
            }
            if heightBytes.last.map({ $0 & 0x80 != 0 }) == true { committedHeight = -1 }
            guard committedHeight == height else {
                throw ConsensusError.invalidCoinbaseHeight
            }
        }

        // Contextual UTXO validation (height > 0)
        if let coinDB = coinDB, height > 0 {
            var view = CoinView()
            var totalFees: Int64 = 0

            for (i, tx) in block.transactions.enumerated() {
                if i > 0 {
                    // Load input coins into view (check view first for intra-block spends, then DB)
                    for input in tx.inputs {
                        if view.getEntry(input.prevout) == nil {
                            guard let coin = coinDB.getCoin(input.prevout) else {
                                throw ChainError.missingCoin("height \(height) tx \(i)")
                            }
                            view.addEntry(input.prevout, coin)
                        }
                    }

                    // Check coinbase maturity
                    for input in tx.inputs {
                        if let coin = view.getEntry(input.prevout), coin.coinbase {
                            try BlockValidator.checkCoinbaseMaturity(
                                coinbaseHeight: coin.height,
                                spendHeight: height,
                                params: params
                            )
                        }
                    }

                    // Verify witness/script for each input (skip for assumevalid)
                    if height > params.assumeValidHeight {
                        for (inputIdx, input) in tx.inputs.enumerated() {
                            guard let coin = view.getEntry(input.prevout) else {
                                throw ChainError.missingCoin("height \(height) tx \(i) input \(inputIdx)")
                            }
                            try WitnessVerifier.verify(
                                tx: tx,
                                index: inputIdx,
                                address: coin.output.address,
                                value: coin.output.value,
                                flags: .mandatory
                            )
                        }
                    }

                    // Verify inputs cover outputs (must check before spend marks them)
                    guard let fee = view.getFee(tx), fee >= 0 else {
                        throw ChainError.inputValueBelowOutput
                    }
                    let (newTotal, feeOverflow) = totalFees.addingReportingOverflow(fee)
                    guard !feeOverflow else {
                        throw ChainError.inputValueBelowOutput
                    }
                    totalFees = newTotal

                    // Spend inputs (marks spent in view, pushes to undo)
                    guard view.spendInputs(tx) else {
                        throw ChainError.missingCoin("height \(height) tx \(i) spend failed")
                    }
                }

                // Add outputs to view (both coinbase and regular)
                view.addTX(tx, height: height)
            }

            // Verify coinbase value: miner reward must not exceed subsidy + fees.
            let coinbaseTx = block.transactions[0]
            try BlockValidator.checkCoinbaseValue(
                coinbaseTx, height: height, fees: totalFees, params: params
            )

            // Covenant validation: verify tree root then process name covenants
            if let nameDB = nameDB {
                // Tree root check BEFORE processing this block's covenants:
                // the block's treeRoot commits to state prior to this block.
                let currentRoot = try nameDB.treeRoot()
                let expectedRoot = entry.treeRoot.bytes
                guard currentRoot == expectedRoot else {
                    throw ChainError.invalidTreeRoot(
                        height: height,
                        expected: entry.treeRoot.hex,
                        computed: HexEncoding.encode(currentRoot)
                    )
                }

                // Snapshot the pending map so we can roll back if any
                // covenant fails — otherwise successful putNameState calls
                // from earlier transactions leak into future mining attempts.
                let pendingSnapshot = nameDB.snapshotPending()
                do {
                    // Use MTP instead of block.header.time for DNSSEC validation
                    // to prevent miners from manipulating the timestamp window.
                    let covenantTime = _medianTimePast(for: entry)
                    // Resolve the dev fund address once from committed state before
                    // processing any transactions, so intra-block name updates
                    // cannot redirect registration fees mid-block.
                    let devFundAddr = CovenantProcessor.resolveDevFundAddress(
                        nameDB: nameDB, network: network, consensusParams: params
                    )
                    for (i, tx) in block.transactions.enumerated() {
                        try CovenantProcessor.processCovenants(
                            tx: tx, txIndex: i, coinView: view, nameDB: nameDB,
                            height: height, network: network, nameParams: nameParams,
                            chain: self,
                            blockTime: covenantTime, consensusParams: params,
                            cachedDevFundAddress: devFundAddr
                        )
                    }
                } catch {
                    nameDB.restorePending(pendingSnapshot)
                    throw error
                }

                // Commit tree every treeInterval blocks
                if height % nameParams.treeInterval == 0 {
                    try nameDB.commit(height: height)
                }
            }

            // Capture undo coins for address indexing before persist
            undoCoins = view.undo

            // Persist: coins + undo + state (single atomic write)
            try coinDB.saveView(view, height: height, hash: entry.hash)
        }

        // Store to disk (skip if already stored, e.g. during reindex)
        if let blockStore = blockStore, !blockStore.hasBlock(height: height) {
            try blockStore.storeBlock(block, height: height)
        }

        // Update transaction index
        if txIndexStore != nil {
            for (i, tx) in block.transactions.enumerated() {
                putTxIndex(txHash: tx.txHash(), height: height, txIndex: i)
            }
        }

        // Update address index
        if addrIndexStore != nil {
            indexAddresses(block: block, height: height, undoCoins: undoCoins)
        }
    }

    /// Validate and store a full block at the given height.
    ///
    /// Performs structural validation:
    /// 1. Verify header matches the chain entry at this height
    /// 2. Check block body (coinbase, weight, tx sanity)
    /// 3. Compute and verify merkle root
    /// 4. Compute and verify witness root
    /// 5. Store block to disk
    ///
    /// Releases the lock before firing the onBlockConnected callback to avoid
    /// deadlocks when the callback reads chain state.
    public func connectBlock(_ block: Block, height: Int) throws {
        lock.lock()
        do {
            try _connectBlock(block, height: height)
        } catch {
            lock.unlock()
            throw error
        }
        let callback = onBlockConnected
        lock.unlock()
        callback?(block, height)
    }

    /// Trial-validate transactions against current chain state.
    ///
    /// Runs processCovenants on each transaction individually to check for
    /// covenant violations (missing payments, wrong state, etc.). Returns
    /// the tx hashes of any that fail. State is rolled back after each test.
    ///
    /// Used by the miner to pre-validate the block template before mining.
    public func validateTransactions(_ txs: [Transaction], height: Int, blockTime: UInt64) -> Set<Hash256> {
        lock.lock()
        defer { lock.unlock() }
        guard let nameDB = nameDB, let coinDB = coinDB else { return [] }
        // Use MTP for DNSSEC validation consistency with _connectBlock
        let covenantTime = _medianTimePast(for: _tip)
        var invalid = Set<Hash256>()

        for tx in txs {
            // Only test transactions with name covenants
            guard tx.outputs.contains(where: { $0.covenant.type.isName }) else { continue }

            // Build a coin view with this tx's inputs
            var view = CoinView()
            for input in tx.inputs {
                if input.isCoinbase { continue }
                if let coin = coinDB.getCoin(input.prevout) {
                    view.addEntry(input.prevout, coin)
                }
            }

            let snapshot = nameDB.snapshotPending()
            do {
                try CovenantProcessor.processCovenants(
                    tx: tx, txIndex: 0, coinView: view, nameDB: nameDB,
                    height: height, network: network, nameParams: nameParams,
                    chain: self, blockTime: covenantTime, consensusParams: params
                )
            } catch {
                invalid.insert(tx.txHash())
            }
            nameDB.restorePending(snapshot)
        }
        return invalid
    }

    // MARK: - Difficulty Verification

    func _verifyDifficulty(header: BlockHeader, prev: ChainEntry, height: Int) throws {
        // Regtest: no retargeting, bits must match genesis
        if params.noRetargeting {
            guard header.bits == params.powBits else {
                throw HeaderError.badDifficulty
            }
            return
        }

        // Before the window is full (+2 so getSuitableBlock has 3 entries at start),
        // bits must match genesis (matches hsd: prev.height < blocksPerDay + 2)
        if height < params.targetWindow + 3 {
            guard header.bits == params.powBits else {
                throw HeaderError.badDifficulty
            }
            return
        }

        // Get the entries at window endpoints
        let last = prev
        guard let windowStart = _getAncestor(entry: last, height: last.height - params.targetWindow) else {
            throw HeaderError.badDifficulty
        }

        // Get suitable blocks (median-of-3 at each end)
        let firstSuitable = _getSuitableBlock(windowStart)
        let lastSuitable = _getSuitableBlock(last)

        let expected = DifficultyRetarget.retarget(
            first: firstSuitable,
            last: lastSuitable,
            params: params
        )

        guard header.bits == expected else {
            throw HeaderError.badDifficulty
        }
    }

    // MARK: - Reindex & Rebuild

    /// Whether stored blocks need reindexing (coin database behind block store).
    ///
    /// This happens when the chain database is deleted but block files are kept,
    /// or when a previous reindex was interrupted.
    public var needsReindex: Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let coinDB = coinDB, let blockStore = blockStore else { return false }
        let storedCount = blockStore.storedCount
        guard storedCount > 0 else { return false }

        // Exact check: committed height tracks the last fully-processed block.
        if coinDB.committedHeight >= 0 {
            return coinDB.committedHeight < storedCount - 1
        }

        // Legacy fallback (committedHeight not yet stored): use coin count heuristic.
        // After 100+ blocks there should be at least 100 coins. A trivially small
        // count relative to stored blocks means the DB wasn't fully populated.
        return storedCount > 100 && coinDB.coinCount < 100
    }

    /// Reindex stored blocks: rebuild headers, UTXOs, and name state from block files.
    ///
    /// Loads each stored block, adds its header to the chain index, then processes
    /// it through `connectBlock()` to rebuild the UTXO set and Urkel tree.
    /// Headers are flushed to disk periodically so progress survives crashes.
    ///
    /// Handles the case where headers are already loaded from ChainStore (skips
    /// duplicates) and where the tree has stale data from a previous name rebuild
    /// (resets it before starting).
    ///
    /// - Parameter progress: Optional callback receiving (currentHeight, totalBlocks).
    public func reindexBlocks(progress: ((Int, Int) -> Void)? = nil) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let blockStore = blockStore else { return }
        let total = blockStore.storedCount
        guard total > 0 else { return }

        // Reset tree state if it has stale data from a previous (incomplete) run.
        // connectBlock checks the tree root against the block entry's treeRoot,
        // so we need a fresh tree starting from the zero hash.
        if let nameDB = nameDB, nameDB.committedHeight >= 0, let treeDir = treeDir {
            nameDB.close()
            let namesPath = treeDir + "/names"
            try? FileManager.default.removeItem(atPath: namesPath)
            resetNameDB(try NameDB(path: namesPath))
        }

        for h in 0..<total {
            guard let block = try blockStore.loadBlock(height: h) else {
                throw ChainError.validationFailed("missing block at height \(h) during reindex")
            }

            // Rebuild header index (skip if already loaded from ChainStore)
            if h > 0 && _getEntryByHeight(h) == nil {
                var disconnectNotifications: [(Block, Int)] = []
                try _add(header: block.header, proof: block.balloonProof, disconnectNotifications: &disconnectNotifications)
                // During reindex, disconnect notifications are not expected;
                // discard them since we are replaying sequentially.
            }

            // Process block through full validation (UTXOs + covenants).
            // connectBlock skips the BlockStore write since blocks are already stored.
            try _connectBlock(block, height: h)

            // Persist headers periodically so progress survives crashes
            if h % 1000 == 0 {
                try _flush()
            }

            progress?(h, total)
        }

        // Final flush of remaining headers
        try _flush()
    }

    /// The height from which name state rebuild will start.
    ///
    /// Returns 0 if no persisted tree state, otherwise `committedHeight + 1`.
    public var nameRebuildStartHeight: Int {
        lock.lock()
        defer { lock.unlock() }
        guard let nameDB = nameDB else { return 0 }
        return (nameDB.committedHeight >= 0) ? nameDB.committedHeight + 1 : 0
    }

    /// Rebuild the in-memory name state (Urkel tree) from stored blocks.
    ///
    /// Must be called after init when resuming from a previous session.
    /// If the tree was persisted to LevelDB, only replays blocks since the
    /// last tree commit (at most `treeInterval - 1` blocks). Otherwise
    /// replays all stored blocks.
    ///
    /// - Parameter progress: Optional callback receiving (currentHeight, totalHeight).
    public func rebuildNameState(progress: ((Int, Int) -> Void)? = nil) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let nameDB = nameDB, let blockStore = blockStore else { return }
        let total = blockStore.storedCount
        guard total > 0 else { return }

        let startHeight = (nameDB.committedHeight >= 0)
            ? nameDB.committedHeight + 1
            : 0

        for h in startHeight..<total {
            guard let block = try blockStore.loadBlock(height: h) else { continue }

            // Replay covenant state updates (no input coin validation)
            try CovenantProcessor.replayCovenants(
                block: block, nameDB: nameDB,
                height: h, nameParams: nameParams
            )

            // Commit tree at treeInterval boundaries
            if h % nameParams.treeInterval == 0 {
                try nameDB.commit(height: h)
            }

            // Verify tree root at treeInterval boundaries after the commit.
            // The NEXT block's treeRoot should match our committed state.
            if h % nameParams.treeInterval == 0 && h > 0 {
                if let nextEntry = _getEntryByHeight(h + 1) {
                    let currentRoot = try nameDB.treeRoot()
                    let expectedRoot = nextEntry.treeRoot.bytes
                    if currentRoot != expectedRoot {
                        throw ChainError.invalidTreeRoot(
                            height: h + 1,
                            expected: nextEntry.treeRoot.hex,
                            computed: HexEncoding.encode(currentRoot)
                        )
                    }
                }
            }

            progress?(h, total)
        }

        // Don't commit remaining pending state here — it must stay uncommitted
        // so that treeRoot() returns the root from the last treeInterval boundary.
        // connectBlock() checks treeRoot BEFORE processing each block's covenants,
        // and expects the root from the last treeInterval commit, not from the
        // most recent block. Pending entries are still accessible via getNameState()
        // and will be committed at the next treeInterval boundary during sync.
        // On restart, blocks after the last treeInterval commit get replayed again.
    }

    // MARK: - BIP9 Soft Fork Deployment

    /// Get the BIP9 threshold state for a deployment at a given chain position.
    ///
    /// Matches hsd's `chain.getState()`:
    /// 1. Snap to the last window boundary
    /// 2. Walk backward through windows checking cache, stopping at startTime boundary
    /// 3. Replay forward applying state transitions
    public func getDeploymentState(prev: ChainEntry, deployment: Deployment) -> ThresholdState {
        lock.lock()
        defer { lock.unlock() }
        let window = params.minerWindow
        let bit = deployment.bit

        // Snap to the last retarget window boundary.
        // Height is the boundary block: height = prev.height - ((prev.height + 1) % window)
        let boundaryHeight = prev.height - ((prev.height + 1) % window)

        guard boundaryHeight >= 0 else { return .defined }

        guard let boundaryEntry = _getEntryByHeight(boundaryHeight) else { return .defined }

        // Check cache
        if let cached = stateCache[bit]?[boundaryEntry.hash] {
            return cached
        }

        // Walk backward through window boundaries, building a compute stack
        var compute: [ChainEntry] = []
        var entry = boundaryEntry

        while true {
            // Check cache at this boundary
            if stateCache[bit]?[entry.hash] != nil {
                break
            }

            // Genesis or before first window: DEFINED
            if entry.height == 0 {
                stateCache[bit, default: [:]][entry.hash] = .defined
                break
            }

            // Early exit: if MTP is before startTime, this boundary is DEFINED.
            // This avoids walking all the way to genesis for deployments that
            // haven't started yet (matches hsd optimization).
            let mtp = _medianTimePast(for: entry)
            if mtp < deployment.startTime {
                stateCache[bit, default: [:]][entry.hash] = .defined
                break
            }

            // Walk back one full window
            let prevBoundaryHeight = entry.height - window
            if prevBoundaryHeight < 0 {
                stateCache[bit, default: [:]][entry.hash] = .defined
                break
            }

            compute.append(entry)

            guard let prevBoundary = _getEntryByHeight(prevBoundaryHeight) else {
                stateCache[bit, default: [:]][entry.hash] = .defined
                break
            }
            entry = prevBoundary
        }

        // Replay forward through the compute stack
        var state = stateCache[bit]?[entry.hash] ?? .defined

        while let current = compute.last {
            compute.removeLast()

            let mtp = _medianTimePast(for: current)

            switch state {
            case .defined:
                if mtp >= deployment.timeout {
                    state = .failed
                } else if mtp >= deployment.startTime {
                    state = .started
                }

            case .started:
                if mtp >= deployment.timeout {
                    state = .failed
                } else {
                    // Count signaling bits in the window ending at this boundary
                    var count = 0
                    var scan: ChainEntry? = current
                    for _ in 0..<window {
                        guard let s = scan else { break }
                        if s.hasBit(bit) {
                            count += 1
                        }
                        scan = byHash[s.prevBlock]
                    }
                    if count >= params.activationThreshold {
                        state = .lockedIn
                    }
                }

            case .lockedIn:
                state = .active

            case .active, .failed:
                break // Terminal states
            }

            stateCache[bit, default: [:]][current.hash] = state
        }

        return state
    }

    /// Get the aggregated deployment state for all soft forks at a given chain position.
    ///
    /// Called once per block during `connectBlock()`.
    public func getDeployments(prev: ChainEntry) -> DeploymentState {
        lock.lock()
        defer { lock.unlock() }
        return DeploymentState()
    }
}
