import Storage
import Foundation
import Base
import Consensus
import Protocol

// MARK: - Balance Queries & Coin Selection

extension WalletDB {
    /// Get total confirmed balance (sum of all wallet UTXOs).
    public func getBalance() throws -> UInt64 {
        var total: UInt64 = 0
        try forEachEntry(db: coinsDB) { _, value in
            guard value.count >= 12 else { return }
            // Check height (Int32 LE at offset 8) — skip spent-by-unconfirmed (height <= -2)
            let h = Int32(value[8]) | Int32(value[9]) << 8
                | Int32(value[10]) << 16 | Int32(value[11]) << 24
            guard h >= -1 else { return }
            var v: UInt64 = 0
            for i in 0..<8 { v |= UInt64(value[i]) << (i * 8) }
            total += v
        }
        return total
    }

    /// Get spendable balance for a specific address.
    ///
    /// Excludes covenant-locked outputs and immature coinbase.
    public func getBalance(address: Address) throws -> UInt64 {
        let coins = try listUnspent(address: address)
        let currentHeight = scanHeight
        return coins.reduce(UInt64(0)) { total, coin in
            if coin.covenant.type.isNonspendable { return total }
            if coin.coinbase && currentHeight - coin.height < ConsensusParams.params(for: network).coinbaseMaturity { return total }
            return total + coin.value
        }
    }

    /// Get detailed balance breakdown (confirmed, unconfirmed, locked).
    public func getDetailedBalance() throws -> WalletBalance {
        // Read ALL coins, including spent-by-unconfirmed (height <= -2),
        // so that confirmed balance is not reduced by mempool spends.
        // This matches hsd semantics: confirmed = all confirmed UTXOs
        // regardless of whether a mempool tx spends them.
        var confirmed: UInt64 = 0
        var unconfirmed: UInt64 = 0
        var lockedConfirmed: UInt64 = 0
        var lockedUnconfirmed: UInt64 = 0
        var immatureCoinbase: UInt64 = 0
        let currentHeight = scanHeight

        try forEachEntry(db: coinsDB) { key, value in
            guard key.count == 36 else { return }
            let txHash = Hash256(unchecked: Array(key[0..<32]))
            let idx = UInt32(key[32]) | UInt32(key[33]) << 8
                | UInt32(key[34]) << 16 | UInt32(key[35]) << 24
            let outpoint = Outpoint(hash: txHash, index: idx)
            guard let coin = WalletCoin.deserialize(value, outpoint: outpoint) else { return }
            let locked = coin.covenant.type.isNonspendable

            if coin.height >= 0 {
                // Confirmed UTXO
                confirmed += coin.value
                unconfirmed += coin.value
                if locked { lockedConfirmed += coin.value; lockedUnconfirmed += coin.value }
                // Track immature coinbase
                if coin.coinbase && currentHeight - coin.height < ConsensusParams.params(for: network).coinbaseMaturity {
                    immatureCoinbase += coin.value
                }
            } else if coin.height == -1 {
                // Unconfirmed output (from mempool tx)
                unconfirmed += coin.value
                if locked { lockedUnconfirmed += coin.value }
            } else if coin.height == Int(Int32.min) {
                // Unconfirmed coin spent by another mempool tx — counts toward nothing
            } else {
                // height <= -2: confirmed UTXO spent by a mempool tx.
                // Still counts toward confirmed (the coins exist on-chain),
                // but NOT toward unconfirmed (mempool tx will remove them).
                confirmed += coin.value
                if locked { lockedConfirmed += coin.value }
            }
        }

        return WalletBalance(
            confirmed: confirmed,
            unconfirmed: unconfirmed,
            lockedConfirmed: lockedConfirmed,
            lockedUnconfirmed: lockedUnconfirmed,
            immatureCoinbase: immatureCoinbase
        )
    }

    /// List all unspent coins, optionally filtered by address.
    ///
    /// Excludes coins marked as spent-by-unconfirmed (height <= -2).
    public func listUnspent(address: Address? = nil) throws -> [WalletCoin] {
        var coins = [WalletCoin]()
        try forEachEntry(db: coinsDB) { key, value in
            guard key.count == 36 else { return }
            let txHash = Hash256(unchecked: Array(key[0..<32]))
            let idx = UInt32(key[32]) | UInt32(key[33]) << 8
                | UInt32(key[34]) << 16 | UInt32(key[35]) << 24
            let outpoint = Outpoint(hash: txHash, index: idx)
            if let coin = WalletCoin.deserialize(value, outpoint: outpoint) {
                // Skip coins marked as spent-by-unconfirmed (soft-deleted)
                guard coin.height >= -1 else { return }
                if let addr = address {
                    if coin.address == addr {
                        coins.append(coin)
                    }
                } else {
                    coins.append(coin)
                }
            }
        }
        return coins
    }

    /// Select spendable coins to cover the target amount plus fees.
    ///
    /// Filters for non-covenant, mature, P2WPKH (v0, 20-byte hash) coins.
    /// Includes unconfirmed wallet outputs (own change) so transactions
    /// can be chained without waiting for block confirmation.
    /// Uses largest-first selection to minimize the number of inputs.
    func selectCoins(target: UInt64, feeRate: UInt64, currentHeight: Int, excluding: Set<String> = [], subtractFee: Bool = false) throws -> (coins: [WalletCoin], totalInput: UInt64) {
        let allCoins = try listUnspent()

        // Filter for spendable coins
        let spendable = allCoins.filter { coin in
            // Skip coins already used as linked inputs
            if !excluding.isEmpty {
                let key = "\(coin.outpoint.hash.hex):\(coin.outpoint.index)"
                guard !excluding.contains(key) else { return false }
            }
            // Must not be locked in a covenant
            guard !coin.covenant.type.isNonspendable else { return false }
            // Skip unconfirmed coins (outputs from mempool txs) — prefer
            // confirmed coins to avoid building chains of unconfirmed txs
            // that cascade-evict if any link is invalidated.
            guard coin.height >= 0 else { return false }
            // Coinbase maturity check
            if coin.coinbase {
                let confirmations = currentHeight - coin.height
                guard confirmations >= ConsensusParams.params(for: network).coinbaseMaturity else { return false }
            }
            // P2WPKH only: version 0, 20-byte hash
            guard coin.address.version == 0, coin.address.hash.count == 20 else { return false }
            return true
        }

        guard !spendable.isEmpty else {
            // If the wallet has coins but none are spendable (locked in covenants,
            // immature coinbase, etc.), that's a different error than having nothing.
            if allCoins.isEmpty {
                throw WalletError.insufficientFunds(have: 0, need: target)
            }
            throw WalletError.noSpendableCoins
        }

        // Sort largest-first
        let sorted = spendable.sorted { $0.value > $1.value }

        var selected = [WalletCoin]()
        var total: UInt64 = 0

        for coin in sorted {
            selected.append(coin)
            total += coin.value

            // Estimate fee with current input count (2 outputs: dest + change)
            let fee = estimateFee(inputCount: selected.count, outputCount: 2, feeRate: feeRate)
            let needed = subtractFee ? target : target + fee
            if total >= needed {
                return (coins: selected, totalInput: total)
            }
        }

        // Not enough — compute what we'd need
        let fee = estimateFee(inputCount: selected.count, outputCount: 2, feeRate: feeRate)
        let needed = subtractFee ? target : target + fee
        throw WalletError.insufficientFunds(have: total, need: needed)
    }

    /// Estimate the fee for a transaction with the given parameters.
    ///
    /// Uses P2WPKH sizing. Fee rate is in bumps per kvB (1000 vbytes).
    /// `extraOutputBytes` accounts for covenant data beyond the base output size.
    func estimateFee(inputCount: Int, outputCount: Int, feeRate: UInt64, extraOutputBytes: Int = 0) -> UInt64 {
        // Base overhead: version(4) + input varint(1) + output varint(1) + locktime(4) = 10
        let baseOverhead = 10
        // Per input base: prevout(32+4) + sequence(4) = 40
        let inputBase = 40 * inputCount
        // Per output: value(8) + address version(1) + address hash len(1) + hash(20) + covenant type(1) + covenant len(1) = 32
        let outputBase = 32 * outputCount + extraOutputBytes

        // Witness: per input: varint(1) + sig(65) + varint(1) + pubkey(33) = 100
        // Plus varint for item count = 1, total 101
        let witnessPerInput = 101 * inputCount

        let baseSize = baseOverhead + inputBase + outputBase
        let witnessSize = witnessPerInput
        let weight = baseSize * 4 + witnessSize
        let vsize = (weight + 3) / 4

        // +1 ensures we never land exactly at the min relay threshold
        return UInt64(vsize) * feeRate / 1000 + 1
    }

    /// Compute the serialized size of a covenant's items (for fee estimation).
    func covenantSize(_ covenant: Covenant) -> Int {
        // type(1) + items count varint(1-3) + per item: varint(len) + data
        var size = 1 + compactSizeLen(UInt64(covenant.items.count))
        for item in covenant.items {
            size += compactSizeLen(UInt64(item.count)) + item.count
        }
        return size
    }

    func compactSizeLen(_ n: UInt64) -> Int {
        if n < 0xFD { return 1 }
        if n <= 0xFFFF { return 3 }
        if n <= 0xFFFFFFFF { return 5 }
        return 9
    }

    /// Compute fee from actual transaction structure (not estimates).
    /// Builds a dummy tx to get the real baseSize, then adds witness estimate.
    func computeFee(
        inputs: [Input],
        covenantOutput: Output,
        changeAddr: Address,
        totalInput: UInt64,
        value: UInt64,
        feeRate: UInt64,
        isMultisig: Bool
    ) -> UInt64 {
        // Build with 2 outputs (covenant + change) to get max baseSize
        let dummyChange = Output(value: 0, address: changeAddr)
        let tx2 = Transaction(version: 0, inputs: inputs,
                              outputs: [covenantOutput, dummyChange], locktime: 0)
        let baseSize2 = tx2.baseSize

        // P2WPKH witness: itemCount(1) + sigLen(1) + sig(65) + pubkeyLen(1) + pubkey(33) = 101
        let witnessPerInput = isMultisig ? estimateMultisigWitnessSizeForWallet() : 101
        let witnessSize = witnessPerInput * inputs.count
        let weight2 = baseSize2 * 4 + witnessSize
        let vsize2 = (weight2 + 3) / 4
        let fee2 = UInt64(vsize2) * feeRate / 1000 + 1

        // Check if change would be dust — if so, use 1-output fee
        if totalInput < value + fee2 || (totalInput - value - fee2) <= 500 {
            let tx1 = Transaction(version: 0, inputs: inputs,
                                  outputs: [covenantOutput], locktime: 0)
            let weight1 = tx1.baseSize * 4 + witnessSize
            let vsize1 = (weight1 + 3) / 4
            return UInt64(vsize1) * feeRate / 1000 + 1
        }
        return fee2
    }

    /// Look up a coin by outpoint.
    public func getCoin(outpoint: Outpoint) throws -> WalletCoin? {
        let key = outpointKey(outpoint)
        guard let data = try get(db: coinsDB, key: key) else { return nil }
        return WalletCoin.deserialize(data, outpoint: outpoint)
    }
}
