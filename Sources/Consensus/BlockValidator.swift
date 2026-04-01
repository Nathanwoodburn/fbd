import Base
import Protocol

/// Block and transaction validation routines.
public enum BlockValidator {

    // MARK: - Block Header

    /// Check that the PoW hash meets the target.
    public static func checkProofOfWork(_ header: BlockHeader, params: ConsensusParams) throws {
        let hash = try ProofOfWork.powHash(for: header, params: params)
        try checkProofOfWork(header, hash: hash)
    }

    /// Verify PoW using a precomputed hash (avoids redundant BalloonHash).
    public static func checkProofOfWork(_ header: BlockHeader, hash: Hash256, params: ConsensusParams? = nil) throws {
        let target = Target256.fromCompact(header.bits)
        guard !target.isZero && target.bitLength <= 256 else {
            throw ConsensusError.invalidTarget
        }

        // Target must not exceed the network's powLimit
        if let params = params {
            guard target <= params.powLimit else {
                throw ConsensusError.invalidTarget
            }
        }

        let hashNum = Target256(bigEndian: hash.bytes)
        guard hashNum <= target else {
            throw ConsensusError.insufficientProofOfWork
        }
    }

    /// Check that the block timestamp is not too far in the future.
    public static func checkTimestamp(
        _ header: BlockHeader,
        currentTime: UInt64,
        params: ConsensusParams
    ) throws {
        let maxTime = currentTime + UInt64(params.maxFutureBlockTime)
        guard header.time <= maxTime else {
            throw ConsensusError.timeTooNew
        }
    }

    /// Check that the block timestamp exceeds the median time past.
    public static func checkMedianTimePast(
        _ header: BlockHeader,
        medianTimePast: UInt64
    ) throws {
        guard header.time > medianTimePast else {
            throw ConsensusError.timeTooOld
        }
    }

    // MARK: - Block Body

    /// Perform non-contextual block body checks.
    ///
    /// - Checks that the block has at least one transaction (coinbase).
    /// - Checks that the first transaction is a coinbase and no others are.
    /// - Checks block weight and base size limits.
    /// - Performs sanity checks on each transaction.
    public static func checkBody(_ block: Block) throws {
        guard !block.transactions.isEmpty else {
            throw ConsensusError.noTransactions
        }

        guard block.transactions[0].isCoinbase else {
            throw ConsensusError.missingCoinbase
        }

        for i in 1..<block.transactions.count {
            guard !block.transactions[i].isCoinbase else {
                throw ConsensusError.unexpectedCoinbase
            }
        }

        // Check block weight
        var totalWeight = 0
        var totalBaseSize = 0
        for tx in block.transactions {
            totalWeight += tx.weight
            totalBaseSize += tx.baseSize
        }

        guard totalBaseSize <= Constants.maxBlockSize else {
            throw ConsensusError.blockTooLarge
        }

        guard totalWeight <= Constants.maxBlockWeight else {
            throw ConsensusError.blockTooHeavy
        }

        // Check for duplicate transaction IDs (CVE-2018-17144 defense)
        var seenTxids = Set<Hash256>()
        for tx in block.transactions {
            let txid = tx.txHash()
            guard seenTxids.insert(txid).inserted else {
                throw ConsensusError.duplicateTransaction
            }
        }

        // Sanity-check each transaction
        for tx in block.transactions {
            try checkTransactionSanity(tx)
        }
    }

    // MARK: - Transaction

    /// Perform non-contextual sanity checks on a transaction.
    public static func checkTransactionSanity(_ tx: Transaction) throws {
        guard !tx.inputs.isEmpty else {
            throw ConsensusError.noInputs
        }

        guard !tx.outputs.isEmpty else {
            throw ConsensusError.noOutputs
        }

        guard tx.witnesses.count == tx.inputs.count else {
            throw ConsensusError.witnessCountMismatch
        }

        guard tx.weight <= Constants.maxBlockWeight else {
            throw ConsensusError.txTooHeavy
        }

        // Check for duplicate inputs (skip for coinbase — null prevout is shared)
        if !tx.isCoinbase {
            var seen = Set<Outpoint>()
            for input in tx.inputs {
                guard seen.insert(input.prevout).inserted else {
                    throw ConsensusError.duplicateInput
                }
            }
        }

        // Check output values
        var totalOutput: Int64 = 0
        for output in tx.outputs {
            guard output.value <= UInt64(Amount.maxMoney) else {
                throw ConsensusError.invalidOutputValue
            }
            totalOutput += Int64(output.value)
            guard totalOutput >= 0 && totalOutput <= Amount.maxMoney else {
                throw ConsensusError.totalOutputOverflow
            }
        }
    }

    /// Check that a coinbase output has sufficient maturity to be spent.
    public static func checkCoinbaseMaturity(
        coinbaseHeight: Int,
        spendHeight: Int,
        params: ConsensusParams
    ) throws {
        let depth = spendHeight - coinbaseHeight
        guard depth >= params.coinbaseMaturity else {
            throw ConsensusError.immatureCoinbase
        }
    }

    /// Check that the coinbase value does not exceed the allowed amount.
    public static func checkCoinbaseValue(
        _ tx: Transaction,
        height: Int,
        fees: Int64,
        params: ConsensusParams
    ) throws {
        let subsidy = BlockReward.getReward(height: height, halvingInterval: params.halvingInterval)
        let (allowed, overflow) = subsidy.addingReportingOverflow(fees)
        guard !overflow else {
            throw ConsensusError.coinbaseValueTooHigh
        }

        var coinbaseValue: Int64 = 0
        for output in tx.outputs {
            let (sum, overflow) = coinbaseValue.addingReportingOverflow(Int64(output.value))
            guard !overflow else {
                throw ConsensusError.coinbaseValueTooHigh
            }
            coinbaseValue = sum
        }

        guard coinbaseValue <= allowed else {
            throw ConsensusError.coinbaseValueTooHigh
        }
    }
}
