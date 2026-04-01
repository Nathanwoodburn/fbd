/// Errors from consensus validation.
public enum ConsensusError: Error, Sendable {
    // MARK: - PoW

    /// Block hash does not meet the target difficulty.
    case insufficientProofOfWork

    /// Compact target (nBits) encodes a negative or zero value.
    case invalidTarget

    /// BalloonProof verification failed.
    case invalidProof

    // MARK: - Header

    /// Block timestamp is too old (before median time past).
    case timeTooOld

    /// Block timestamp is too far in the future.
    case timeTooNew

    /// Block's prevBlock does not match the expected parent.
    case invalidPrevBlock

    /// Block's difficulty bits do not match the expected retarget.
    case incorrectDifficulty

    /// Block version is invalid.
    case invalidVersion

    // MARK: - Block body

    /// Block has no transactions (must have at least a coinbase).
    case noTransactions

    /// First transaction is not a coinbase.
    case missingCoinbase

    /// Non-first transaction is a coinbase.
    case unexpectedCoinbase

    /// Block exceeds the maximum weight.
    case blockTooHeavy

    /// Block exceeds the maximum base size.
    case blockTooLarge

    /// Block exceeds the maximum sigops.
    case tooManySigops

    /// Merkle root mismatch.
    case invalidMerkleRoot

    /// Witness root mismatch.
    case invalidWitnessRoot

    /// Coinbase output value exceeds allowed (subsidy + fees).
    case coinbaseValueTooHigh

    /// Coinbase does not encode the correct block height.
    case invalidCoinbaseHeight

    // MARK: - Transaction

    /// Transaction has no inputs.
    case noInputs

    /// Transaction has no outputs.
    case noOutputs

    /// Transaction exceeds the maximum weight.
    case txTooHeavy

    /// Duplicate input (same outpoint referenced twice).
    case duplicateInput

    /// Output value is negative or exceeds max money.
    case invalidOutputValue

    /// Total output value exceeds max money.
    case totalOutputOverflow

    /// Attempting to spend an immature coinbase output.
    case immatureCoinbase

    /// Transaction witness count does not match input count.
    case witnessCountMismatch

    /// Block contains duplicate transaction IDs (CVE-2018-17144 defense).
    case duplicateTransaction
}
