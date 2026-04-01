import Foundation
import Chain
import Consensus
import ExtCrypto
import Protocol
import Base

/// Shared result for parallel mining threads.
final class GenesisResult: @unchecked Sendable {
    private let lock = NSLock()
    private var _nonce: UInt64 = UInt64.max

    func claim(_ nonce: UInt32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard _nonce == UInt64.max else { return false }
        _nonce = UInt64(nonce)
        return true
    }

    var shouldStop: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _nonce != UInt64.max
    }

    var winningNonce: UInt32? {
        lock.lock()
        defer { lock.unlock() }
        return _nonce == UInt64.max ? nil : UInt32(_nonce)
    }
}

/// Tracks per-thread nonce counts for hash rate display.
final class NonceCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var _total: UInt64 = 0

    func increment() {
        lock.lock()
        _total += 1
        lock.unlock()
    }

    var total: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return _total
    }
}

func mine(network: NetworkType) {
    let header = Genesis.header(for: network)
    let params = ConsensusParams.params(for: network)
    let target = Target256.fromCompact(params.powBits)
    let threadCount = ProcessInfo.processInfo.activeProcessorCount

    print("Mining \(network.rawValue) genesis")
    print("  powBits:  \(String(format: "0x%08x", params.powBits))")
    print("  slots:    \(params.balloonSlots)")
    print("  threads:  \(threadCount)")
    print("  target:   \(target)")
    print()

    let start = Date()
    let result = GenesisResult()
    let counter = NonceCounter()
    let group = DispatchGroup()

    // Progress reporter
    let progressQueue = DispatchQueue(label: "mine-genesis.progress")
    let progressTimer = DispatchSource.makeTimerSource(queue: progressQueue)
    progressTimer.schedule(deadline: .now() + .seconds(5), repeating: .seconds(5))
    progressTimer.setEventHandler {
        let elapsed = Date().timeIntervalSince(start)
        let total = counter.total
        let rate = elapsed > 0 ? Double(total) / elapsed : 0
        print("  ... \(total) hashes, \(String(format: "%.2f", rate)) H/s total")
        fflush(stdout)
    }
    progressTimer.resume()

    // Launch threads
    for tid in 0..<threadCount {
        group.enter()
        Thread.detachNewThread {
            defer { group.leave() }
            var nonce = UInt32(tid)
            let stride = UInt32(threadCount)

            while !result.shouldStop {
                let h = BlockHeader(
                    nonce: nonce, time: header.time, prevBlock: header.prevBlock,
                    treeRoot: header.treeRoot, extraNonce: header.extraNonce,
                    reservedRoot: header.reservedRoot, witnessRoot: header.witnessRoot,
                    merkleRoot: header.merkleRoot, version: header.version, bits: header.bits
                )
                counter.increment()
                let hash: Hash256
                do {
                    hash = try ProofOfWork.powHash(for: h, params: params)
                } catch {
                    print("Thread \(tid) error: \(error)")
                    return
                }
                if Target256(bigEndian: hash.bytes) <= target {
                    _ = result.claim(nonce)
                    return
                }
                let (next, overflow) = nonce.addingReportingOverflow(stride)
                if overflow { return }
                nonce = next
            }
        }
    }

    group.wait()
    progressTimer.cancel()

    guard let winningNonce = result.winningNonce else {
        print("No valid nonce found!")
        return
    }

    // Verify and generate proof
    let winHeader = BlockHeader(
        nonce: winningNonce, time: header.time, prevBlock: header.prevBlock,
        treeRoot: header.treeRoot, extraNonce: header.extraNonce,
        reservedRoot: header.reservedRoot, witnessRoot: header.witnessRoot,
        merkleRoot: header.merkleRoot, version: header.version, bits: header.bits
    )
    guard let (hash, proof) = try? ProofOfWork.powHashWithProof(for: winHeader, params: params) else {
        print("Error computing proof for winning nonce")
        return
    }

    let elapsed = Date().timeIntervalSince(start)
    let total = counter.total
    let rate = elapsed > 0 ? Double(total) / elapsed : 0
    let proofHex = HexEncoding.encode(proof.serialize())

    print()
    print("=== \(network.rawValue.uppercased()) GENESIS ===")
    print("  nonce:  \(winningNonce)")
    print("  hash:   \(hash.hex)")
    print("  proof:  \(proofHex)")
    print("  hashes: \(total)")
    print("  time:   \(String(format: "%.1f", elapsed))s")
    print("  rate:   \(String(format: "%.2f", rate)) H/s")
}

// Parse args
let args = CommandLine.arguments
if args.contains("--testnet") {
    mine(network: .testnet)
} else if args.contains("--mainnet") || args.contains("--main") {
    mine(network: .main)
} else {
    // Mine both
    for network: NetworkType in [.main, .testnet] {
        mine(network: network)
        print()
    }
}
