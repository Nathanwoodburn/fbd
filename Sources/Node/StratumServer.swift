import Base
import Chain
import Consensus
import ExtCrypto
import Foundation
import Logging
import Mempool
import Mining
import Protocol
import RPC

/// A Stratum v1 mining pool server.
///
/// Accepts miner connections over TCP, distributes work from the current
/// chain tip, validates submitted shares via BalloonProof verification,
/// and submits valid blocks to the chain.
///
/// FBD-specific difference from Bitcoin Stratum: the extraNonce is in the
/// block header (not the coinbase), so the merkle root stays constant per
/// job — no merkle branch computation needed.
public final class StratumServer: @unchecked Sendable {
    private let chain: Chain
    private let mempool: Mempool
    private let address: Address
    private let password: String?
    private let logger: Logger
    private let onBlockMined: @Sendable (Block, ChainEntry) -> Void

    private let lock = NSLock()
    private var listener: TCPListener?
    private var workers: [UInt64: StratumWorker] = [:]
    private var nextWorkerId: UInt64 = 1
    private var nextExtraNonce1: UInt32 = 1
    private var nextJobId: UInt64 = 1
    private var currentJob: StratumJob?
    private var recentJobs: [String: StratumJob] = [:]
    private var jobNotifierTask: Task<Void, Never>?

    /// Maximum number of recent jobs to keep for stale share acceptance.
    private let maxRecentJobs = 4

    public init(
        chain: Chain,
        mempool: Mempool,
        address: Address,
        password: String?,
        logger: Logger,
        onBlockMined: @escaping @Sendable (Block, ChainEntry) -> Void
    ) {
        self.chain = chain
        self.mempool = mempool
        self.address = address
        self.password = password
        self.logger = logger
        self.onBlockMined = onBlockMined
    }

    // MARK: - Lifecycle

    /// Start the Stratum server on the given host and port.
    public func start(host: String, port: Int) throws {
        let tcp = try TCPListener(host: host, port: port)
        self.listener = tcp

        tcp.accept { [self] stream, ip, clientPort in
            await self.handleConnection(stream: stream, ip: ip, port: clientPort)
        }

        // Start job notifier — polls chain tip and generates new jobs.
        jobNotifierTask = Task { [self] in
            var lastTipHash = self.chain.tip.hash
            // Generate initial job
            do {
                let job = try self.generateJob()
                self.lock.lock()
                self.currentJob = job
                self.recentJobs[job.id] = job
                self.lock.unlock()
            } catch {
                self.logger.error("Failed to generate initial job: \(error)", source: "Stratum")
            }

            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                let tipHash = self.chain.tip.hash
                if tipHash != lastTipHash {
                    lastTipHash = tipHash
                    do {
                        let job = try self.generateJob()
                        self.broadcastJob(job, clean: true)
                    } catch {
                        self.logger.error("Failed to generate job: \(error)", source: "Stratum")
                    }
                }
            }
        }

        logger.info("Stratum listening on \(host):\(port)", source: "Stratum")
    }

    /// Shut down the server and disconnect all workers.
    public func shutdown() {
        jobNotifierTask?.cancel()
        jobNotifierTask = nil
        listener?.shutdown()
        listener = nil
        lock.lock()
        let allWorkers = workers.values
        lock.unlock()
        for worker in allWorkers {
            worker.close()
        }
    }

    // MARK: - Connection Handling

    private func handleConnection(stream: SocketStream, ip: String, port: Int) async {
        let workerId: UInt64
        let extraNonce1: UInt32
        lock.lock()
        workerId = nextWorkerId
        nextWorkerId += 1
        extraNonce1 = nextExtraNonce1
        nextExtraNonce1 += 1
        lock.unlock()

        let worker = StratumWorker(id: workerId, stream: stream, extraNonce1: extraNonce1, remoteAddress: "\(ip):\(port)")

        lock.lock()
        workers[workerId] = worker
        lock.unlock()

        logger.debug("Miner connected", metadata: [
            "worker": "\(workerId)",
            "address": "\(ip):\(port)",
        ], source: "Stratum")

        await worker.run(server: self)

        lock.lock()
        workers.removeValue(forKey: workerId)
        let remaining = workers.count
        lock.unlock()

        logger.debug("Miner disconnected", metadata: [
            "worker": "\(workerId)",
            "remaining": "\(remaining)",
        ], source: "Stratum")
    }

    // MARK: - Protocol Handlers

    func handleSubscribe(worker: StratumWorker, id: JSONValue) {
        let extraNonce1Hex = String(format: "%08x", worker.extraNonce1)
        let response = JSONValue.array([
            .array([.string("mining.notify"), .string("1")]),
            .string(extraNonce1Hex),
            .int(Int64(StratumJob.extraNonce2Size)),
        ])
        worker.sendResponse(id: id, result: response)
        worker.isSubscribed = true

        logger.debug("Miner subscribed", metadata: [
            "worker": "\(worker.id)",
            "extranonce1": "\(extraNonce1Hex)",
        ], source: "Stratum")
    }

    func handleAuthorize(worker: StratumWorker, id: JSONValue, params: [JSONValue]) {
        let username = params.first?.stringValue ?? "unknown"
        let workerPassword = params.count > 1 ? params[1].stringValue : nil

        if let required = password, !required.isEmpty {
            guard workerPassword == required else {
                worker.sendResponse(id: id, result: nil, error: .string("unauthorized"))
                return
            }
        }

        worker.username = username
        worker.isAuthorized = true
        worker.sendResponse(id: id, result: .bool(true))

        logger.info("Miner authorized", metadata: [
            "worker": "\(worker.id)",
            "username": "\(username)",
        ], source: "Stratum")

        // Send current job
        lock.lock()
        let job = currentJob
        lock.unlock()

        if let job = job {
            worker.sendNotify(job: job)
        }
    }

    func handleSubmit(worker: StratumWorker, id: JSONValue, params: [JSONValue]) {
        // params: [username, jobId, extraNonce2Hex, nTimeHex, nonceHex, proofHex]
        guard params.count >= 6,
              let jobId = params[1].stringValue,
              let extraNonce2Hex = params[2].stringValue,
              let nTimeHex = params[3].stringValue,
              let nonceHex = params[4].stringValue,
              let proofHex = params[5].stringValue else {
            worker.sendResponse(id: id, result: nil, error: .string("invalid params"))
            worker.rejected += 1
            return
        }

        // Look up job
        lock.lock()
        let job = recentJobs[jobId]
        lock.unlock()

        guard let job = job else {
            worker.sendResponse(id: id, result: nil, error: .string("stale job"))
            worker.stale += 1
            return
        }

        // Decode hex values
        guard let extraNonce2 = try? HexEncoding.decode(extraNonce2Hex),
              extraNonce2.count == StratumJob.extraNonce2Size,
              let nTimeBytes = try? HexEncoding.decode(nTimeHex),
              nTimeBytes.count == 8,
              let nonceBytes = try? HexEncoding.decode(nonceHex),
              nonceBytes.count == 4,
              let proofBytes = try? HexEncoding.decode(proofHex),
              proofBytes.count == BalloonProof.serializedSize else {
            worker.sendResponse(id: id, result: nil, error: .string("invalid hex"))
            worker.rejected += 1
            return
        }

        // Reconstruct extraNonce: poolPrefix(8) || extraNonce1(4) || extraNonce2(12)
        var extraNonce = job.poolExtraNonce
        extraNonce.append(contentsOf: withUnsafeBytes(of: worker.extraNonce1.littleEndian) { Array($0) })
        extraNonce.append(contentsOf: extraNonce2)
        assert(extraNonce.count == 24)

        let nonce = nonceBytes.withUnsafeBytes { $0.load(as: UInt32.self) }
        let time = nTimeBytes.withUnsafeBytes { $0.load(as: UInt64.self) }

        // Reconstruct header
        let header = BlockHeader(
            nonce: nonce,
            time: time,
            prevBlock: job.template.header.prevBlock,
            treeRoot: job.template.header.treeRoot,
            extraNonce: extraNonce,
            reservedRoot: job.template.header.reservedRoot,
            witnessRoot: job.template.header.witnessRoot,
            merkleRoot: job.template.header.merkleRoot,
            version: job.template.header.version,
            bits: job.template.header.bits
        )

        // Deserialize and verify proof
        guard let proof = BalloonProof.deserialize(proofBytes) else {
            worker.sendResponse(id: id, result: nil, error: .string("invalid proof"))
            worker.rejected += 1
            return
        }

        let hash: Hash256
        do {
            hash = try ProofOfWork.verifyWithProof(header: header, proof: proof, params: chain.params)
        } catch {
            worker.sendResponse(id: id, result: nil, error: .string("proof verification failed"))
            worker.rejected += 1
            return
        }

        // Check if hash meets network target
        let target = Target256.fromCompact(job.template.header.bits)
        let hashTarget = Target256(bigEndian: hash.bytes)

        if hashTarget <= target {
            // Valid block!
            let txs = [job.template.coinbase] + job.template.transactions
            let block = Block(header: header, transactions: txs, balloonProof: proof)

            do {
                let entry = try chain.add(header: block.header, proof: proof)
                try chain.connectBlock(block, height: entry.height)
                try chain.flush()
                try chain.flushBlocks()

                logger.info("Block \(entry.height) found by \(worker.username ?? "unknown")", metadata: [
                    "hash": "\(entry.hash.hex)",
                    "worker": "\(worker.id)",
                ], source: "Stratum")

                worker.accepted += 1
                worker.blocks += 1
                worker.sendResponse(id: id, result: .bool(true))

                onBlockMined(block, entry)

                // Generate new job
                if let newJob = try? generateJob() {
                    broadcastJob(newJob, clean: true)
                }
            } catch {
                logger.error("Failed to submit block: \(error)", source: "Stratum")
                worker.sendResponse(id: id, result: nil, error: .string("block submission failed"))
            }
        } else {
            // Valid share but not a block
            worker.accepted += 1
            worker.sendResponse(id: id, result: .bool(true))
        }
    }

    // MARK: - Job Management

    private func generateJob() throws -> StratumJob {
        let tip = chain.tip
        let bits = chain.getNextBits()
        let treeRoot = try chain.getCurrentTreeRoot()
        let time = max(UInt64(Date().timeIntervalSince1970), tip.time + 1)

        let template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: address,
            treeRoot: treeRoot,
            time: time,
            bits: bits
        )

        lock.lock()
        let jobId = String(format: "%x", nextJobId)
        nextJobId += 1
        lock.unlock()

        // 8-byte pool extraNonce prefix (random)
        var poolExtraNonce = [UInt8](repeating: 0, count: StratumJob.poolExtraNonceSize)
        for i in 0..<poolExtraNonce.count {
            poolExtraNonce[i] = UInt8.random(in: 0...255)
        }

        return StratumJob(
            id: jobId,
            template: template,
            poolExtraNonce: poolExtraNonce
        )
    }

    private func broadcastJob(_ job: StratumJob, clean: Bool) {
        lock.lock()
        currentJob = job
        recentJobs[job.id] = job
        // Trim old jobs
        if recentJobs.count > maxRecentJobs {
            let sortedKeys = recentJobs.keys.sorted()
            for key in sortedKeys.prefix(recentJobs.count - maxRecentJobs) {
                recentJobs.removeValue(forKey: key)
            }
        }
        let allWorkers = Array(workers.values)
        lock.unlock()

        for worker in allWorkers {
            if worker.isAuthorized {
                worker.sendNotify(job: job)
            }
        }
    }

    // MARK: - Stats

    /// Get connected worker count.
    public var workerCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return workers.count
    }

}
