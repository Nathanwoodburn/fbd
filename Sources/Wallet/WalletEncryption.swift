import Storage
import Foundation
import Base
import ExtCrypto
import Protocol

// MARK: - Wallet Encryption

extension WalletDB {
    /// Encrypt the wallet with a passphrase. One-way migration.
    ///
    /// Moves seed, mnemonic, and account key into an encrypted blob.
    /// Deletes plaintext key material from the database.
    /// Stores the account xpub unencrypted for address derivation while locked.
    public func encryptWallet(passphrase: String) throws {
        guard initialized else { throw WalletError.notInitialized }
        guard !isEncrypted else { throw WalletError.alreadyEncrypted }
        guard !passphrase.isEmpty else { throw WalletError.emptyPassphrase }

        // Gather key material
        let seed = masterSeed
        let mnemonicStr = storedMnemonic

        var accountKeyData: [UInt8]?
        if let account = getAccountKey() {
            accountKeyData = serializeAccountKey(account)
        }

        // Store xpub before encryption
        guard let xpubStr = xpub else {
            throw WalletError.databaseError("cannot derive account xpub")
        }

        let material = WalletCrypto.KeyMaterial(
            seed: seed, mnemonic: mnemonicStr, accountKey: accountKeyData
        )
        let (blob, check) = try WalletCrypto.encrypt(material: material, passphrase: passphrase)

        // Write encrypted data and delete plaintext in a single batch
        var ops = [(db: UInt8, op: LevelDBStore.BatchOp)]()

        ops.append((metaDB, .put(key: Array("encrypted".utf8), value: blob)))
        ops.append((metaDB, .put(key: Array("encrypted_check".utf8), value: check)))
        ops.append((metaDB, .put(key: Array("accountXpub".utf8), value: Array(xpubStr.utf8))))

        // Delete plaintext key material
        ops.append((metaDB, .delete(key: Array("seed".utf8))))
        ops.append((metaDB, .delete(key: Array("mnemonic".utf8))))
        ops.append((metaDB, .delete(key: Array("accountKey".utf8))))

        // Delete all private keys from keysDB atomically in the same batch,
        // so a crash between metaDB update and keysDB clear cannot leave
        // plaintext key material on disk.
        try forEachEntry(db: keysDB) { key, _ in
            ops.append((keysDB, .delete(key: key)))
        }

        try writeBatch(ops)

        // Update in-memory state
        isEncrypted = true
        encryptionUnlocked = false
        storedAccountXpub = try? ExtendedPublicKey.deserialize(xpubStr)
        masterSeed = nil
        storedMnemonic = nil
        storedAccountKey = nil
    }

    /// Unlock an encrypted wallet by decrypting keys into memory.
    ///
    /// - Parameters:
    ///   - passphrase: The wallet passphrase.
    ///   - timeout: Seconds until auto-lock (0 = no auto-lock). Default 300.
    public func unlockWallet(passphrase: String, timeout: Int = 300) throws {
        guard initialized else { throw WalletError.notInitialized }
        guard isEncrypted else { throw WalletError.notEncrypted }

        guard let blob = try get(db: metaDB, key: Array("encrypted".utf8)),
              let check = try get(db: metaDB, key: Array("encrypted_check".utf8)) else {
            throw WalletError.databaseError("missing encrypted data")
        }

        let material = try WalletCrypto.decrypt(blob: blob, passphrase: passphrase, expectedCheck: check)

        // Restore key material to memory
        masterSeed = material.seed
        storedMnemonic = material.mnemonic

        if let akData = material.accountKey, akData.count == 73 {
            let key = Array(akData[0..<32])
            let chainCode = Array(akData[32..<64])
            let depth = akData[64]
            let fingerprint = UInt32(akData[65]) << 24 | UInt32(akData[66]) << 16
                | UInt32(akData[67]) << 8 | UInt32(akData[68])
            let index = UInt32(akData[69]) << 24 | UInt32(akData[70]) << 16
                | UInt32(akData[71]) << 8 | UInt32(akData[72])
            storedAccountKey = ExtendedPrivateKey(
                key: key, chainCode: chainCode,
                depth: depth, fingerprint: fingerprint, index: index
            )
        }

        encryptionUnlocked = true
        unlockTimeout = timeout
        unlockTime = Date()
    }

    /// Lock an encrypted wallet, wiping keys from memory.
    public func lockWallet() throws {
        guard isEncrypted else { throw WalletError.notEncrypted }

        masterSeed = nil
        storedMnemonic = nil
        storedAccountKey = nil
        encryptionUnlocked = false
        unlockTimeout = 0
        unlockTime = nil
    }

    /// Check if the unlock timeout has expired and auto-lock if so.
    /// Call this periodically (e.g., before signing operations).
    public func checkAutoLock() {
        guard isEncrypted, encryptionUnlocked, unlockTimeout > 0,
              let start = unlockTime else { return }
        if Date().timeIntervalSince(start) >= Double(unlockTimeout) {
            try? lockWallet()
        }
    }
}
