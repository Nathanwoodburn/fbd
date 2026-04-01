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

    // MARK: - RPC Shared Helpers

    /// Validate a wallet name to prevent path traversal.
    @Sendable static func rpcValidateWalletName(_ name: String) throws {
        guard !name.contains("/"), !name.contains("\\"),
              !name.contains("\0"), name != ".", name != ".." else {
            throw RPCError.invalidParams("invalid wallet name")
        }
    }

    /// Resolve a wallet from the request's wallet field (set via --wallet).
    /// Returns the wallet name, WalletDB instance, and method params.
    @Sendable static func rpcResolveWallet(_ req: RPCRequest, ctx: NodeContext) throws -> (String, WalletDB, [JSONValue]) {
        let wallets = ctx.allWallets()
        if wallets.isEmpty {
            throw RPCError.invalidParams("no wallets (call createwallet first)")
        }
        // Explicit --wallet flag
        if let name = req.wallet {
            guard let wallet = wallets[name] else {
                throw RPCError.invalidParams("wallet not found: \(name)")
            }
            return (name, wallet, req.params)
        }
        // No --wallet: auto-select if only one exists
        if wallets.count == 1, let entry = wallets.first {
            return (entry.key, entry.value, req.params)
        }
        throw RPCError.invalidParams("multiple wallets exist, specify --wallet <name>")
    }

    // MARK: - RPC Context Helpers

    /// Unwrap the chain or throw a standard RPC error.
    @Sendable static func requireChain(_ ctx: NodeContext) throws -> Chain {
        guard let chain = ctx.chain else { throw RPCError.internalError("chain not ready") }
        return chain
    }

    /// Unwrap chain + mempool + coinDB or throw a standard RPC error.
    @Sendable static func requireNode(_ ctx: NodeContext) throws -> (Chain, Mempool, CoinDatabase) {
        guard let chain = ctx.chain else { throw RPCError.internalError("chain not ready") }
        guard let mempool = ctx.mempool, let coinDB = ctx.coinDB else {
            throw RPCError.internalError("node not ready")
        }
        return (chain, mempool, coinDB)
    }

    /// Resolve wallet + unwrap chain + mempool + coinDB, verifying wallet is initialized.
    @Sendable static func requireWalletAndNode(_ req: RPCRequest, ctx: NodeContext) throws -> (String, WalletDB, [JSONValue], Chain, Mempool, CoinDatabase) {
        let (name, wallet, rest) = try rpcResolveWallet(req, ctx: ctx)
        guard wallet.initialized else { throw RPCError.internalError("wallet not initialized") }
        let (chain, mempool, coinDB) = try requireNode(ctx)
        return (name, wallet, rest, chain, mempool, coinDB)
    }

    // MARK: - Resource Formatting

    /// Format a Resource as JSON matching hsd's getnameresource output.
    static func formatResource(_ resource: Resource) -> JSONValue {
        var records = [JSONValue]()
        for record in resource.records {
            switch record {
            case .ds(let keyTag, let algorithm, let digestType, let digest):
                records.append(.object([
                    ("type", .string("DS")),
                    ("keyTag", .int(Int64(keyTag))),
                    ("algorithm", .int(Int64(algorithm))),
                    ("digestType", .int(Int64(digestType))),
                    ("digest", .string(HexEncoding.encode(digest))),
                ]))
            case .ns(let name):
                records.append(.object([
                    ("type", .string("NS")),
                    ("ns", .string(name)),
                ]))
            case .glue4(let name, let address):
                records.append(.object([
                    ("type", .string("GLUE4")),
                    ("ns", .string(name)),
                    ("address", .string(formatIPv4(address))),
                ]))
            case .glue6(let name, let address):
                records.append(.object([
                    ("type", .string("GLUE6")),
                    ("ns", .string(name)),
                    ("address", .string(formatIPv6(address))),
                ]))
            case .synth4(let address):
                records.append(.object([
                    ("type", .string("SYNTH4")),
                    ("address", .string(formatIPv4(address))),
                ]))
            case .synth6(let address):
                records.append(.object([
                    ("type", .string("SYNTH6")),
                    ("address", .string(formatIPv6(address))),
                ]))
            case .txt(let strings):
                records.append(.object([
                    ("type", .string("TXT")),
                    ("txt", .array(strings.map { .string($0) })),
                ]))
            case .a(let address):
                records.append(.object([
                    ("type", .string("A")),
                    ("address", .string(formatIPv4(address))),
                ]))
            case .aaaa(let address):
                records.append(.object([
                    ("type", .string("AAAA")),
                    ("address", .string(formatIPv6(address))),
                ]))
            case .cname(let name):
                records.append(.object([
                    ("type", .string("CNAME")),
                    ("target", .string(name)),
                ]))
            case .mx(let preference, let exchange):
                records.append(.object([
                    ("type", .string("MX")),
                    ("preference", .int(Int64(preference))),
                    ("exchange", .string(exchange)),
                ]))
            case .tlsa(let port, let proto, let usage, let selector, let matchingType, let certificate):
                records.append(.object([
                    ("type", .string("TLSA")),
                    ("port", .int(Int64(port))),
                    ("protocol", .int(Int64(proto))),
                    ("usage", .int(Int64(usage))),
                    ("selector", .int(Int64(selector))),
                    ("matchingType", .int(Int64(matchingType))),
                    ("certificate", .string(HexEncoding.encode(certificate))),
                ]))
            case .caa(let flags, let tag, let value):
                records.append(.object([
                    ("type", .string("CAA")),
                    ("flags", .int(Int64(flags))),
                    ("tag", .string(tag)),
                    ("value", .string(value)),
                ]))
            case .sub(let name, let nested):
                var nestedJSON = [JSONValue]()
                for nr in nested {
                    nestedJSON.append(Self.formatSingleRecord(nr))
                }
                records.append(.object([
                    ("type", .string("SUB")),
                    ("name", .string(name)),
                    ("records", .array(nestedJSON)),
                ]))
            case .wallet(let address):
                records.append(.object([
                    ("type", .string("WALLET")),
                    ("address", .string(address)),
                ]))
            }
        }
        return .object([("records", .array(records))])
    }

    /// Format a single Record as JSON (used by formatResource and recursively for SUB).
    static func formatSingleRecord(_ record: Record) -> JSONValue {
        switch record {
        case .ds(let keyTag, let algorithm, let digestType, let digest):
            return .object([
                ("type", .string("DS")),
                ("keyTag", .int(Int64(keyTag))),
                ("algorithm", .int(Int64(algorithm))),
                ("digestType", .int(Int64(digestType))),
                ("digest", .string(HexEncoding.encode(digest))),
            ])
        case .ns(let name):
            return .object([("type", .string("NS")), ("ns", .string(name))])
        case .glue4(let name, let address):
            return .object([("type", .string("GLUE4")), ("ns", .string(name)), ("address", .string(formatIPv4(address)))])
        case .glue6(let name, let address):
            return .object([("type", .string("GLUE6")), ("ns", .string(name)), ("address", .string(formatIPv6(address)))])
        case .synth4(let address):
            return .object([("type", .string("SYNTH4")), ("address", .string(formatIPv4(address)))])
        case .synth6(let address):
            return .object([("type", .string("SYNTH6")), ("address", .string(formatIPv6(address)))])
        case .txt(let strings):
            return .object([("type", .string("TXT")), ("txt", .array(strings.map { .string($0) }))])
        case .a(let address):
            return .object([("type", .string("A")), ("address", .string(formatIPv4(address)))])
        case .aaaa(let address):
            return .object([("type", .string("AAAA")), ("address", .string(formatIPv6(address)))])
        case .cname(let name):
            return .object([("type", .string("CNAME")), ("target", .string(name))])
        case .mx(let preference, let exchange):
            return .object([("type", .string("MX")), ("preference", .int(Int64(preference))), ("exchange", .string(exchange))])
        case .tlsa(let port, let proto, let usage, let selector, let matchingType, let certificate):
            return .object([
                ("type", .string("TLSA")), ("port", .int(Int64(port))), ("protocol", .int(Int64(proto))),
                ("usage", .int(Int64(usage))), ("selector", .int(Int64(selector))),
                ("matchingType", .int(Int64(matchingType))), ("certificate", .string(HexEncoding.encode(certificate))),
            ])
        case .caa(let flags, let tag, let value):
            return .object([("type", .string("CAA")), ("flags", .int(Int64(flags))), ("tag", .string(tag)), ("value", .string(value))])
        case .sub(let name, let nested):
            return .object([
                ("type", .string("SUB")), ("name", .string(name)),
                ("records", .array(nested.map { Self.formatSingleRecord($0) })),
            ])
        case .wallet(let address):
            return .object([("type", .string("WALLET")), ("address", .string(address))])
        }
    }

    static func formatIPv4(_ bytes: [UInt8]) -> String {
        guard bytes.count == 4 else { return "0.0.0.0" }
        return "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])"
    }

    static func formatIPv6(_ bytes: [UInt8]) -> String {
        guard bytes.count == 16 else { return "::" }
        var parts = [String]()
        for i in stride(from: 0, to: 16, by: 2) {
            let val = UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1])
            parts.append(String(val, radix: 16))
        }
        return parts.joined(separator: ":")
    }

    /// Parse a resource JSON value into a Resource for on-chain storage.
    ///
    /// Accepts the hsd-compatible format:
    /// `{"records": [{"type": "NS", "ns": "ns1.example.com"}, ...]}`
    static func parseResourceJSON(_ json: JSONValue) -> Resource {
        var records = [Record]()

        guard case .object(let pairs) = json else { return Resource(records: []) }
        guard let recordsEntry = pairs.first(where: { $0.0 == "records" }),
              case .array(let items) = recordsEntry.1 else {
            return Resource(records: [])
        }

        for item in items {
            guard case .object(let fields) = item else { continue }
            let dict = Dictionary(fields, uniquingKeysWith: { _, b in b })
            guard let typeVal = dict["type"]?.stringValue else { continue }

            switch typeVal.uppercased() {
            case "NS":
                guard let ns = dict["ns"]?.stringValue else { continue }
                records.append(.ns(name: ns))
            case "DS":
                guard let keyTag = dict["keyTag"]?.intValue,
                      let algorithm = dict["algorithm"]?.intValue,
                      let digestType = dict["digestType"]?.intValue,
                      let digestHex = dict["digest"]?.stringValue else { continue }
                let digest = (try? HexEncoding.decode(digestHex)) ?? []
                records.append(.ds(keyTag: UInt16(keyTag), algorithm: UInt8(algorithm),
                                   digestType: UInt8(digestType), digest: digest))
            case "GLUE4":
                guard let ns = dict["ns"]?.stringValue,
                      let addrStr = dict["address"]?.stringValue else { continue }
                let parts = addrStr.split(separator: ".").compactMap { UInt8($0) }
                guard parts.count == 4 else { continue }
                records.append(.glue4(name: ns, address: parts))
            case "GLUE6":
                guard let ns = dict["ns"]?.stringValue,
                      let addrStr = dict["address"]?.stringValue else { continue }
                let addr = parseIPv6Address(addrStr)
                records.append(.glue6(name: ns, address: addr))
            case "SYNTH4":
                guard let addrStr = dict["address"]?.stringValue else { continue }
                let parts = addrStr.split(separator: ".").compactMap { UInt8($0) }
                guard parts.count == 4 else { continue }
                records.append(.synth4(address: parts))
            case "SYNTH6":
                guard let addrStr = dict["address"]?.stringValue else { continue }
                let addr = parseIPv6Address(addrStr)
                records.append(.synth6(address: addr))
            case "TXT":
                if let txtArr = dict["txt"] {
                    if case .array(let strings) = txtArr {
                        let strs = strings.compactMap { $0.stringValue }
                        records.append(.txt(strings: strs))
                    }
                }
            case "A":
                guard let addrStr = dict["address"]?.stringValue else { continue }
                let parts = addrStr.split(separator: ".").compactMap { UInt8($0) }
                guard parts.count == 4 else { continue }
                records.append(.a(address: parts))
            case "AAAA":
                guard let addrStr = dict["address"]?.stringValue else { continue }
                let addr = parseIPv6Address(addrStr)
                records.append(.aaaa(address: addr))
            case "CNAME":
                guard let target = dict["target"]?.stringValue else { continue }
                records.append(.cname(name: target))
            case "MX":
                guard let pref = dict["preference"]?.intValue,
                      let exchange = dict["exchange"]?.stringValue else { continue }
                records.append(.mx(preference: UInt16(pref), exchange: exchange))
            case "TLSA":
                guard let port = dict["port"]?.intValue,
                      let proto = dict["protocol"]?.intValue,
                      let usage = dict["usage"]?.intValue,
                      let selector = dict["selector"]?.intValue,
                      let matchingType = dict["matchingType"]?.intValue,
                      let certHex = dict["certificate"]?.stringValue else { continue }
                let cert = (try? HexEncoding.decode(certHex)) ?? []
                records.append(.tlsa(port: UInt16(port), protocol: UInt8(proto),
                                     usage: UInt8(usage), selector: UInt8(selector),
                                     matchingType: UInt8(matchingType), certificate: cert))
            case "CAA":
                guard let flags = dict["flags"]?.intValue,
                      let tag = dict["tag"]?.stringValue,
                      let value = dict["value"]?.stringValue else { continue }
                records.append(.caa(flags: UInt8(flags), tag: tag, value: value))
            case "SUB":
                guard let name = dict["name"]?.stringValue,
                      let nestedArr = dict["records"],
                      case .array(let nestedItems) = nestedArr else { continue }
                var nested = [Record]()
                for nestedItem in nestedItems {
                    guard case .object(let nf) = nestedItem else { continue }
                    let nd = Dictionary(nf, uniquingKeysWith: { _, b in b })
                    guard let nt = nd["type"]?.stringValue else { continue }
                    if let r = Self.parseSingleRecord(type: nt.uppercased(), dict: nd) {
                        nested.append(r)
                    }
                }
                records.append(.sub(name: name, records: nested))
            case "WALLET":
                guard let address = dict["address"]?.stringValue else { continue }
                records.append(.wallet(address: address))
            default:
                continue
            }
        }

        return Resource(records: records)
    }

    /// Parse a single record from a type string and field dictionary.
    static func parseSingleRecord(type: String, dict: [String: JSONValue]) -> Record? {
        switch type {
        case "NS":
            guard let ns = dict["ns"]?.stringValue else { return nil }
            return .ns(name: ns)
        case "DS":
            guard let keyTag = dict["keyTag"]?.intValue,
                  let algorithm = dict["algorithm"]?.intValue,
                  let digestType = dict["digestType"]?.intValue,
                  let digestHex = dict["digest"]?.stringValue else { return nil }
            let digest = (try? HexEncoding.decode(digestHex)) ?? []
            return .ds(keyTag: UInt16(keyTag), algorithm: UInt8(algorithm),
                       digestType: UInt8(digestType), digest: digest)
        case "GLUE4":
            guard let ns = dict["ns"]?.stringValue,
                  let addrStr = dict["address"]?.stringValue else { return nil }
            let parts = addrStr.split(separator: ".").compactMap { UInt8($0) }
            guard parts.count == 4 else { return nil }
            return .glue4(name: ns, address: parts)
        case "GLUE6":
            guard let ns = dict["ns"]?.stringValue,
                  let addrStr = dict["address"]?.stringValue else { return nil }
            return .glue6(name: ns, address: parseIPv6Address(addrStr))
        case "SYNTH4":
            guard let addrStr = dict["address"]?.stringValue else { return nil }
            let parts = addrStr.split(separator: ".").compactMap { UInt8($0) }
            guard parts.count == 4 else { return nil }
            return .synth4(address: parts)
        case "SYNTH6":
            guard let addrStr = dict["address"]?.stringValue else { return nil }
            return .synth6(address: parseIPv6Address(addrStr))
        case "TXT":
            if let txtArr = dict["txt"], case .array(let strings) = txtArr {
                return .txt(strings: strings.compactMap { $0.stringValue })
            }
            return nil
        case "A":
            guard let addrStr = dict["address"]?.stringValue else { return nil }
            let parts = addrStr.split(separator: ".").compactMap { UInt8($0) }
            guard parts.count == 4 else { return nil }
            return .a(address: parts)
        case "AAAA":
            guard let addrStr = dict["address"]?.stringValue else { return nil }
            return .aaaa(address: parseIPv6Address(addrStr))
        case "CNAME":
            guard let target = dict["target"]?.stringValue else { return nil }
            return .cname(name: target)
        case "MX":
            guard let pref = dict["preference"]?.intValue,
                  let exchange = dict["exchange"]?.stringValue else { return nil }
            return .mx(preference: UInt16(pref), exchange: exchange)
        case "TLSA":
            guard let port = dict["port"]?.intValue,
                  let proto = dict["protocol"]?.intValue,
                  let usage = dict["usage"]?.intValue,
                  let selector = dict["selector"]?.intValue,
                  let matchingType = dict["matchingType"]?.intValue,
                  let certHex = dict["certificate"]?.stringValue else { return nil }
            let cert = (try? HexEncoding.decode(certHex)) ?? []
            return .tlsa(port: UInt16(port), protocol: UInt8(proto),
                         usage: UInt8(usage), selector: UInt8(selector),
                         matchingType: UInt8(matchingType), certificate: cert)
        case "CAA":
            guard let flags = dict["flags"]?.intValue,
                  let tag = dict["tag"]?.stringValue,
                  let value = dict["value"]?.stringValue else { return nil }
            return .caa(flags: UInt8(flags), tag: tag, value: value)
        case "WALLET":
            guard let address = dict["address"]?.stringValue else { return nil }
            return .wallet(address: address)
        default:
            return nil
        }
    }

    /// Validate all records in a resource.
    ///
    /// Checks that record values are well-formed before encoding for on-chain storage.
    /// Throws `RPCError.invalidParams` with a descriptive message on failure.
    static func validateResource(_ resource: Resource, network: NetworkType) throws {
        for record in resource.records {
            try validateRecord(record, network: network)
        }
    }

    /// Validate a DNS hostname (labels separated by dots, trailing dot optional).
    /// Labels must be 1-63 bytes, alphanumeric + hyphens, no leading/trailing hyphens.
    static func isValidHostname(_ name: String) -> Bool {
        let cleaned = name.hasSuffix(".") ? String(name.dropLast()) : name
        guard !cleaned.isEmpty else { return false }
        let labels = cleaned.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels {
            let bytes = Array(label.utf8)
            guard bytes.count >= 1, bytes.count <= 63 else { return false }
            guard bytes.first != 0x2D, bytes.last != 0x2D else { return false } // no leading/trailing hyphen
            for b in bytes {
                let ok = (b >= 0x61 && b <= 0x7A) // a-z
                    || (b >= 0x41 && b <= 0x5A)    // A-Z
                    || (b >= 0x30 && b <= 0x39)    // 0-9
                    || b == 0x2D                    // hyphen
                    || b == 0x5F                    // underscore (for _dmarc, _synth, etc.)
                guard ok else { return false }
            }
        }
        return true
    }

    /// Validate an IPv4 address (4 bytes, each 0-255).
    static func isValidIPv4(_ addr: [UInt8]) -> Bool {
        addr.count == 4
    }

    /// Validate an IPv6 address (16 bytes, not all zeros).
    static func isValidIPv6(_ addr: [UInt8]) -> Bool {
        addr.count == 16
    }

    /// Validate a hex string.
    static func isValidHex(_ str: String) -> Bool {
        !str.isEmpty && str.allSatisfy { $0.isHexDigit }
    }

    static func validateRecord(_ record: Record, network: NetworkType) throws {
        switch record {
        case .wallet(let address):
            guard !address.isEmpty else {
                throw RPCError.invalidParams("WALLET: address is empty")
            }
            do {
                _ = try Address(bech32: address, network: network)
            } catch {
                throw RPCError.invalidParams("WALLET: invalid address '\(address)'")
            }

        case .a(let addr):
            guard isValidIPv4(addr) else {
                throw RPCError.invalidParams("A: invalid IPv4 address")
            }

        case .aaaa(let addr):
            guard isValidIPv6(addr) else {
                throw RPCError.invalidParams("AAAA: invalid IPv6 address")
            }

        case .ns(let name):
            guard isValidHostname(name) else {
                throw RPCError.invalidParams("NS: invalid nameserver '\(name)'")
            }

        case .glue4(let name, let addr):
            guard isValidHostname(name) else {
                throw RPCError.invalidParams("GLUE4: invalid nameserver '\(name)'")
            }
            guard isValidIPv4(addr) else {
                throw RPCError.invalidParams("GLUE4: invalid IPv4 address")
            }

        case .glue6(let name, let addr):
            guard isValidHostname(name) else {
                throw RPCError.invalidParams("GLUE6: invalid nameserver '\(name)'")
            }
            guard isValidIPv6(addr) else {
                throw RPCError.invalidParams("GLUE6: invalid IPv6 address")
            }

        case .synth4(let addr):
            guard isValidIPv4(addr) else {
                throw RPCError.invalidParams("SYNTH4: invalid IPv4 address")
            }

        case .synth6(let addr):
            guard isValidIPv6(addr) else {
                throw RPCError.invalidParams("SYNTH6: invalid IPv6 address")
            }

        case .cname(let name):
            guard isValidHostname(name) else {
                throw RPCError.invalidParams("CNAME: invalid target '\(name)'")
            }

        case .mx(_, let exchange):
            guard isValidHostname(exchange) else {
                throw RPCError.invalidParams("MX: invalid exchange '\(exchange)'")
            }

        case .txt(let strings):
            guard !strings.isEmpty else {
                throw RPCError.invalidParams("TXT: no strings provided")
            }
            for s in strings {
                guard Array(s.utf8).count <= 255 else {
                    throw RPCError.invalidParams("TXT: string exceeds 255 bytes")
                }
            }

        case .ds(let keyTag, let algorithm, let digestType, let digest):
            guard keyTag <= 65535 else {
                throw RPCError.invalidParams("DS: keyTag out of range")
            }
            guard [8, 13, 14, 15, 16].contains(algorithm) else {
                throw RPCError.invalidParams("DS: unsupported algorithm \(algorithm)")
            }
            guard [1, 2, 4].contains(digestType) else {
                throw RPCError.invalidParams("DS: unsupported digest type \(digestType)")
            }
            guard !digest.isEmpty else {
                throw RPCError.invalidParams("DS: digest is empty")
            }

        case .tlsa(let port, let proto, let usage, let selector, let matchingType, let cert):
            guard port > 0 else {
                throw RPCError.invalidParams("TLSA: port must be > 0")
            }
            guard [6, 17, 132].contains(proto) else {
                throw RPCError.invalidParams("TLSA: unsupported protocol \(proto)")
            }
            guard usage <= 3 else {
                throw RPCError.invalidParams("TLSA: usage must be 0-3")
            }
            guard selector <= 1 else {
                throw RPCError.invalidParams("TLSA: selector must be 0-1")
            }
            guard matchingType <= 2 else {
                throw RPCError.invalidParams("TLSA: matching type must be 0-2")
            }
            guard !cert.isEmpty else {
                throw RPCError.invalidParams("TLSA: certificate is empty")
            }

        case .caa(let flags, let tag, let value):
            guard flags == 0 || flags == 128 else {
                throw RPCError.invalidParams("CAA: flags must be 0 or 128")
            }
            guard ["issue", "issuewild", "iodef"].contains(tag.lowercased()) else {
                throw RPCError.invalidParams("CAA: unsupported tag '\(tag)'")
            }
            guard !value.isEmpty else {
                throw RPCError.invalidParams("CAA: value is empty")
            }

        case .sub(let name, let nested):
            let nameBytes = Array(name.utf8)
            guard !nameBytes.isEmpty, nameBytes.count <= 63 else {
                throw RPCError.invalidParams("SUB: subdomain name must be 1-63 bytes")
            }
            // Subdomain labels: alphanumeric, hyphens, underscores
            for b in nameBytes {
                let ok = (b >= 0x61 && b <= 0x7A) // a-z
                    || (b >= 0x41 && b <= 0x5A)    // A-Z
                    || (b >= 0x30 && b <= 0x39)    // 0-9
                    || b == 0x2D || b == 0x5F      // hyphen, underscore
                guard ok else {
                    throw RPCError.invalidParams("SUB: invalid character in subdomain name '\(name)'")
                }
            }
            guard !nested.isEmpty else {
                throw RPCError.invalidParams("SUB: no nested records")
            }
            for nr in nested {
                try validateRecord(nr, network: network)
            }
        }
    }

    /// Parse a colon-separated IPv6 address string into 16 bytes.
    static func parseIPv6Address(_ str: String) -> [UInt8] {
        let parts = str.split(separator: ":")
        guard parts.count == 8 else { return [UInt8](repeating: 0, count: 16) }
        var bytes = [UInt8]()
        bytes.reserveCapacity(16)
        for part in parts {
            guard let val = UInt16(part, radix: 16) else {
                return [UInt8](repeating: 0, count: 16)
            }
            bytes.append(UInt8(val >> 8))
            bytes.append(UInt8(val & 0xFF))
        }
        return bytes
    }
}
