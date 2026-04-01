import Base
import ExtCrypto
import Protocol
import Consensus
import Covenants

/// Genesis block constants for each Fistbump network.
///
/// FBD uses Balloon Hash PoW. The genesis block coinbase pays the block
/// reward to a burn address (zero hash). The genesis is mined on first
/// startup if needed (regtest/simnet mine instantly due to easy difficulty).
public enum Genesis {

    /// Genesis coinbase message.
    private static let genesisFlags: [UInt8] = Array("fbd".utf8)

    /// Genesis timestamp per network.
    /// Mainnet: 2026-04-01T04:00:00Z (midnight EDT). Testnet: 2026-03-15T17:44:21Z.
    private static func genesisTime(for network: NetworkType) -> UInt64 {
        switch network {
        case .main:    return 1775016000
        case .testnet: return 1773797061
        case .regtest: return 1774224000
        case .simnet:  return 1774224000
        }
    }

    /// Get the genesis block header for a network.
    ///
    /// For regtest/simnet, nonce=0 satisfies the easy difficulty target.
    /// For mainnet/testnet, the genesis is pre-mined with known nonces.
    public static func header(for network: NetworkType) -> BlockHeader {
        let params = ConsensusParams.params(for: network)

        // Build the genesis coinbase to compute merkle/witness roots
        let coinbase = genesisCoinbase(network: network)
        let merkleRoot = (try? MerkleTree.computeRoot([coinbase.txHash()])) ?? .zero
        let witnessRoot = (try? MerkleTree.computeRoot([.zero])) ?? .zero

        return BlockHeader(
            nonce: genesisNonce(for: network),
            time: genesisTime(for: network),
            prevBlock: .zero,
            treeRoot: .zero,
            extraNonce: [UInt8](repeating: 0, count: 24),
            reservedRoot: .zero,
            witnessRoot: witnessRoot,
            merkleRoot: merkleRoot,
            version: 0,
            bits: params.powBits,
            mask: [UInt8](repeating: 0, count: 32)
        )
    }

    /// Build the genesis coinbase transaction.
    ///
    /// Built inline to avoid depending on the Mining module.
    /// Includes REGISTER outputs for "fistbump" and all single-character TLDs (a-z, 0-9).
    public static func genesisCoinbase(network: NetworkType) -> Transaction {
        let reward = BlockReward.getReward(height: 0)
        let burnAddress = Address(unchecked: 0, hash: [UInt8](repeating: 0, count: 20))
        let params = ConsensusParams.params(for: network)
        let devAddr = Address(unchecked: params.devFundVersion, hash: params.devFundAddress)

        let input = Input(prevout: .null, sequence: 0)  // height 0
        let burnOutput = Output(value: UInt64(max(0, reward)), address: burnAddress)

        var outputs = [burnOutput]

        let zeroBlockHash = [UInt8](repeating: 0, count: 32)
        let emptyResource: [UInt8] = [0] // version byte only

        // REGISTER "fistbump" with DNS records (no subdomain auctions)
        let fistbumpHash = NameRules.hashName("fistbump")
        let fistbumpCov = CovenantData.makeRegister(
            nameHash: fistbumpHash, startHeight: 0,
            resource: genesisResource(), blockHash: zeroBlockHash
        )
        outputs.append(Output(value: 0, address: devAddr, covenant: fistbumpCov))

        // REGISTER all single-character TLDs (a-z, 0-9) with subdomain auctions enabled
        for char in "abcdefghijklmnopqrstuvwxyz0123456789" {
            let nameHash = NameRules.hashName(String(char))
            let cov = CovenantData.makeRegister(
                nameHash: nameHash, startHeight: 0,
                resource: emptyResource, blockHash: zeroBlockHash,
                flags: 1 // auctionSubdomains
            )
            outputs.append(Output(value: 0, address: devAddr, covenant: cov))
        }

        let witness = Witness(items: [[0], genesisFlags])

        return Transaction(
            inputs: [input],
            outputs: outputs,
            witnesses: [witness]
        )
    }

    /// DNS resource data for the genesis "fistbump" name.
    ///
    /// Records:
    ///   CNAME → fistbump.org
    ///   TLSA 443 tcp 3 1 1 2F61BDD6...D807F6
    ///
    /// Encoded manually to avoid a DNS module dependency.
    /// Format: [version:0][type:CNAME(9)][name]...[type:TLSA(11)][port][proto][usage][sel][match][cert]
    private static func genesisResource() -> [UInt8] {
        var buf = [UInt8]()
        buf.append(0) // version

        // CNAME record (type 9): name = "fistbump.org"
        // Name uses DNS label encoding: [len]label[len]label[0]
        buf.append(9) // RecordType.cname
        for label in "fistbump.org".split(separator: ".") {
            let bytes = Array(label.utf8)
            buf.append(UInt8(bytes.count))
            buf.append(contentsOf: bytes)
        }
        buf.append(0) // root terminator

        // TLSA record (type 11): 443 tcp 3 1 1 <hash>
        buf.append(11) // RecordType.tlsa
        buf.append(UInt8(443 >> 8)); buf.append(UInt8(443 & 0xFF)) // port BE
        buf.append(6) // protocol: TCP
        buf.append(3) // usage: DANE-EE
        buf.append(1) // selector: SPKI
        buf.append(1) // matching type: SHA-256
        let certHash: [UInt8] = [
            0x2F, 0x61, 0xBD, 0xD6, 0xD5, 0x7B, 0x97, 0x36,
            0x0F, 0x3F, 0x05, 0x3F, 0x64, 0x99, 0xBC, 0xFF,
            0x23, 0x2D, 0xF6, 0xE8, 0x64, 0xE6, 0xE4, 0x93,
            0xC1, 0x06, 0x7B, 0xA0, 0x3B, 0xD8, 0x07, 0xF6,
        ]
        buf.append(UInt8(certHash.count >> 8)); buf.append(UInt8(certHash.count & 0xFF)) // length BE
        buf.append(contentsOf: certHash)

        return buf
    }

    /// Build the full genesis block (header + coinbase).
    public static func block(for network: NetworkType) -> Block {
        let hdr = header(for: network)
        let cb = genesisCoinbase(network: network)
        return Block(header: hdr, transactions: [cb], balloonProof: genesisProof(for: network))
    }

    /// Pre-computed genesis BalloonProof per network.
    /// Mainnet/testnet proofs are hardcoded (512MB BalloonHash is too slow to recompute).
    /// Regtest/simnet proofs are computed on the fly (4-slot BalloonHash is instant).
    public static func genesisProof(for network: NetworkType) -> BalloonProof {
        switch network {
        case .main:
            return BalloonProof.deserialize(try! HexEncoding.decode(genesisProofHex_main))!
        case .testnet:
            return BalloonProof.deserialize(try! HexEncoding.decode(genesisProofHex_testnet))!
        case .regtest, .simnet:
            let hdr = header(for: network)
            let params = ConsensusParams.params(for: network)
            return try! ProofOfWork.powHashWithProof(for: hdr, params: params).proof
        }
    }

    // swiftlint:disable line_length
    // Computed via mine-genesis
    private static let genesisProofHex_main = "ffffff00803ed46d6ceae6b2e21505f7a3b019152db8c371822f03128843510bb827bff39a4074b6f58509358829ba2e12edc55c1fcacc5d79e35e8c6cbe66587b782a9f09bb35792f7751242938df198bf4a50393f47052075d16ba4d94ec21d771c7b838e3fdf5af396ec8a8768d9571ccf513adb2b3d83bb54ca416d65562568550dd2023bf00aa9928a43418e541ad3ca7248691a5d54dfe254d878a66d5f04ccfc47cd0ca8471e36f0001cd0863db8637b9f4ce2c40258f5bceedd4fb689261c1aca21abba2b70dbbd85129a0bd91a6dfb65c720cb20025136921859178617e1b314aedea0ba5819f5bc47e13ad8a7a4308af9916f6f3ea09800b6df0bea6fbdd766f233292c3949f788866a171b1655657c7eed486a656ef0a661af60a253d2dc2a9be3909b80fd187470acc000b0c82eee972f61f07d70e30f7b4a97ad19c9eba70d3ccd88947070edeff2ef041f8b900b3f8f8d90d49670a2448de8a7260470d9ee1b172fbc068f308e86b632c0e35acf07fc097d68f8c2d37d03e4ee3c6108e8e035981857883ce0415e759a27eae293438d6bdf8a76f673bf3599a6fb95c5b935ee23434d7b32ef044b6e4f97ac7ee47988bf81677611a571997b8dcf0e96616b799a75ee6275a6cd19273459fbc8400a8a90041946cf54c5d163d0cf64515b841952632c68c8814fac5e80cef13bc82828d8f1fece200dc2f51dad94fb04072d99a7dfd6b98c70bcd9fd7738d8f43e1b98dd5ba0a27c70c111db13a5cccd162e022242a19096d656fc3ed7be4fd96db95accd2e42d7a803368ae45334487bfb9d1c8711b545938e90142edb28bd93116ddd29875c7ee8ac9b99fe838328c30ca6bbe4f2d8c459590452878eda947df75838393f787ab77e9efa009cdc5afe31a15b4a6d70ad58f3e25a850e108e7f4eb3619fd8ad710ec30b1d8826e49c00511c57c3caddcd68bf17618e699f00a38d0feacb19b0be6a8f4b31a4c6d756efa4bb5b6921e593efff053776f41a14ef991a5f321e35406dbd1682517dc2d7ae640881b37852138f42120d8d11003d22c989f9dde5106b596380261f1864efda3e41fbf12dde2330229a3d8b206e5d199582377984a685e92bbf619fde3e6cf16cbf2a00f4e7e4d9b1d3a66dbd401b8e1c6c57a1cc3b5d2690ade41e456ca2ce4f17653bd48fda00ae0f137700146eddb9c2baab16542ea9e00d534d5084a3d139404a25c5223d1760ded2ad00465956d1af0ba1a452cb5110242484c246c01eb043cef80cf28197264b28ed5b7a10efa77bca571c0adf56bc49a455b48f66ed40e6f7e1963f25a6dfc22e34690f94ff0047009c5c70e53e6b5a5c696939c0f678ba5a7d2e4653449e42880086faad24751fa4d75441546a0d3979843086da93a1d48beaf2df9a70db2adf117191bc00f27f90260380f56891d45a165235710239b711b57d0298d84e943aec5c62971efc01137f86c057834027a1009667ef2c5c4f48a9a65a19776f25696cc66bd0cec66396a9b42d5e8b50416a43240fd165f80371e555daa9b8552ca472029a43ae02aa1ae47d2a9f9d483d8378ad66fc49a8560c08b9a769e78c7cc2ebbc126a0e1022c6008d9edbf8ef7135be67235c99582379069961bff61c8e846a790f073743fac1dcfbebc200912b4d0b6e0d6a93a33050085785e5674145122221a9f8541766ffd675d4c823bfa8b850bd0f57e5c2fcbb602ea8209658dec55dbf2e7e55d53be4cedf20ce8e84e9d708cb121efc05ee8089e77ab5e76559a07e53020086ca94cffb8371d34dd3f9c3f29d975c16fe7472199c8a9f0a6418c60b922ec3e189ccc9b5a280e2757122e800d64fb8f4700e4fc1ade7935c2e265efd4d60c89a5d09c582727775d283138d119d12f5008f8f6844ae24bdca281c3a4a4b74c55bdfba3d6e9277501e0c0b344ed52bfbf0a27a0ea1e4befbf339bddbf0a648f58a459ebb225aa3a2a9a52228f336c7e3abd42d82e28582a300f2ded1335265951ff4b55ca1d3a495061f6f3ce5f4fe2f2cfc3f0a7b405658af52c28599131a860736a1347bc6d4a6364943388a0ba15d418c7d0b00238fc8a239fb0e285995d6422ae16b8fa98f0420ccaba6f3e0279a181f3aaa797930ae007b8cd57df2c3201730c21704567951892868f6b1817a8c86bd0c53f62fc416d06e3a4f373a63095a74af8cb900a27ae614cee31eeaa28c657fd7d7f4e862baa8757cc71f0aa78b79f739c8449ef941a6c5673cec93363c99ccd1d3380b0cd677f5a6088b7f60c62216edca7fc3562e761b3ae94cf3553a9c0ff4b30132de539345e9be00e02c82d95a41bf949364f8a744ddd0ffad2569da3b76c85ae8859fb23b9e7983bb36710014e0f1d2c53041d7e2d02cf677369a19e7e6bdf4cd8cc87855c67e45292d379878eb3c666c93206e8fbe9c28623ecc009a3eeadf70cebfdf8972c5115e21d5af338c63508d5e0206415f9ff58a90d85925ccff8c46a15b625eb8a782729406fcd55d1cc40bd461daa6ac6edd9223965a28b0e8c0478d8ab62650e711555b2578f32f2b00272b78ca406d3bb14c175d0840a0d266adab018d583afe79482d1c1626bf705018c47400f22581ec7bf4774e9a9d0d24aad9785ce870b95d018b458a5f8893810d77b3ec83fc31ff398ece5fd44a8c78ea84ce8d451f8722c7df91cbba333cf56b21240283b17f72bc6bac380f23c7ed46bf0e46f8a739c9ecf73f978d3f2289223c2c51d79f5bcc31f1264cf01fefba7ff3de49004200c8a5042942e01dd7b4e844aac9f397ff0019aa1273250b2b1e1ddc3412726cc7986d63d290bf227ef32484b93872e72e36cb4495001e00aa82455bf81f0db7eb1cf72989b160347dc1208bb135511d93c9120581c8de81c4b3a3bb015106a46550311d0a767408e96804e7191bcb0b32c6ce4ca61ea196aad6aba5885059e797a5ad82d6c47aa440941f2bf97f10035c978135c44befa7e80b0cc060e7c55e2b6a712c97cad7435039fa37676d75ec7a976855653aea709c00fcc8eafce626c8c4ef09319d28fcd7090e819c850e07e573a83b4950ad5df58c129043007dc514fc845e434c9e7003e8a5af3bd8aadc8e6a7f1087c5338f9e6c85f2d00c8fbb6a0f65231b36fe0cf0a6b1613d99e4fc7ffd57d74b596e19107a73a4af12d0ccfde7c2c77999db7469a088e112d56396a7335061e3beee5f7c0af84b1851f4deb2bd178ffd2498772401b654de562df1442a762f5310ae3926d4a44ecdb4338f7200f343a211fa4f83b4feb975ea4b5774d66c60b919fe9c2a7904e4faa1cb32fee507f674005d4ebf63d9d9848d47c3dd72d93bf2d579b25490a18e71d5777b7ebce40f91c66e72f1868f329f4730742b47ee2636ff9452285aaa358432820e0b0b60287568e7fb9458ae2576bd67228fd2690ec23ca8e07ee645744af5d4132332aa3e3e94b5f37017767033fd42eee5c545aab43b00f7baac4733f2f83fb959e83e37c4bd61552c00c19fb7b5c686aa9fff9602688ecdf9aeccf402a6cc654b4b294adfb898221a8698eed70049788d0906eeaee722458d49f2a0f922e87ae1308f257e84cb782aea5663a7a7c7e36fac8fc98e57e0bc48d51fa85b3169e3e40239960e5e8a4f1293cc50321280ff750d5e4f83c68954afe2319f53024250e37d5ae47e11d0dcef2a3a49191a6681047e917d3086d837526d56cbe3cf8a397fc3686c4653e255d24daa780553abba0500e6431fd7533e466426f7bfee592fb83f0e3e1691b4a8666bbaee4c2014c30f39dae5ca00140142e38056617b88128793bd5a0b970229f3424c66178bb821e6b6bc4c7739e4862998c088202aeccae5ec9aa99f08c6d4cf2803f4461dce55f89b6c91db444841a3286dca8c817ae20991ba2e47b7fce66e325e7dc6acbcd2b994cf8e7926954a96f8d5b9978193a553b610e263487bd5e82d5d1dd641a670b8550f97fab74330d4003ad564c399080baa1ef167d07026b9bdbb2b177989095ed2eb1be5a63c772748cb76fb0039c12b2844bcb52a5bf8d102e56da51dae871adf5ec8de23ae84446d4d216683ce5e9b0e594c76dc667153c1d7aaeeea2e80fff8c3cdea227c964a697afe6c03ff78dffdb5d1164142187b743095a3a7cb56c7f58349e38aa0eda2b4ebc4999098342c84a5691ad80c0b1f39396154a65f70ffb4146740a9bac2e4e7c20e4be4ec0753008d6699faad4116013e222d46b1fdae7c3b48073fe402f37538e15f10af414b1a866d6d0041a303424bf11b4fcd885ca00e5586dc9a9863c61bc5c2da8358de2dd2bc3606cb61176272a186a0fbdf509a96df3afb0b610c335be8b8cefab066ad03f1c74a1a28aabe2f291704923e9f3abecdec7f94e1fa830a461860ccc1f6cdcfa899dbc44be6ddce422c40262ed534a0bed2a1d07907589fef13a22f5b492c2d643b02a3df2500c4db1b655505463eb4ab5c0f644c78411605fa4c89261057fb0435506516ae172eaa6b003be83c73cbd18747cc1acf698d1814b8ac4246e8bc52c30edc2aadfa5bd2e6248cdd13004e5ff06d6e65840f50a0b8f1847929971711a4a59bd0ef69783c657fa19fddd11b4f425e8c332254cdd226558dd7f7244911b99731b6f46f7c7550e97745ce79e35347333e8820b902cdc4e418710c9db141f6e69b856794d09d40b34449070074d100f259ff5087e72b053864ba4d00537b617058acbddc3edcd9dae00ebbc442399000fcc02de056dba54a9c6f62bc505825232043dbb85f9e01a2e16b7ade22d6f862f1e603cc79c01ceb9a860b355cce4eee8e8abb5ce3ab7da2fa07b6a6c370939f2f45bb9b4be00ea7817a6f7121fb61502104e07b68aea3789db15e36bd6695858cb84a8668083f903eff08368fbd7e90b09118e019ab5ed087a3810e4bb9c214be39f6001fd4b743c43f5b9265bd087c9376df066f215ce72b8ca5a521c19e1024cd453fea1c570023306ea460d6062c05dcee1f290ae9a1abd5026d44acfb1e23227d2fd6a1d821c3745ffdfc6ba4250d5dc86f060217776166bd488332606dc891f9b26aa1cc4dba649f21621b213f84eeee66540f5e612e2d3000ab236f1c92196d470f263a69c4fe385b00db17c052b4d5ce261ab4ad0874a9ea37e9bbc721ed62d99f168c963014b3001f0cf6c14e23514263a0565600fb71a5e26002049cf5ade3eb568f1f983535cdf3230e0006ac1db716b859936dea1aea3a218e26b89df61f2e70b01d2943662c4b9524fadfc374457ef25df1196504186e287b3644bdd27a1cf9f2e5629cd8328485daeb1d1a9b4ebb6036c8e3d58bd03a5cd9cf0cc284a0a566933daae24c736d0d237238a862fdc162f9cf49f125aa4844836b93b2e339855387e016b3c8be4b2a11a0f05197009849b1b438cc73febb311d5ea99ed4c506b8870efaabce80fde64fe9d926f5994ddcf2001271fb6fcfa017eb95a6325f829fd6d282718e5530fab8f7614f808b0c3ed6bfb5b4c695ac81fc79ff6aa25e3006ba92cdbe5a0394b8a4af018c8cd3f75ca84d859009e58601a0f65820ff02781300d407489307fa34d82e41e83ed7f4200339bbfe4a4e4f695d47057d4e3cf3a32a49b4ddfc7630f7da4ef43c08ace8a10585b1b28600d3408480fe002da7879066ae65778fa1a7ff8b1c909cfb67389375cb2e87b88e1f0ad5002da3c1e56af5f61ee826ca68f1b43c126b730d3a98e74260eb85e8e7d16c29d2eb838c817fccfd95e001e98483c89dcbc7ce5dd263fb5d6fae473b7aa134338d9f2aa4e1b9791b3ba7291d0f2cc5b3161d7210ca3898080f10f9bfff60a5ba077e2993a6e05f7ecc57138475327f48ab9823de48611ebedd2a81f4eaa5818f8d85737a0080490cb811f848d89f2f6526950d3e4f29ba25b88897e1c9acdd21dc0c416f568fc7eb004d04abfddc4b8ba81525b0f4061f5714016c75e87136e55e1cdd188c9a610c0df5dd0e75928be741b5c479d5753becb17a2c04f5fcc73107b4898b0126a4c40a89274257a729937fdbe11d58bf8d4b8a133af505131742841ccc6f15b0f7afba0a5fc85e5f27e8dfb35556aa9c2e3ab000f1aab3aee43f925989f4eea0c16db35bcfe000dfb39809217639d990a5e873b41e280201d19f74144e20880d3fc197ea1ee43b58c5f5007e9726bbc9d02bde050235a7b43ccde28e5594332fb5a0c4c74d135485b5ca0aa7753417c29d98e3b0611c9274969d93d7ee79b891a8a51e879ab55156df657131a18bbd47d08a4c74932add44a5ae3c23a48d506871aa4ab16112588e55fd8ccf0c5d34a76f1cfe4b1d193dc579abb742c702c1409e9bc6a1c75c80acb6e7f47ddec40028e6fd6bcf2e4711da34726777745e26260a405938f3b8ca14c3eaffe62f0f81f8494d0043e92d3edcf4e1ff1eeb7ac6147e0f5cbf9f4224108e4712caa6a9f05c88bbc61e1ee6752854a82a69d844bd29b511aa9bc405d4b816be3fbbe88cbeff9ea3f9afe69427e53cf9c94d2d2a9a2dfd6b97cdecf487a737f038b690c06c64bed4a612a985d7ff39a03409966a7c7a36a4fe14742310e7129d7204ac4f90e6d38c8418a8fd008a0879501c9a3f4487cb4e54de8ccda7e80c3b71cb82ad0796684dbb25bfbba54bcf7b00e9d2f0f42d67e1eb7dce41d16b6321a17855640773e4777dfb2c4e442eb4cb23299b9163c79aa4d8f7b0108ceae05e75ba52e8657bfefbce5ac233cf09165d25fb6558d9c505d242da585e3582cc803e836d52ceb8f79c80998822c6d9700c9bacde86fdd7ff190417397f43240fbe1a99e0d1b079d0bb6cf99bc3f6afabe86257383500e0df83ba57029c374690cb3db338410d604ad9c8e584f3d46e5f7034bd7a439cc56f77002a758b158358edb7e79d0564a2b537aaecebfa773b238a89812f51f14819c2676fee0b63cd98339e30cfd4d680d17472084e559b7466324c2cb8d4d7b1d359e3cab74cffcb729fde7099aaefcc1db47bd45e02f65e67734a4cf199814981b055a860f0f1d7395dbbc0be5e5c34c386fb86cf598c09185c0f4fc0fdaf05f607eca2af8e0033f03cf1b90f73e98c322367e63c0bcebd1ac0104001f04561a8c35459564215a4d5f500b2b4a11997b246b3f22dd62f575c4e77508299c5d3251d07e61015aaee3771db8be7984c50d6723986d557fd60048eb04ae05505592349bccb9540b704bdaa4e8f637c2fb4f7cec654689df6931a95333b5970bf64c0d14dc95ac47ae59d096c08c67aa8eeb9b76fe686ceee88cd188189699422f0a2dead7082632847cbf1ca8fd74b00a5950020b8468012eeb5c9bcb6af199461af1de392ca52b6afd9061002378ee963e0ed0066185fbf1a6c68fae038bb4289771d9f2685655b6833fd332b0364d00298fffe5ac7c56a01ef1ab78d371fb9b485964316a3fd58500bbc2d9c64ab2f28ed5fbd9d56d6ac81fba17eaabfc26f141ee424a736df1975b005faed1cadabaef2fe83b404348f02ebbc90e58aad82743429bf4bfc25943f43496ef5884ef3442f116d0d666400cab999c88a4056c02af3154a3b0a1f59eb52fc48cf825fae45044f9b8f830ee6"
    // Computed via: ProofOfWork.powHashWithProof(for: Genesis.header(for: .testnet), params: ...)
    private static let genesisProofHex_testnet = "ffffff009b808d15b34f32907948a7dc017f7ff2e66eb7f478dedfe5837eb907f4505cb398f044efbe0349bbf691ea17de3e31a3539a3d327b7d3edf59ec5125041901680e58e9ce7422a4af96f622e131b91b0af613418b16a9b3427ad94dd2ac3ebd43783df23da302cd82063cd04c9471494bab36d199aa133ff926df678f2e3a54852023bf00a9a6b5dea5afcee52a52ef120fd2431f65627d210a673bed53cbad1c1a02052a7edf53001b1f2f07a798ddcb2f4385213e3b4dc58e68361c9c6eaaef53070d56dc6f9d3cbb8ab4906411f00d32c8ef7cf164ff5bdf90fda76a70f5e276e13c73f7abc87c7ad7255dd5c046e403d0720454bb499ed92350ab61713ff52bd52cce713833b58cbe99094384cdd49624047af7fa1091bca50f63877a88e46628b91bd20073b8ea64e20060e7b0b47a0fff710350c8eee2fc51d18a5119ecdd921e1300c4c008c91431e6049b43002bc533ce23702866dc8763c8c56ae573075e37ed48a966714025894bd68cab6419a72cdb3ddbe1d0d2191637f6267fe8567fb662b37b015e7ca941e6af96a6ed6a28ec78fbe28dcb406228fba5ee33f2c5736a7df86c39b456df5b0bc70dad2a9015523099afb3ebf17f0dfc9e981dde1fc4c906a5df9a464adb463c4d1e514447cdba002c955959491f48b9ce7d33e66b8842b10e5d14641f49e0da407d1eb413ae2a9e466d41003148642a5d72effe75572df416ba63f157c0d89e6f9a61fbfc749f27e474283080f901de1e31e0c9183d88182ccde5ea14379867bc53f9f7b0289d5509001cb3806ef9936db670b01fba03cc5fd7cc8098819fdcda362fb25953600ede0a7bb14cf72d800bac41914d40816c7945dc7ede474aa65234b0a840918e84254dc04386019400f0240c8a38be67659aed91dfbe0fd785523ef9b64d4813ba64899fa9336df44f35a616005383497d030a7464511ac91d36d1d3e3060ae8527357162a97f332dfcd016d3de1cedfc149695df3a75af218c72ab0b8424e68b85ec133c24fe0a40e1b6f8a2af09fa05ea5b9877f5a2520e1ad48d310bc91aa4f2c4ceb99ec8921d4f3087212718454ee97b62f3bf7afd975914ffb4868a03a0974dbdcd2d27539832ec52bc11e7458002856d35bff10f48c0de41c16916a1e33209ecab21fa80e5f35b3fb98ba05f83acd511b002b532f27efe52b4cedfaad8d06ebabf69d10ed9f5bad314a7003536a322ccf6f12302043cdfe3ad28fae1c0524f066fc4ba036163bb4e7067fa1747f4539684f6633e0e2665dc2a9fa196b645c86deb38d93e03b648f3c5095c75931e34a5f0c7715325c2754f5d95472d4692cd9e76c67e99604ae25cb97eea98f55b5de93d377743f001b1c12fe32359c8c76c159ea818be02eb325e1913926c3ef38c53be282286d9438bf8900818e97290388b544be2e74eb3b65c95b8c86833b1a0b63849f8045a5803310488529490c0a667e18d5a20c71007b12ef177dc46f8695c95a288f56558daa28609b5147f146fb5a3867ec869f852d7dfafa8b39f774ead67ab9a81bb6e4e5f55339b1f61056764f2eb05731c131f6903e35731e8f6e5525d4efdd8dfd70999bd626e8b8002f2325bf41012bc64505faaffb043f79ceeb2956f14216d78f2835945b17fde0e63f8b0070004f8e16b228d6d59457662ac1116074b108a742ce23ec4647a3a0efb253fb9a9b2f804a50cb06197d057f4fdfdc8a5f9843b8230a4eb766c25ef05e9e73c68e0040c2f0f7a773975b2f0028eab1aa73eacefbbeb8d7d41d9a63d494b663f1c7d1babaaba13e1abcc2b7c4ef8ee416a56f2285b932136c4127940c399ab9aca509a400b57da3acdc8cdc56aaaf7e17482307176e7d03d1cce3232b3db0086f267d5b8b6fe27f00afbee2d87487bb48db9deb6e445130cfbe3631e63c1a6974ade80782df000453b79f464b6fa5a45e2471ab137af2c41b7f3adef8c0041e1651b668735f2e810eecd8271e4b61fe7ed2e929771b29a3b0a7141ba6bc561963bab1d47c7047eb94313b856afc361a4145223cb738552ff1e34f400f0dc14448b60923fae93c4f92f9f5b3003a7c33c6d39b75cb3e1e76b67f4aaf7d7b87b0fc2919bef60597f2d00448f734014a7b002d998918b4d5ec113940f3c60f74d1475e14a8c207578d44a5faf5a3b467c2dc177eef681f26aa633f51014efe1aef795faacebf6e41ae65ee03b2936e60ac089856a17992144349d3b241acec2ed909461b01bc091f78e7c46abefc7de2de009b799c73851e9fb56b989912dbd54946c9dba966d000038b55fdfe1d9995dddcc76cd70002671ad81db79ca68499feadd8480224dd10492e4550ea4f32ce05e1a94c818f671c6f0018abdeb14c20ecfd8d4d4f43ac2f7b1718593c85cd2494f35501fa6c57e101444b3baf224053fedc832d41ea02bb5593779ecddb24d1fad190338a5ce4f73e1a7449db2162a8dff666bbd80f7122c2df1c73bfcdb0ee802d62f793bbb74d3299d26758e12497f0f396f89e3b1096fc4a0f05de80e6409271f16530c77ffbb442ee119f001898cea1baf745c3a403132038254f637353389f208b3d1f7f833b25bedde19f6590a900db124f7ab260babb5b2ab5de2170cef3d58d86db6f22cc6af2e22cff0713d47e001538292d7d35acee1d1a85fed498e77e7c7933a17e23c960d9fc95d2d4ef4ff2ff4b54be19ed8b2abf19c6f571a95e47c3c1fa5788c38fe35dde086de81a7918c4642a71d343b17ee628a9ed76cbb0b9e50b56cc33413e41dc93c6e1e867e289ac56001e36fc92d3fff264856792c26897e599228783c77884c1de323f331fdffd954d709a4f003c88da086a83a845aa9fb2753a6f7459375abd32348153c539d5766d2b769cf9f19c9b5a36b89219abe3c3efd1c9c7a20171f41bc2c028ebd9cb5392ca1d4030d9199731eaad77b1045c4db7370f61f4c0ce68895d3b31372d281c6b82d8979294fa13eda4dfaf4cd55ffed554f8d48a3775f9a242e967d8d6d30f01d106a5e47a269000e80443a4b4f4658aa297c2a4067eb83a36c3316ff10eb59004e2d24c3bf6656fefc9bd00e27cc0c880a107f9a3ea7de04b3af05ac39738aea1cd5f92990d342010cce8325b9f33b79bda712d7510d7a0782fd072d186910bcaa28c53d7562207906d38dbfb1bf701d342fab5e4297be93f38bc55949ea3f5ddcffe0d6f62a0135d1cc25d7e85565ad040d807c056609c87a1d53d9d8f8d931ca9e40d6793094f12d41c64cef32a0023372a489d4957117b4c6edb730348a8654509313d673786a4ff8d7397428bd9329bf000c0e1ab9f8b1c8b81f9dada2e7a915df4e673f453fdfe432188cc173b4d2f55cd8f0c3eaf306a91b03b493ee8d4dde10eae0366ed4c704baa8682c477a816b837b51bf315e28981e3faaaa38299c18f0f313382614ba08d2da0391f6e573ade4aa2c3780254d11ab5d8feca3c7a50e18a27012d7c888b7ce2db68e95383aabc77cb59e300c748415f7c36e4d5fd36df02808521e5817d7ad3a1dc71b0183bb2e0f231ec2aac304a00409538d92def5725da156e097c998740ae66bfd47e5fc1043b2783ebf8937b3ded57e522967c778ee4c06b5cd96a6611bb11b12a8a6e79dd1c74f3082ad8a8fc5d7dc928657894601391a40ee1b0af165e2dceda20777864547b3dadfa115e8ca7f5cd703fd3ae3c737bec4b89bec72d7b99763d7b0c22a0d4cac71fd1a1a8e38b1cfd007fe6c5184c3bd24ba1eda92b6ee8ea03d690d80b68f9279a605ea919e276d7e9680ca5001902e72f4093fb5bc322cf850718a7930f7960aa8a197e3ce5c366406d00e54a415bbf45efaa45d16e4b120a33feae065a464e249a2bd5eb6d74f49099d294e3b0d512f3a9a273f68649bb36e2ad47414098f64882428558be5d4f7e5e7dbaefc4d9db1df2aeefed950d848474ff1dafb59d39aef885659e27ccdb4010cc7ca48d9ebf00b03cc537f76699f82f2fb10053e3c7ee0c47227b104230198d7bad47a3ef1ff839360900d355d3acefc72f1fff92d45b0e1fdb5691deebce82bac7881fef8adc0f889c429e7c752bf661ac9b4da34550315bf2232b60e92c4291270273c71affa7520b23d67a10c14b63975d68bf185774a809322d95e32848b2ee3ec08229b4c8be9d86ef70523d39ce8198fe1f60c9c8254517ef56d956703a8c6ad19179fc208c9ab4b51e080038aa2fdbc789c841c18317dca4661f1c6b7d2a7089f2c7fd95807dd18a65f6a8b7c81c00f2018965c1c37d5e6dc7d6c601b972456ceefbdf8081a724a59ac21d31eb96addba2616ed8e0c1cd227d3bffaf87c62ce633c4c907c1915b2899888ec772e66aa9fca475f614d84f52ddee9a495ad52e3042458c354b3a8ec7294242d28c22bd814731b03c328d88b7eec5efed557a851d901aecf6db87b4e393313914810a95cec60500b86410f873db9443d21449b949256e7616c34ce07144f20b15ebba5f4d49d05baa733d009f0c0b1481222748ef7d9afc6601ba49536d2efe136c50fa82f4a7448d73a49ea6da1dfefd892d74124d446d5b830d82264375582f93dca08916eb4577afe33757b882b4c45ab6fc2478d4094ca14ba08e0756d5bd996a75a346cf1e74262870005e3248d77822602b5a1322442f9fbb8c834d7fbcf6f0c0bc65de47c03e1b14b46ed200e946dcfa5ab3b80ecc957d7c05b271c76fec0c146958cbb9f37c97c09d297901aef12b00f5b39e8b9185f8ecec9ea1f35dd82f8a3bb41812d6ffa0c7e0af8d4ea0832e3edded910d100fb9d375b53f4094371e082b35cfb7ca4aabbe3c1efcb4947c99d7bd7bef94a696c512abccc10e65faf955787464eb27ab8a4b4501d4050dd4b265ad47f9345333b39a0d0492aaf5d915f570955f031071ac208ab8ded4d077e547fb5d8000c7be7c81432a7a7814f97a3c723ed9462a30fba4884d34abd08724ed6d81fdbf468f9100eecd204e199f6ebce0e1965aaa14424c13d93f27c87e43434c1877acffe026eaff68389fab6ddffc29d07e78fff06b7fb87d3e8f92fea0886e416ee0ee8d2432ead6f4a3bc3850006cacdb07138141bfbf7fe5511ff1363722f5c5f6addd697742c00462cab3297a903576050e8cf02b7fca1e4dcbf839be499dde79d9dd68310841c30000f9f064dc84de51ef74de229215b27bea0883c4dfce6f19d98e263557722ebc33e029006d4db311b06760b63566a354a9b0ae6b17d7c0aabe99e9eba5badb71b3e716b18dc7915e68865958240c6fb32dcbc95c637df5e6a05a6b9841adddc889d4b248a98d4d7236035610942026d59026a5e3da57ab0ee1259d91d1d22f98a62174f31d9d6f7a516f8ca3990437e24ce99bf4f313c232cff4c25dbff0ae9800cde08843908d000f03c4d3eee16befa5d20001f2c0ed80aa509083eddaa1dd31a11ca389ef271b447636008c1bb316982280040cdb2c59726564fc8f4c89577276be3aa50b0646f534668bd49b67285b5f32b1648468c94125257d7760021ee547e4073fe841d7fddf8ab7edcbb3a4d249ed621f780aef4db56a79def4e535043636fa920ba88ecf82ea2b0faa5be424b3627e9fd4bf24b5829c585659fa3073c58a63c15bc4ba79965656a84f39003a62feb69d1669e1b74d3141413b71ae7369c34305509064373c73fd1c9fbc6533bd2d007e15f2b67ef756fa9ef9be36cdca80fe9567cba36bb675312a8912da84f93f0b56a44cbb6893091d74259d0b0bcb875b745671f0eb3e6ea773dbd77f486c0a9322699a586e8d4301f2e60056e3a1228779aff43bc639b9a09bbb52289e12ab5e9a99360928840acca840180d109e75002ec9550cc8c2d59cc546839f71bcbd932be13300b99b54da46007b08aa81989ab1404f39cfb11df45b55301ba3f12143db9145b06aed54007ab2c8c805abcbde6435cdc898381c5543e09e34ef84b3a564ccb0eb5df57cad5cea4928921d5c4cbfac8f768c2f74eab2f3b9668c462702148b7486b7afe5e39dba7d031834cb9c03c95fd74923cb8bd861a40e1c75ac4a84671e7db3f99351bc8b2bef5cbd1f3ed3187dd949d44779c5f3d73e5e728638c03fe700d7c3d3f59403b40072d4291ffd51b05c30de4bfede1d93493540e671dda3cc6d9f2db700c8fe506b218f470027d6caf2e2c8b87277fd81031aeb19323b19a00aa1ffae3c783ec317dcb48ed8bb288387093b9c49cb3356132fc2b64cadea96dbb86ce637be8b3cf77efb9926e0bc7a4696f5c527fbc058c0df89d2308a7ada547c7767f01aca9ac5ede972f7bf28e2b39437f2363f23bea36c1a7b20076ec744d165cf4cc0aac0607d89dbd42527c80047782668e5eb249d3bec1165e6f2f3958f506d6b389a6deed9c07a5cc88c41d21fe5310049054cbb055099f44abb1410db269d13367a8917baa48ef164aebfd9279a19e72ad2fdd1aa5c4ee8d7256243eff25192673f58339114112eaf0eeb2ba501c54b2d1afff84cd4050977e97a40b3df37c5e348570910d5129b3e28446f8cc280205564d7985ab34cc82a0a22111ff30bc3c949f6818de0fc1468a0c801e3461f4ce980a900aafb1ec36c6a1c798a57f53d6f7423931c2b3274474cd0df506285fb3ff072735dc4f4005095b5af05474f8c91dc36a3bc996e4896801baa6693d90d8f08a5dd0c2b45810c5319304cbe72482b5d2b47bf261915546a69fb82ae08145bd14982093b35dd389ee330f322b0d55d7bd26459af37ba11ed533aab9fd722d4fdff8f3e0b41450bdd5b6ff19f6ce36ea690be1477a1f69b9bac52479297267c05c48b63511222cf5a5700d64dce7eda986ce6909114d923f51954045f607f2864c20164acb24ec2983f2a395e93003dc0d322c5ea35191d810a0a5f017c3d70d5dfa3d9022b892c5eee35f682fa5187b96fa7b0d57f8224f6513bc7b90e1fdcb8bdaf74b0741321edefad29456dc41b58255cff73a1bce7178707bacfabb02a9a76fc18714074d1781c7fb362027f4e87c7bb8020180e8f9ef770cec4265ac930cca925ad342f3ad72d40d0412eefb7858400182c48ff5a0b35b0e8f77d025827330e4436fb799e456114ffc23a8db29eb46b5ee97d00b5d4cc8000ebf24432c8ea442696e8d2a43d6a0568413d962ceb745dca0c318cf4ad5e1bce5b8bdfac0b15fed0ef027506a3d329d7546bbb2c014f1174deee667f8c5a0120ea9446d4a5bb974ffead9c5df9c0167eb7bb9abfe3cf4dc08948f93720dd22bc1b2ad28fb7299401d44d9f0452c7e8f6b8dddf778c547c3c612f704410a2003dac37d048d42f7c0a1439841bea06fe86af2ed92fbd98d569a9a5d33bf918f042f94a000e0d32ea76765c0521e607d8a7bf9ab225ac0a32920e731ffa375f8b6fbdb790594c3868320a864368f5a5217ca42cbc13baa7fb0d171c2f4b9d3a43be0cfb9147f449486b74e99052e08e13b6e4ef3ac15d5d26c4a682bdddce81feff58f9e37b6b5bf3f520314199dfdee45cbd99b590c80a8b6a6ff8f5fc2b27bb777bd77c534db300afb418fa2b7240e35922274b24e9e6e764ab13de7345f57334797f194abde01e"
    // swiftlint:enable line_length

    /// Pre-computed genesis PoW hash per network.
    /// Avoids recomputing the 512 MB BalloonHash (~30s) on every startup.
    private static func genesisHash(for network: NetworkType) -> Hash256? {
        switch network {
        case .main:
            return try? Hash256.fromHex("09bb35792f7751242938df198bf4a50393f47052075d16ba4d94ec21d771c7b8")
        case .testnet:
            return try? Hash256.fromHex("0e58e9ce7422a4af96f622e131b91b0af613418b16a9b3427ad94dd2ac3ebd43")
        case .regtest, .simnet:
            return nil // Cheap to compute (4 slots)
        }
    }

    /// Get the genesis chain entry for a network.
    public static func entry(for network: NetworkType) throws -> ChainEntry {
        let hdr = header(for: network)

        if let hash = genesisHash(for: network) {
            let chainwork = DifficultyRetarget.targetToWork(hdr.bits)
            return ChainEntry(
                hash: hash,
                version: hdr.version,
                prevBlock: hdr.prevBlock,
                merkleRoot: hdr.merkleRoot,
                witnessRoot: hdr.witnessRoot,
                treeRoot: hdr.treeRoot,
                reservedRoot: hdr.reservedRoot,
                time: hdr.time,
                bits: hdr.bits,
                nonce: hdr.nonce,
                extraNonce: hdr.extraNonce,
                mask: hdr.mask,
                height: 0,
                chainwork: chainwork
            )
        }

        let params = ConsensusParams.params(for: network)
        return try ChainEntry.fromBlock(hdr, prev: nil, slots: params.balloonSlots, rounds: params.balloonRounds, delta: params.balloonDelta)
    }

    /// Pre-mined nonce for each network's genesis block.
    ///
    /// Regtest and simnet use easy difficulty (0x207fffff) where nonce=0 works.
    /// Mainnet and testnet genesis nonces are pre-computed.
    private static func genesisNonce(for network: NetworkType) -> UInt32 {
        switch network {
        case .main:    return 2
        case .testnet: return 2
        case .regtest: return 0
        case .simnet:  return 0
        }
    }
}
