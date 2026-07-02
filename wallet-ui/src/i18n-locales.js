// Locale data for the HD Wallet WASM site — the world's top 10 languages by
// number of native speakers. Non-English strings are machine-quality
// translations intended for native-speaker review. Product names, protocol
// identifiers (BIP-32, WASM, X.509, secp256k1, EIP-…), and link labels such as
// "npm"/"GitHub" are intentionally left untranslated.

export const LANGS = [
  { code: "en", native: "English" },
  { code: "zh", native: "中文" },
  { code: "hi", native: "हिन्दी" },
  { code: "es", native: "Español" },
  { code: "ar", native: "العربية" },
  { code: "fr", native: "Français" },
  { code: "bn", native: "বাংলা" },
  { code: "pt", native: "Português" },
  { code: "ru", native: "Русский" },
  { code: "ur", native: "اردو" },
];

export const RTL_LANGS = ["ar", "ur"];

const en = {
  "lang.label": "Language",
  "nav.packages": "Packages",
  "nav.features": "Features",
  "nav.quickstart": "Quick Start",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "Blockchains",
  "nav.security": "Security",
  "nav.login": "Login",
  "nav.logout": "Logout",
  "nav.account": "Account",
  "hero.subtitle":
    "A comprehensive hierarchical deterministic wallet implementation in pure C++, compiled to WebAssembly for cross-platform compatibility. BIP-32/39/44 compliant with multi-curve cryptography and multi-chain support.",
  "hero.demo": "Try Interactive Demo",
  "packages.heading": "Packages",
  "packages.wasm.desc":
    "Core WebAssembly library. BIP-32/39/44 HD key derivation, multi-curve cryptography, X.509 certificate issuance, wallet attestations, address generation, signing, and encryption for 50+ blockchains.",
  "packages.ui.desc":
    "Drop-in modal UI for any web app. Provides login, key management, identity (vCard), trust map, and adversarial security bond modals. Attach to any button — fully styleable via CSS custom properties.",
  "packages.ui.note":
    'Headless utilities (address derivation, wallet storage) are also available via <code>hd-wallet-ui/lib</code>.',
  "features.heading": "Features",
  "features.bip.title": "BIP Standards Compliant",
  "features.bip.desc":
    "Full implementation of BIP-32 (HD keys), BIP-39 (mnemonic phrases), BIP-44/49/84 (account hierarchy), and SLIP-44 (coin types).",
  "features.curve.title": "Multi-Curve Cryptography",
  "features.curve.desc":
    "Support for secp256k1 (Bitcoin, Ethereum), Ed25519 (Solana, Polkadot), NIST P-256, P-384, and X25519 key exchange.",
  "features.chain.title": "Multi-Chain Support",
  "features.chain.desc":
    "Bitcoin (all address types), Ethereum/EVM, Solana, Cosmos/Tendermint, Polkadot/Substrate, and 50+ coins via SLIP-44.",
  "features.wasm.title": "WebAssembly Native",
  "features.wasm.desc":
    "Compiled to WASM for browser, Node.js, and WASI runtimes. Works with Go, Rust, Python, and any WASI-compatible host.",
  "features.x509.title": "X.509 and Wallet Proofs",
  "features.x509.desc":
    "Issue standard P-256/P-384 certificates, exchange PEM/DER/PKCS#12, and embed wallet attestations that bind a certificate to a selected crypto key.",
  "features.hw.title": "Hardware Wallet Support",
  "features.hw.desc":
    "Abstraction layer for Trezor, Ledger, and KeepKey devices with WASI bridge integration for USB/HID communication.",
  "features.sec.title": "Security First",
  "features.sec.desc":
    "Secure memory wiping, optional FIPS-compliant mode, and comprehensive input validation for production use.",
  "quickstart.heading": "Quick Start",
  "quickstart.addresses": "Addresses",
  "quickstart.signing": "Signing",
  "quickstart.encryption": "Encryption",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "Standard Web PKI for TLS and device identity, with a wallet-backed attestation layer that binds certificates to HD-wallet keys.",
  "pki.eyebrow": "Why we use it",
  "pki.title": "X.509 is what the rest of the internet already understands",
  "pki.p1":
    "Browsers, load balancers, reverse proxies, mTLS deployments, device identity systems, and keystore tooling all already speak X.509. That means if we want a certificate that real infrastructure can consume, we use normal Web PKI instead of inventing a repo-local identity format.",
  "pki.p2":
    "What hd-wallet-wasm adds is a second proof path: the certificate can carry a wallet attestation signed by a selected wallet key. The certificate remains interoperable for TLS, and applications that care about wallet identity can verify the extra proof.",
  "pki.tag.attest": "Wallet Attestations",
  "pki.flow.gen": "Generate Cert Key",
  "pki.flow.issue": "Issue X.509 Cert",
  "pki.flow.embed": "Embed Wallet Proof",
  "pki.flow.verify": "Verify Chain + Wallet",
  "pki.card1.title": "How It Works",
  "pki.card1.desc":
    "Certificate issuance stays on regular P-256 or P-384 keys. The repo can create self-signed certs, issue subordinates, convert PEM and DER, and package material as PKCS#12 for normal keystores.",
  "pki.card2.title": "Why It Matters",
  "pki.card2.desc":
    "Standard TLS tooling gets a normal certificate. Wallet-aware verifiers get an additional proof that the certificate was attested by a selected wallet key without replacing the existing PKI chain.",
  "pki.card3.title": "How We Use It",
  "pki.card3.desc":
    "The wallet attestation signs canonical certificate fields including the SPKI digest. That creates a durable binding between the certificate and the chosen wallet identity, such as a Bitcoin-root secp256k1 key.",
  "pki.card4.title": "What Verifiers Check",
  "pki.card4.desc":
    "First validate the normal X.509 chain. Then parse the certificate and verify the embedded wallet proof. Both need to pass if you want to prove a server certificate was bound by a wallet key.",
  "chains.heading": "Supported Blockchains",
  "chains.sol.sub": "Ed25519 signatures",
  "chains.atom.sub": "Amino & Direct signing",
  "chains.dot.sub": "SS58 addresses",
  "chains.ltc.sub": "All address types",
  "chains.doge.sub": "P2PKH addresses",
  "chains.more": "+ 50 more",
  "chains.more.sub": "via SLIP-44",
  "adv.heading": "Adversarial Security",
  "adv.subheading":
    "Rational actors drain compromised keys. Undrained value proves key integrity.",
  "adv.intro.title": "What is Adversarial Security?",
  "adv.intro.desc":
    "Cryptographic public keys can derive addresses on cryptocurrency networks. By depositing value at those derived addresses, you create a <strong>game-theoretic security bond</strong>. A rational actor who compromises the private key will drain the funds — the payout is immediate, anonymous, and risk-free. This makes the balance a <strong>real-time indicator of key integrity</strong>: undrained value implies an uncompromised key.",
  "adv.flow.pubkey": "Public Key",
  "adv.flow.derive": "Derive Address",
  "adv.flow.deposit": "Deposit Value",
  "adv.flow.monitor": "Monitor",
  "adv.flow.trusted": "Trusted",
  "adv.prin1.title": "Key Derivation",
  "adv.prin1.desc":
    "A public key used for signing data can mathematically derive addresses on multiple blockchain networks (BIP-32/44). One key pair serves both authentication and value custody.",
  "adv.prin2.title": "Value as Trust Signal",
  "adv.prin2.desc":
    "Derived addresses are permissionless — anyone can deposit funds to signal trust in a key. The aggregate balance quantifies the economic cost of compromise.",
  "adv.prin3.title": "Rational Actor Assumption",
  "adv.prin3.desc":
    "Draining funds is the dominant strategy: it's <strong>immediate, irreversible, and carries zero marginal risk</strong>. Undrained value therefore implies no compromise.",
  "adv.prin4.title": "Real-Time Verification",
  "adv.prin4.desc":
    "Blockchain state is publicly auditable and updates every block. This provides <strong>continuous, permissionless proof of key integrity</strong> — not a certificate, but a live signal.",
  "adv.whitepaper": "Read the Whitepaper",
  "adv.login.prompt":
    "Login to derive addresses from your keys and check live balances across multiple blockchain networks.",
  "adv.balances.title": "Your Derived Addresses",
  "adv.refresh": "Refresh",
  "adv.balances.intro":
    "These addresses are mathematically derived from your HD wallet keys. Anyone can verify the derivation and send funds to increase trust in your keys.",
  "footer.license": "HD Wallet WASM — Apache-2.0 License",
};

const zh = {
  "lang.label": "语言",
  "nav.packages": "软件包",
  "nav.features": "功能",
  "nav.quickstart": "快速开始",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "区块链",
  "nav.security": "安全",
  "nav.login": "登录",
  "nav.logout": "退出登录",
  "nav.account": "账户",
  "hero.subtitle":
    "一个用纯 C++ 实现的完整分层确定性钱包，编译为 WebAssembly 以实现跨平台兼容。符合 BIP-32/39/44 标准，支持多曲线密码学和多链。",
  "hero.demo": "试用交互式演示",
  "packages.heading": "软件包",
  "packages.wasm.desc":
    "核心 WebAssembly 库。BIP-32/39/44 分层密钥派生、多曲线密码学、X.509 证书签发、钱包证明、地址生成、签名，以及面向 50 多条区块链的加密。",
  "packages.ui.desc":
    "适用于任何 Web 应用的即插即用模态界面。提供登录、密钥管理、身份（vCard）、信任图谱和对抗式安全押金模态框。可绑定到任意按钮 — 通过 CSS 自定义属性完全可定制样式。",
  "packages.ui.note":
    '无界面工具（地址派生、钱包存储）也可通过 <code>hd-wallet-ui/lib</code> 使用。',
  "features.heading": "功能",
  "features.bip.title": "符合 BIP 标准",
  "features.bip.desc":
    "完整实现 BIP-32（分层密钥）、BIP-39（助记词）、BIP-44/49/84（账户层级）和 SLIP-44（币种类型）。",
  "features.curve.title": "多曲线密码学",
  "features.curve.desc":
    "支持 secp256k1（比特币、以太坊）、Ed25519（Solana、Polkadot）、NIST P-256、P-384 以及 X25519 密钥交换。",
  "features.chain.title": "多链支持",
  "features.chain.desc":
    "比特币（所有地址类型）、以太坊/EVM、Solana、Cosmos/Tendermint、Polkadot/Substrate，以及通过 SLIP-44 支持的 50 多种币种。",
  "features.wasm.title": "原生 WebAssembly",
  "features.wasm.desc":
    "编译为 WASM，适用于浏览器、Node.js 和 WASI 运行时。可与 Go、Rust、Python 及任何兼容 WASI 的宿主环境配合使用。",
  "features.x509.title": "X.509 与钱包证明",
  "features.x509.desc":
    "签发标准 P-256/P-384 证书，交换 PEM/DER/PKCS#12，并嵌入将证书绑定到选定加密密钥的钱包证明。",
  "features.hw.title": "硬件钱包支持",
  "features.hw.desc":
    "面向 Trezor、Ledger 和 KeepKey 设备的抽象层，通过 WASI 桥接实现 USB/HID 通信。",
  "features.sec.title": "安全至上",
  "features.sec.desc":
    "安全内存擦除、可选的 FIPS 合规模式，以及面向生产环境的全面输入校验。",
  "quickstart.heading": "快速开始",
  "quickstart.addresses": "地址",
  "quickstart.signing": "签名",
  "quickstart.encryption": "加密",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "用于 TLS 和设备身份的标准 Web PKI，并配有将证书绑定到分层钱包密钥的钱包证明层。",
  "pki.eyebrow": "我们为何采用它",
  "pki.title": "X.509 是互联网其余部分早已理解的标准",
  "pki.p1":
    "浏览器、负载均衡器、反向代理、mTLS 部署、设备身份系统和密钥库工具都已支持 X.509。这意味着，若希望证书能被真实基础设施使用，我们就采用普通的 Web PKI，而不是发明仓库专用的身份格式。",
  "pki.p2":
    "hd-wallet-wasm 增加的是第二条证明路径：证书可携带由选定钱包密钥签名的钱包证明。证书对 TLS 仍然可互操作，而关注钱包身份的应用可以验证这一额外证明。",
  "pki.tag.attest": "钱包证明",
  "pki.flow.gen": "生成证书密钥",
  "pki.flow.issue": "签发 X.509 证书",
  "pki.flow.embed": "嵌入钱包证明",
  "pki.flow.verify": "验证证书链 + 钱包",
  "pki.card1.title": "工作原理",
  "pki.card1.desc":
    "证书签发仍使用常规的 P-256 或 P-384 密钥。本仓库可创建自签名证书、签发下级证书、转换 PEM 与 DER，并将材料打包为 PKCS#12 以供常规密钥库使用。",
  "pki.card2.title": "为何重要",
  "pki.card2.desc":
    "标准 TLS 工具获得普通证书。支持钱包的验证方则获得额外证明，表明证书由选定钱包密钥背书，且无需替换现有 PKI 链。",
  "pki.card3.title": "我们如何使用",
  "pki.card3.desc":
    "钱包证明对包括 SPKI 摘要在内的规范化证书字段进行签名。这在证书与所选钱包身份（例如比特币根 secp256k1 密钥）之间建立了持久绑定。",
  "pki.card4.title": "验证方检查什么",
  "pki.card4.desc":
    "首先验证普通的 X.509 链。然后解析证书并验证内嵌的钱包证明。若要证明服务器证书由钱包密钥绑定，两者都必须通过。",
  "chains.heading": "支持的区块链",
  "chains.sol.sub": "Ed25519 签名",
  "chains.atom.sub": "Amino 与 Direct 签名",
  "chains.dot.sub": "SS58 地址",
  "chains.ltc.sub": "所有地址类型",
  "chains.doge.sub": "P2PKH 地址",
  "chains.more": "+ 50 余种",
  "chains.more.sub": "通过 SLIP-44",
  "adv.heading": "对抗式安全",
  "adv.subheading": "理性行为者会转走被泄露的密钥中的资金。未被转走的价值证明了密钥的完整性。",
  "adv.intro.title": "什么是对抗式安全？",
  "adv.intro.desc":
    "加密公钥可在加密货币网络上派生地址。通过向这些派生地址存入价值，你便建立了一个<strong>博弈论安全押金</strong>。任何泄露私钥的理性行为者都会转走资金 — 这笔收益即时、匿名且无风险。因此余额成为<strong>密钥完整性的实时指标</strong>：未被转走的价值意味着密钥未被泄露。",
  "adv.flow.pubkey": "公钥",
  "adv.flow.derive": "派生地址",
  "adv.flow.deposit": "存入价值",
  "adv.flow.monitor": "监控",
  "adv.flow.trusted": "可信",
  "adv.prin1.title": "密钥派生",
  "adv.prin1.desc":
    "用于签名数据的公钥可通过数学方式在多个区块链网络上派生地址（BIP-32/44）。同一密钥对既用于身份验证，也用于价值保管。",
  "adv.prin2.title": "价值即信任信号",
  "adv.prin2.desc":
    "派生地址无需许可 — 任何人都可存入资金以表明对某密钥的信任。总余额量化了泄露的经济成本。",
  "adv.prin3.title": "理性行为者假设",
  "adv.prin3.desc":
    "转走资金是占优策略：它<strong>即时、不可逆且边际风险为零</strong>。因此未被转走的价值意味着未发生泄露。",
  "adv.prin4.title": "实时验证",
  "adv.prin4.desc":
    "区块链状态可公开审计并逐块更新。这提供了<strong>持续、无需许可的密钥完整性证明</strong> — 不是证书，而是实时信号。",
  "adv.whitepaper": "阅读白皮书",
  "adv.login.prompt": "登录以从你的密钥派生地址，并跨多个区块链网络查看实时余额。",
  "adv.balances.title": "你的派生地址",
  "adv.refresh": "刷新",
  "adv.balances.intro":
    "这些地址通过数学方式从你的分层钱包密钥派生而来。任何人都可以验证该派生并发送资金以增强对你密钥的信任。",
  "footer.license": "HD Wallet WASM — Apache-2.0 许可证",
};

const hi = {
  "lang.label": "भाषा",
  "nav.packages": "पैकेज",
  "nav.features": "विशेषताएँ",
  "nav.quickstart": "त्वरित शुरुआत",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "ब्लॉकचेन",
  "nav.security": "सुरक्षा",
  "nav.login": "लॉग इन",
  "nav.logout": "लॉग आउट",
  "nav.account": "खाता",
  "hero.subtitle":
    "शुद्ध C++ में एक व्यापक पदानुक्रमिक नियतात्मक (HD) वॉलेट कार्यान्वयन, जिसे क्रॉस-प्लेटफ़ॉर्म संगतता के लिए WebAssembly में संकलित किया गया है। BIP-32/39/44 अनुरूप, बहु-वक्र क्रिप्टोग्राफी और बहु-श्रृंखला समर्थन के साथ।",
  "hero.demo": "इंटरैक्टिव डेमो आज़माएँ",
  "packages.heading": "पैकेज",
  "packages.wasm.desc":
    "मुख्य WebAssembly लाइब्रेरी। BIP-32/39/44 HD कुंजी व्युत्पत्ति, बहु-वक्र क्रिप्टोग्राफी, X.509 प्रमाणपत्र जारी करना, वॉलेट प्रमाणन, पता निर्माण, हस्ताक्षर, और 50+ ब्लॉकचेन के लिए एन्क्रिप्शन।",
  "packages.ui.desc":
    "किसी भी वेब ऐप के लिए ड्रॉप-इन मोडल UI। लॉगिन, कुंजी प्रबंधन, पहचान (vCard), ट्रस्ट मानचित्र और विरोधात्मक सुरक्षा बॉन्ड मोडल प्रदान करता है। किसी भी बटन से जोड़ें — CSS कस्टम प्रॉपर्टीज़ के माध्यम से पूर्णतः शैली-योग्य।",
  "packages.ui.note":
    'हेडलेस उपयोगिताएँ (पता व्युत्पत्ति, वॉलेट भंडारण) भी <code>hd-wallet-ui/lib</code> के माध्यम से उपलब्ध हैं।',
  "features.heading": "विशेषताएँ",
  "features.bip.title": "BIP मानकों के अनुरूप",
  "features.bip.desc":
    "BIP-32 (HD कुंजियाँ), BIP-39 (स्मरक वाक्यांश), BIP-44/49/84 (खाता पदानुक्रम) और SLIP-44 (सिक्का प्रकार) का पूर्ण कार्यान्वयन।",
  "features.curve.title": "बहु-वक्र क्रिप्टोग्राफी",
  "features.curve.desc":
    "secp256k1 (बिटकॉइन, एथेरियम), Ed25519 (Solana, Polkadot), NIST P-256, P-384 और X25519 कुंजी विनिमय के लिए समर्थन।",
  "features.chain.title": "बहु-श्रृंखला समर्थन",
  "features.chain.desc":
    "बिटकॉइन (सभी पता प्रकार), एथेरियम/EVM, Solana, Cosmos/Tendermint, Polkadot/Substrate, और SLIP-44 के माध्यम से 50+ सिक्के।",
  "features.wasm.title": "मूल WebAssembly",
  "features.wasm.desc":
    "ब्राउज़र, Node.js और WASI रनटाइम के लिए WASM में संकलित। Go, Rust, Python और किसी भी WASI-संगत होस्ट के साथ काम करता है।",
  "features.x509.title": "X.509 और वॉलेट प्रमाण",
  "features.x509.desc":
    "मानक P-256/P-384 प्रमाणपत्र जारी करें, PEM/DER/PKCS#12 का आदान-प्रदान करें, और प्रमाणपत्र को चयनित क्रिप्टो कुंजी से बाँधने वाले वॉलेट प्रमाणन एम्बेड करें।",
  "features.hw.title": "हार्डवेयर वॉलेट समर्थन",
  "features.hw.desc":
    "USB/HID संचार के लिए WASI ब्रिज एकीकरण के साथ Trezor, Ledger और KeepKey उपकरणों के लिए अमूर्तन परत।",
  "features.sec.title": "सुरक्षा सर्वोपरि",
  "features.sec.desc":
    "सुरक्षित मेमोरी मिटाना, वैकल्पिक FIPS-अनुरूप मोड, और उत्पादन उपयोग हेतु व्यापक इनपुट सत्यापन।",
  "quickstart.heading": "त्वरित शुरुआत",
  "quickstart.addresses": "पते",
  "quickstart.signing": "हस्ताक्षर",
  "quickstart.encryption": "एन्क्रिप्शन",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "TLS और डिवाइस पहचान के लिए मानक वेब PKI, प्रमाणपत्रों को HD-वॉलेट कुंजियों से बाँधने वाली वॉलेट-समर्थित प्रमाणन परत के साथ।",
  "pki.eyebrow": "हम इसका उपयोग क्यों करते हैं",
  "pki.title": "X.509 वही है जिसे शेष इंटरनेट पहले से समझता है",
  "pki.p1":
    "ब्राउज़र, लोड बैलेंसर, रिवर्स प्रॉक्सी, mTLS परिनियोजन, डिवाइस पहचान प्रणालियाँ और कीस्टोर उपकरण — ये सभी पहले से X.509 बोलते हैं। इसका अर्थ है कि यदि हमें ऐसा प्रमाणपत्र चाहिए जिसे वास्तविक बुनियादी ढाँचा उपयोग कर सके, तो हम रिपॉजिटरी-विशिष्ट पहचान प्रारूप गढ़ने के बजाय सामान्य वेब PKI का उपयोग करते हैं।",
  "pki.p2":
    "hd-wallet-wasm जो जोड़ता है वह एक दूसरा प्रमाण-पथ है: प्रमाणपत्र चयनित वॉलेट कुंजी द्वारा हस्ताक्षरित वॉलेट प्रमाणन ले जा सकता है। प्रमाणपत्र TLS के लिए अंतर-संचालनीय बना रहता है, और वॉलेट पहचान की परवाह करने वाले अनुप्रयोग इस अतिरिक्त प्रमाण को सत्यापित कर सकते हैं।",
  "pki.tag.attest": "वॉलेट प्रमाणन",
  "pki.flow.gen": "प्रमाणपत्र कुंजी बनाएँ",
  "pki.flow.issue": "X.509 प्रमाणपत्र जारी करें",
  "pki.flow.embed": "वॉलेट प्रमाण एम्बेड करें",
  "pki.flow.verify": "श्रृंखला + वॉलेट सत्यापित करें",
  "pki.card1.title": "यह कैसे काम करता है",
  "pki.card1.desc":
    "प्रमाणपत्र जारी करना सामान्य P-256 या P-384 कुंजियों पर ही रहता है। रिपॉजिटरी स्व-हस्ताक्षरित प्रमाणपत्र बना सकती है, अधीनस्थ जारी कर सकती है, PEM और DER परिवर्तित कर सकती है, और सामान्य कीस्टोर के लिए सामग्री को PKCS#12 के रूप में पैकेज कर सकती है।",
  "pki.card2.title": "यह क्यों मायने रखता है",
  "pki.card2.desc":
    "मानक TLS उपकरणों को सामान्य प्रमाणपत्र मिलता है। वॉलेट-सजग सत्यापनकर्ताओं को एक अतिरिक्त प्रमाण मिलता है कि प्रमाणपत्र किसी चयनित वॉलेट कुंजी द्वारा प्रमाणित है, बिना मौजूदा PKI श्रृंखला को बदले।",
  "pki.card3.title": "हम इसका उपयोग कैसे करते हैं",
  "pki.card3.desc":
    "वॉलेट प्रमाणन SPKI डाइजेस्ट सहित विहित प्रमाणपत्र क्षेत्रों पर हस्ताक्षर करता है। यह प्रमाणपत्र और चुनी गई वॉलेट पहचान (जैसे बिटकॉइन-रूट secp256k1 कुंजी) के बीच एक टिकाऊ बंधन बनाता है।",
  "pki.card4.title": "सत्यापनकर्ता क्या जाँचते हैं",
  "pki.card4.desc":
    "पहले सामान्य X.509 श्रृंखला सत्यापित करें। फिर प्रमाणपत्र का विश्लेषण करें और एम्बेडेड वॉलेट प्रमाण सत्यापित करें। यदि आप सिद्ध करना चाहते हैं कि सर्वर प्रमाणपत्र किसी वॉलेट कुंजी द्वारा बाँधा गया था, तो दोनों का उत्तीर्ण होना आवश्यक है।",
  "chains.heading": "समर्थित ब्लॉकचेन",
  "chains.sol.sub": "Ed25519 हस्ताक्षर",
  "chains.atom.sub": "Amino और Direct हस्ताक्षर",
  "chains.dot.sub": "SS58 पते",
  "chains.ltc.sub": "सभी पता प्रकार",
  "chains.doge.sub": "P2PKH पते",
  "chains.more": "+ 50 और",
  "chains.more.sub": "SLIP-44 के माध्यम से",
  "adv.heading": "विरोधात्मक सुरक्षा",
  "adv.subheading":
    "तार्किक कर्ता समझौता-ग्रस्त कुंजियों से धन निकाल लेते हैं। बिना निकाला गया मूल्य कुंजी की अखंडता सिद्ध करता है।",
  "adv.intro.title": "विरोधात्मक सुरक्षा क्या है?",
  "adv.intro.desc":
    "क्रिप्टोग्राफ़िक सार्वजनिक कुंजियाँ क्रिप्टोकरेंसी नेटवर्क पर पते व्युत्पन्न कर सकती हैं। उन व्युत्पन्न पतों पर मूल्य जमा करके, आप एक <strong>गेम-थ्योरी सुरक्षा बॉन्ड</strong> बनाते हैं। निजी कुंजी से समझौता करने वाला कोई भी तार्किक कर्ता धन निकाल लेगा — यह भुगतान तत्काल, गुमनाम और जोखिम-मुक्त है। इससे शेष राशि <strong>कुंजी अखंडता का वास्तविक-समय संकेतक</strong> बन जाती है: बिना निकाला गया मूल्य दर्शाता है कि कुंजी से समझौता नहीं हुआ।",
  "adv.flow.pubkey": "सार्वजनिक कुंजी",
  "adv.flow.derive": "पता व्युत्पन्न करें",
  "adv.flow.deposit": "मूल्य जमा करें",
  "adv.flow.monitor": "निगरानी",
  "adv.flow.trusted": "विश्वसनीय",
  "adv.prin1.title": "कुंजी व्युत्पत्ति",
  "adv.prin1.desc":
    "डेटा पर हस्ताक्षर के लिए प्रयुक्त सार्वजनिक कुंजी गणितीय रूप से कई ब्लॉकचेन नेटवर्क (BIP-32/44) पर पते व्युत्पन्न कर सकती है। एक ही कुंजी-युग्म प्रमाणीकरण और मूल्य अभिरक्षा दोनों के लिए काम आता है।",
  "adv.prin2.title": "मूल्य ही विश्वास संकेत",
  "adv.prin2.desc":
    "व्युत्पन्न पते अनुमति-रहित होते हैं — किसी कुंजी में विश्वास दर्शाने के लिए कोई भी धन जमा कर सकता है। कुल शेष राशि समझौते की आर्थिक लागत को परिमाणित करती है।",
  "adv.prin3.title": "तार्किक कर्ता धारणा",
  "adv.prin3.desc":
    "धन निकालना प्रमुख रणनीति है: यह <strong>तत्काल, अपरिवर्तनीय और शून्य सीमांत जोखिम वाला</strong> है। अतः बिना निकाला गया मूल्य किसी समझौते के न होने को दर्शाता है।",
  "adv.prin4.title": "वास्तविक-समय सत्यापन",
  "adv.prin4.desc":
    "ब्लॉकचेन स्थिति सार्वजनिक रूप से लेखा-परीक्षण योग्य है और प्रत्येक ब्लॉक पर अद्यतन होती है। यह <strong>कुंजी अखंडता का निरंतर, अनुमति-रहित प्रमाण</strong> प्रदान करती है — कोई प्रमाणपत्र नहीं, बल्कि एक जीवंत संकेत।",
  "adv.whitepaper": "श्वेतपत्र पढ़ें",
  "adv.login.prompt":
    "अपनी कुंजियों से पते व्युत्पन्न करने और कई ब्लॉकचेन नेटवर्क पर लाइव शेष राशि जाँचने के लिए लॉग इन करें।",
  "adv.balances.title": "आपके व्युत्पन्न पते",
  "adv.refresh": "ताज़ा करें",
  "adv.balances.intro":
    "ये पते गणितीय रूप से आपकी HD वॉलेट कुंजियों से व्युत्पन्न होते हैं। कोई भी व्युत्पत्ति सत्यापित कर सकता है और आपकी कुंजियों में विश्वास बढ़ाने हेतु धन भेज सकता है।",
  "footer.license": "HD Wallet WASM — Apache-2.0 लाइसेंस",
};

const es = {
  "lang.label": "Idioma",
  "nav.packages": "Paquetes",
  "nav.features": "Características",
  "nav.quickstart": "Inicio rápido",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "Blockchains",
  "nav.security": "Seguridad",
  "nav.login": "Iniciar sesión",
  "nav.logout": "Cerrar sesión",
  "nav.account": "Cuenta",
  "hero.subtitle":
    "Una implementación integral de monedero determinista jerárquico en C++ puro, compilada a WebAssembly para compatibilidad multiplataforma. Compatible con BIP-32/39/44, con criptografía multicurva y soporte multicadena.",
  "hero.demo": "Probar la demo interactiva",
  "packages.heading": "Paquetes",
  "packages.wasm.desc":
    "Biblioteca WebAssembly principal. Derivación de claves HD BIP-32/39/44, criptografía multicurva, emisión de certificados X.509, atestaciones de monedero, generación de direcciones, firma y cifrado para más de 50 blockchains.",
  "packages.ui.desc":
    "Interfaz modal lista para usar en cualquier aplicación web. Ofrece inicio de sesión, gestión de claves, identidad (vCard), mapa de confianza y modales de bono de seguridad adversarial. Se conecta a cualquier botón — totalmente personalizable mediante propiedades CSS.",
  "packages.ui.note":
    'Las utilidades sin interfaz (derivación de direcciones, almacenamiento del monedero) también están disponibles vía <code>hd-wallet-ui/lib</code>.',
  "features.heading": "Características",
  "features.bip.title": "Cumple los estándares BIP",
  "features.bip.desc":
    "Implementación completa de BIP-32 (claves HD), BIP-39 (frases mnemónicas), BIP-44/49/84 (jerarquía de cuentas) y SLIP-44 (tipos de moneda).",
  "features.curve.title": "Criptografía multicurva",
  "features.curve.desc":
    "Compatible con secp256k1 (Bitcoin, Ethereum), Ed25519 (Solana, Polkadot), NIST P-256, P-384 e intercambio de claves X25519.",
  "features.chain.title": "Soporte multicadena",
  "features.chain.desc":
    "Bitcoin (todos los tipos de dirección), Ethereum/EVM, Solana, Cosmos/Tendermint, Polkadot/Substrate y más de 50 monedas vía SLIP-44.",
  "features.wasm.title": "WebAssembly nativo",
  "features.wasm.desc":
    "Compilado a WASM para navegador, Node.js y entornos WASI. Funciona con Go, Rust, Python y cualquier host compatible con WASI.",
  "features.x509.title": "X.509 y pruebas de monedero",
  "features.x509.desc":
    "Emite certificados estándar P-256/P-384, intercambia PEM/DER/PKCS#12 e incrusta atestaciones de monedero que vinculan un certificado a una clave criptográfica seleccionada.",
  "features.hw.title": "Soporte de monederos físicos",
  "features.hw.desc":
    "Capa de abstracción para dispositivos Trezor, Ledger y KeepKey con integración de puente WASI para comunicación USB/HID.",
  "features.sec.title": "Seguridad ante todo",
  "features.sec.desc":
    "Borrado seguro de memoria, modo opcional conforme a FIPS y validación exhaustiva de entradas para uso en producción.",
  "quickstart.heading": "Inicio rápido",
  "quickstart.addresses": "Direcciones",
  "quickstart.signing": "Firma",
  "quickstart.encryption": "Cifrado",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "PKI web estándar para TLS e identidad de dispositivos, con una capa de atestación respaldada por monedero que vincula los certificados a claves de monedero HD.",
  "pki.eyebrow": "Por qué lo usamos",
  "pki.title": "X.509 es lo que el resto de internet ya entiende",
  "pki.p1":
    "Navegadores, balanceadores de carga, proxies inversos, implementaciones de mTLS, sistemas de identidad de dispositivos y herramientas de almacén de claves ya hablan X.509. Esto significa que, si queremos un certificado que la infraestructura real pueda consumir, usamos PKI web normal en lugar de inventar un formato de identidad propio del repositorio.",
  "pki.p2":
    "Lo que añade hd-wallet-wasm es una segunda vía de prueba: el certificado puede llevar una atestación de monedero firmada por una clave de monedero seleccionada. El certificado sigue siendo interoperable para TLS, y las aplicaciones que se preocupan por la identidad del monedero pueden verificar la prueba adicional.",
  "pki.tag.attest": "Atestaciones de monedero",
  "pki.flow.gen": "Generar clave del certificado",
  "pki.flow.issue": "Emitir certificado X.509",
  "pki.flow.embed": "Incrustar prueba de monedero",
  "pki.flow.verify": "Verificar cadena + monedero",
  "pki.card1.title": "Cómo funciona",
  "pki.card1.desc":
    "La emisión de certificados se mantiene en claves normales P-256 o P-384. El repositorio puede crear certificados autofirmados, emitir subordinados, convertir PEM y DER, y empaquetar el material como PKCS#12 para almacenes de claves normales.",
  "pki.card2.title": "Por qué importa",
  "pki.card2.desc":
    "Las herramientas TLS estándar obtienen un certificado normal. Los verificadores conscientes del monedero obtienen una prueba adicional de que el certificado fue atestado por una clave de monedero seleccionada, sin reemplazar la cadena PKI existente.",
  "pki.card3.title": "Cómo lo usamos",
  "pki.card3.desc":
    "La atestación de monedero firma campos canónicos del certificado, incluido el resumen SPKI. Eso crea un vínculo duradero entre el certificado y la identidad de monedero elegida, como una clave secp256k1 raíz de Bitcoin.",
  "pki.card4.title": "Qué comprueban los verificadores",
  "pki.card4.desc":
    "Primero validan la cadena X.509 normal. Luego analizan el certificado y verifican la prueba de monedero incrustada. Ambas deben superarse si se quiere probar que un certificado de servidor fue vinculado por una clave de monedero.",
  "chains.heading": "Blockchains compatibles",
  "chains.sol.sub": "Firmas Ed25519",
  "chains.atom.sub": "Firma Amino y Direct",
  "chains.dot.sub": "Direcciones SS58",
  "chains.ltc.sub": "Todos los tipos de dirección",
  "chains.doge.sub": "Direcciones P2PKH",
  "chains.more": "+ 50 más",
  "chains.more.sub": "vía SLIP-44",
  "adv.heading": "Seguridad adversarial",
  "adv.subheading":
    "Los actores racionales vacían las claves comprometidas. El valor no vaciado prueba la integridad de la clave.",
  "adv.intro.title": "¿Qué es la seguridad adversarial?",
  "adv.intro.desc":
    "Las claves públicas criptográficas pueden derivar direcciones en redes de criptomonedas. Al depositar valor en esas direcciones derivadas, se crea un <strong>bono de seguridad de teoría de juegos</strong>. Un actor racional que comprometa la clave privada vaciará los fondos — el pago es inmediato, anónimo y sin riesgo. Esto convierte el saldo en un <strong>indicador en tiempo real de la integridad de la clave</strong>: el valor no vaciado implica una clave no comprometida.",
  "adv.flow.pubkey": "Clave pública",
  "adv.flow.derive": "Derivar dirección",
  "adv.flow.deposit": "Depositar valor",
  "adv.flow.monitor": "Monitorear",
  "adv.flow.trusted": "Confiable",
  "adv.prin1.title": "Derivación de claves",
  "adv.prin1.desc":
    "Una clave pública usada para firmar datos puede derivar matemáticamente direcciones en múltiples redes blockchain (BIP-32/44). Un mismo par de claves sirve tanto para la autenticación como para la custodia de valor.",
  "adv.prin2.title": "El valor como señal de confianza",
  "adv.prin2.desc":
    "Las direcciones derivadas son sin permisos — cualquiera puede depositar fondos para señalar confianza en una clave. El saldo agregado cuantifica el costo económico de un compromiso.",
  "adv.prin3.title": "Supuesto del actor racional",
  "adv.prin3.desc":
    "Vaciar los fondos es la estrategia dominante: es <strong>inmediato, irreversible y con riesgo marginal cero</strong>. Por lo tanto, el valor no vaciado implica que no hubo compromiso.",
  "adv.prin4.title": "Verificación en tiempo real",
  "adv.prin4.desc":
    "El estado de la blockchain es auditable públicamente y se actualiza en cada bloque. Esto proporciona una <strong>prueba continua y sin permisos de la integridad de la clave</strong> — no un certificado, sino una señal en vivo.",
  "adv.whitepaper": "Leer el informe técnico",
  "adv.login.prompt":
    "Inicia sesión para derivar direcciones a partir de tus claves y consultar saldos en vivo en múltiples redes blockchain.",
  "adv.balances.title": "Tus direcciones derivadas",
  "adv.refresh": "Actualizar",
  "adv.balances.intro":
    "Estas direcciones se derivan matemáticamente de tus claves de monedero HD. Cualquiera puede verificar la derivación y enviar fondos para aumentar la confianza en tus claves.",
  "footer.license": "HD Wallet WASM — Licencia Apache-2.0",
};

const ar = {
  "lang.label": "اللغة",
  "nav.packages": "الحزم",
  "nav.features": "المزايا",
  "nav.quickstart": "بدء سريع",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "سلاسل الكتل",
  "nav.security": "الأمان",
  "nav.login": "تسجيل الدخول",
  "nav.logout": "تسجيل الخروج",
  "nav.account": "الحساب",
  "hero.subtitle":
    "تطبيق شامل لمحفظة حتمية هرمية بلغة C++ الخالصة، مُترجَم إلى WebAssembly لتوافق متعدد المنصات. متوافق مع BIP-32/39/44 مع تشفير متعدد المنحنيات ودعم متعدد السلاسل.",
  "hero.demo": "جرّب العرض التفاعلي",
  "packages.heading": "الحزم",
  "packages.wasm.desc":
    "مكتبة WebAssembly الأساسية. اشتقاق مفاتيح HD وفق BIP-32/39/44، وتشفير متعدد المنحنيات، وإصدار شهادات X.509، وإثباتات المحفظة، وتوليد العناوين، والتوقيع، والتشفير لأكثر من 50 سلسلة كتل.",
  "packages.ui.desc":
    "واجهة منبثقة جاهزة للاستخدام في أي تطبيق ويب. توفّر تسجيل الدخول وإدارة المفاتيح والهوية (vCard) وخريطة الثقة ونوافذ سند الأمان التنافسي. اربطها بأي زر — قابلة للتنسيق بالكامل عبر خصائص CSS المخصصة.",
  "packages.ui.note":
    'تتوفر أيضًا أدوات بلا واجهة (اشتقاق العناوين، تخزين المحفظة) عبر <code>hd-wallet-ui/lib</code>.',
  "features.heading": "المزايا",
  "features.bip.title": "متوافق مع معايير BIP",
  "features.bip.desc":
    "تنفيذ كامل لـ BIP-32 (مفاتيح HD)، وBIP-39 (عبارات التذكّر)، وBIP-44/49/84 (تسلسل الحسابات)، وSLIP-44 (أنواع العملات).",
  "features.curve.title": "تشفير متعدد المنحنيات",
  "features.curve.desc":
    "دعم لـ secp256k1 (بيتكوين، إيثريوم)، وEd25519 (سولانا، بولكادوت)، وNIST P-256، وP-384، وتبادل المفاتيح X25519.",
  "features.chain.title": "دعم متعدد السلاسل",
  "features.chain.desc":
    "بيتكوين (جميع أنواع العناوين)، وإيثريوم/EVM، وسولانا، وكوزموس/Tendermint، وبولكادوت/Substrate، وأكثر من 50 عملة عبر SLIP-44.",
  "features.wasm.title": "WebAssembly أصلي",
  "features.wasm.desc":
    "مُترجَم إلى WASM للمتصفح وNode.js وبيئات WASI. يعمل مع Go وRust وPython وأي مضيف متوافق مع WASI.",
  "features.x509.title": "X.509 وإثباتات المحفظة",
  "features.x509.desc":
    "إصدار شهادات معيارية P-256/P-384، وتبادل PEM/DER/PKCS#12، وتضمين إثباتات محفظة تربط الشهادة بمفتاح تشفير محدد.",
  "features.hw.title": "دعم المحافظ العتادية",
  "features.hw.desc":
    "طبقة تجريد لأجهزة Trezor وLedger وKeepKey مع تكامل جسر WASI للاتصال عبر USB/HID.",
  "features.sec.title": "الأمان أولًا",
  "features.sec.desc":
    "مسح آمن للذاكرة، ووضع اختياري متوافق مع FIPS، والتحقق الشامل من المدخلات للاستخدام الإنتاجي.",
  "quickstart.heading": "بدء سريع",
  "quickstart.addresses": "العناوين",
  "quickstart.signing": "التوقيع",
  "quickstart.encryption": "التشفير",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "بنية مفاتيح عامة ويب معيارية لـ TLS وهوية الأجهزة، مع طبقة إثبات مدعومة بالمحفظة تربط الشهادات بمفاتيح محفظة HD.",
  "pki.eyebrow": "لماذا نستخدمه",
  "pki.title": "X.509 هو ما تفهمه بقية الإنترنت بالفعل",
  "pki.p1":
    "المتصفحات وموازنات الأحمال والوكلاء العكسيون وعمليات نشر mTLS وأنظمة هوية الأجهزة وأدوات مخازن المفاتيح جميعها تتحدث X.509 بالفعل. هذا يعني أنه إذا أردنا شهادة يمكن للبنية التحتية الحقيقية استخدامها، فإننا نستخدم بنية مفاتيح عامة ويب عادية بدلًا من ابتكار صيغة هوية خاصة بالمستودع.",
  "pki.p2":
    "ما يضيفه hd-wallet-wasm هو مسار إثبات ثانٍ: يمكن للشهادة أن تحمل إثبات محفظة موقّعًا بمفتاح محفظة محدد. تبقى الشهادة قابلة للتشغيل البيني مع TLS، ويمكن للتطبيقات التي تهتم بهوية المحفظة التحقق من الإثبات الإضافي.",
  "pki.tag.attest": "إثباتات المحفظة",
  "pki.flow.gen": "توليد مفتاح الشهادة",
  "pki.flow.issue": "إصدار شهادة X.509",
  "pki.flow.embed": "تضمين إثبات المحفظة",
  "pki.flow.verify": "التحقق من السلسلة + المحفظة",
  "pki.card1.title": "كيف يعمل",
  "pki.card1.desc":
    "يبقى إصدار الشهادات على مفاتيح P-256 أو P-384 العادية. يمكن للمستودع إنشاء شهادات ذاتية التوقيع، وإصدار شهادات فرعية، وتحويل PEM وDER، وتعبئة المواد كـ PKCS#12 لمخازن المفاتيح العادية.",
  "pki.card2.title": "لماذا هو مهم",
  "pki.card2.desc":
    "تحصل أدوات TLS المعيارية على شهادة عادية. ويحصل المتحققون المدركون للمحفظة على إثبات إضافي بأن الشهادة مصدّقة بمفتاح محفظة محدد، دون استبدال سلسلة PKI الحالية.",
  "pki.card3.title": "كيف نستخدمه",
  "pki.card3.desc":
    "يوقّع إثبات المحفظة على حقول الشهادة القانونية بما في ذلك بصمة SPKI. وهذا يُنشئ ارتباطًا دائمًا بين الشهادة وهوية المحفظة المختارة، مثل مفتاح secp256k1 الجذري لبيتكوين.",
  "pki.card4.title": "ما الذي يتحقق منه المدققون",
  "pki.card4.desc":
    "أولًا تحقّق من سلسلة X.509 العادية. ثم حلّل الشهادة وتحقّق من إثبات المحفظة المضمّن. يجب أن ينجح كلاهما إذا أردت إثبات أن شهادة الخادم مرتبطة بمفتاح محفظة.",
  "chains.heading": "سلاسل الكتل المدعومة",
  "chains.sol.sub": "توقيعات Ed25519",
  "chains.atom.sub": "توقيع Amino وDirect",
  "chains.dot.sub": "عناوين SS58",
  "chains.ltc.sub": "جميع أنواع العناوين",
  "chains.doge.sub": "عناوين P2PKH",
  "chains.more": "+ 50 أخرى",
  "chains.more.sub": "عبر SLIP-44",
  "adv.heading": "الأمان التنافسي",
  "adv.subheading":
    "الفاعلون العقلانيون يستنزفون المفاتيح المخترقة. القيمة غير المستنزَفة تثبت سلامة المفتاح.",
  "adv.intro.title": "ما هو الأمان التنافسي؟",
  "adv.intro.desc":
    "يمكن للمفاتيح العامة التشفيرية اشتقاق عناوين على شبكات العملات المشفّرة. وبإيداع قيمة في تلك العناوين المشتقّة، تُنشئ <strong>سند أمان قائمًا على نظرية الألعاب</strong>. أي فاعل عقلاني يخترق المفتاح الخاص سيستنزف الأموال — فالعائد فوري ومجهول وخالٍ من المخاطر. وهذا يجعل الرصيد <strong>مؤشرًا لحظيًا على سلامة المفتاح</strong>: القيمة غير المستنزَفة تعني مفتاحًا غير مخترَق.",
  "adv.flow.pubkey": "المفتاح العام",
  "adv.flow.derive": "اشتقاق العنوان",
  "adv.flow.deposit": "إيداع القيمة",
  "adv.flow.monitor": "المراقبة",
  "adv.flow.trusted": "موثوق",
  "adv.prin1.title": "اشتقاق المفاتيح",
  "adv.prin1.desc":
    "المفتاح العام المستخدم لتوقيع البيانات يمكنه رياضيًا اشتقاق عناوين على عدة شبكات بلوكتشين (BIP-32/44). زوج مفاتيح واحد يخدم المصادقة وحفظ القيمة معًا.",
  "adv.prin2.title": "القيمة كإشارة ثقة",
  "adv.prin2.desc":
    "العناوين المشتقّة بلا أذونات — يمكن لأي شخص إيداع أموال للإشارة إلى الثقة بمفتاح ما. ويُقدّر الرصيد الإجمالي التكلفة الاقتصادية للاختراق.",
  "adv.prin3.title": "افتراض الفاعل العقلاني",
  "adv.prin3.desc":
    "استنزاف الأموال هو الاستراتيجية المهيمنة: فهو <strong>فوري ولا رجعة فيه وذو مخاطرة حدّية صفرية</strong>. لذلك تعني القيمة غير المستنزَفة عدم وجود اختراق.",
  "adv.prin4.title": "التحقق اللحظي",
  "adv.prin4.desc":
    "حالة البلوكتشين قابلة للتدقيق العلني وتُحدَّث مع كل كتلة. وهذا يوفّر <strong>إثباتًا مستمرًا وبلا أذونات لسلامة المفتاح</strong> — ليس شهادة، بل إشارة حيّة.",
  "adv.whitepaper": "اقرأ الورقة البيضاء",
  "adv.login.prompt":
    "سجّل الدخول لاشتقاق العناوين من مفاتيحك والتحقق من الأرصدة الحية عبر عدة شبكات بلوكتشين.",
  "adv.balances.title": "عناوينك المشتقّة",
  "adv.refresh": "تحديث",
  "adv.balances.intro":
    "تُشتق هذه العناوين رياضيًا من مفاتيح محفظتك HD. يمكن لأي شخص التحقق من الاشتقاق وإرسال أموال لزيادة الثقة بمفاتيحك.",
  "footer.license": "HD Wallet WASM — رخصة Apache-2.0",
};

const fr = {
  "lang.label": "Langue",
  "nav.packages": "Paquets",
  "nav.features": "Fonctionnalités",
  "nav.quickstart": "Démarrage rapide",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "Blockchains",
  "nav.security": "Sécurité",
  "nav.login": "Connexion",
  "nav.logout": "Déconnexion",
  "nav.account": "Compte",
  "hero.subtitle":
    "Une implémentation complète de portefeuille déterministe hiérarchique en C++ pur, compilée en WebAssembly pour une compatibilité multiplateforme. Conforme à BIP-32/39/44, avec cryptographie multicourbe et prise en charge multichaîne.",
  "hero.demo": "Essayer la démo interactive",
  "packages.heading": "Paquets",
  "packages.wasm.desc":
    "Bibliothèque WebAssembly principale. Dérivation de clés HD BIP-32/39/44, cryptographie multicourbe, émission de certificats X.509, attestations de portefeuille, génération d'adresses, signature et chiffrement pour plus de 50 blockchains.",
  "packages.ui.desc":
    "Interface modale prête à l'emploi pour toute application web. Fournit connexion, gestion des clés, identité (vCard), carte de confiance et modales de caution de sécurité adversariale. À rattacher à n'importe quel bouton — entièrement stylable via des propriétés CSS.",
  "packages.ui.note":
    'Des utilitaires sans interface (dérivation d\'adresses, stockage du portefeuille) sont également disponibles via <code>hd-wallet-ui/lib</code>.',
  "features.heading": "Fonctionnalités",
  "features.bip.title": "Conforme aux normes BIP",
  "features.bip.desc":
    "Implémentation complète de BIP-32 (clés HD), BIP-39 (phrases mnémoniques), BIP-44/49/84 (hiérarchie de comptes) et SLIP-44 (types de pièces).",
  "features.curve.title": "Cryptographie multicourbe",
  "features.curve.desc":
    "Prise en charge de secp256k1 (Bitcoin, Ethereum), Ed25519 (Solana, Polkadot), NIST P-256, P-384 et échange de clés X25519.",
  "features.chain.title": "Prise en charge multichaîne",
  "features.chain.desc":
    "Bitcoin (tous les types d'adresses), Ethereum/EVM, Solana, Cosmos/Tendermint, Polkadot/Substrate et plus de 50 pièces via SLIP-44.",
  "features.wasm.title": "WebAssembly natif",
  "features.wasm.desc":
    "Compilé en WASM pour le navigateur, Node.js et les runtimes WASI. Fonctionne avec Go, Rust, Python et tout hôte compatible WASI.",
  "features.x509.title": "X.509 et preuves de portefeuille",
  "features.x509.desc":
    "Émettez des certificats standard P-256/P-384, échangez du PEM/DER/PKCS#12 et intégrez des attestations de portefeuille qui lient un certificat à une clé cryptographique sélectionnée.",
  "features.hw.title": "Prise en charge des portefeuilles matériels",
  "features.hw.desc":
    "Couche d'abstraction pour les appareils Trezor, Ledger et KeepKey avec intégration d'un pont WASI pour la communication USB/HID.",
  "features.sec.title": "La sécurité d'abord",
  "features.sec.desc":
    "Effacement sécurisé de la mémoire, mode conforme FIPS optionnel et validation complète des entrées pour un usage en production.",
  "quickstart.heading": "Démarrage rapide",
  "quickstart.addresses": "Adresses",
  "quickstart.signing": "Signature",
  "quickstart.encryption": "Chiffrement",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "PKI web standard pour TLS et identité des appareils, avec une couche d'attestation adossée au portefeuille qui lie les certificats aux clés de portefeuille HD.",
  "pki.eyebrow": "Pourquoi nous l'utilisons",
  "pki.title": "X.509 est ce que le reste d'internet comprend déjà",
  "pki.p1":
    "Les navigateurs, répartiteurs de charge, proxys inverses, déploiements mTLS, systèmes d'identité des appareils et outils de magasin de clés parlent déjà tous X.509. Cela signifie que si nous voulons un certificat que l'infrastructure réelle peut consommer, nous utilisons une PKI web normale plutôt que d'inventer un format d'identité propre au dépôt.",
  "pki.p2":
    "Ce que hd-wallet-wasm ajoute, c'est une seconde voie de preuve : le certificat peut porter une attestation de portefeuille signée par une clé de portefeuille sélectionnée. Le certificat reste interopérable pour TLS, et les applications soucieuses de l'identité du portefeuille peuvent vérifier cette preuve supplémentaire.",
  "pki.tag.attest": "Attestations de portefeuille",
  "pki.flow.gen": "Générer la clé du certificat",
  "pki.flow.issue": "Émettre le certificat X.509",
  "pki.flow.embed": "Intégrer la preuve de portefeuille",
  "pki.flow.verify": "Vérifier la chaîne + le portefeuille",
  "pki.card1.title": "Comment ça marche",
  "pki.card1.desc":
    "L'émission des certificats reste sur des clés P-256 ou P-384 normales. Le dépôt peut créer des certificats auto-signés, émettre des subordonnés, convertir PEM et DER, et empaqueter le matériel en PKCS#12 pour les magasins de clés normaux.",
  "pki.card2.title": "Pourquoi c'est important",
  "pki.card2.desc":
    "Les outils TLS standard obtiennent un certificat normal. Les vérificateurs sensibles au portefeuille obtiennent une preuve supplémentaire que le certificat a été attesté par une clé de portefeuille sélectionnée, sans remplacer la chaîne PKI existante.",
  "pki.card3.title": "Comment nous l'utilisons",
  "pki.card3.desc":
    "L'attestation de portefeuille signe des champs canoniques du certificat, y compris l'empreinte SPKI. Cela crée un lien durable entre le certificat et l'identité de portefeuille choisie, comme une clé secp256k1 racine Bitcoin.",
  "pki.card4.title": "Ce que vérifient les vérificateurs",
  "pki.card4.desc":
    "Validez d'abord la chaîne X.509 normale. Analysez ensuite le certificat et vérifiez la preuve de portefeuille intégrée. Les deux doivent réussir si vous voulez prouver qu'un certificat de serveur a été lié par une clé de portefeuille.",
  "chains.heading": "Blockchains prises en charge",
  "chains.sol.sub": "Signatures Ed25519",
  "chains.atom.sub": "Signature Amino et Direct",
  "chains.dot.sub": "Adresses SS58",
  "chains.ltc.sub": "Tous les types d'adresses",
  "chains.doge.sub": "Adresses P2PKH",
  "chains.more": "+ 50 autres",
  "chains.more.sub": "via SLIP-44",
  "adv.heading": "Sécurité adversariale",
  "adv.subheading":
    "Les acteurs rationnels vident les clés compromises. La valeur non vidée prouve l'intégrité de la clé.",
  "adv.intro.title": "Qu'est-ce que la sécurité adversariale ?",
  "adv.intro.desc":
    "Les clés publiques cryptographiques peuvent dériver des adresses sur les réseaux de cryptomonnaies. En déposant de la valeur à ces adresses dérivées, vous créez une <strong>caution de sécurité issue de la théorie des jeux</strong>. Un acteur rationnel qui compromet la clé privée videra les fonds — le gain est immédiat, anonyme et sans risque. Le solde devient ainsi un <strong>indicateur en temps réel de l'intégrité de la clé</strong> : une valeur non vidée implique une clé non compromise.",
  "adv.flow.pubkey": "Clé publique",
  "adv.flow.derive": "Dériver l'adresse",
  "adv.flow.deposit": "Déposer de la valeur",
  "adv.flow.monitor": "Surveiller",
  "adv.flow.trusted": "De confiance",
  "adv.prin1.title": "Dérivation de clés",
  "adv.prin1.desc":
    "Une clé publique utilisée pour signer des données peut dériver mathématiquement des adresses sur plusieurs réseaux blockchain (BIP-32/44). Une même paire de clés sert à la fois à l'authentification et à la garde de valeur.",
  "adv.prin2.title": "La valeur comme signal de confiance",
  "adv.prin2.desc":
    "Les adresses dérivées sont sans permission — n'importe qui peut déposer des fonds pour signaler sa confiance en une clé. Le solde agrégé quantifie le coût économique d'une compromission.",
  "adv.prin3.title": "Hypothèse de l'acteur rationnel",
  "adv.prin3.desc":
    "Vider les fonds est la stratégie dominante : c'est <strong>immédiat, irréversible et sans risque marginal</strong>. Une valeur non vidée implique donc l'absence de compromission.",
  "adv.prin4.title": "Vérification en temps réel",
  "adv.prin4.desc":
    "L'état de la blockchain est publiquement auditable et se met à jour à chaque bloc. Cela fournit une <strong>preuve continue et sans permission de l'intégrité de la clé</strong> — non pas un certificat, mais un signal en direct.",
  "adv.whitepaper": "Lire le livre blanc",
  "adv.login.prompt":
    "Connectez-vous pour dériver des adresses à partir de vos clés et consulter les soldes en direct sur plusieurs réseaux blockchain.",
  "adv.balances.title": "Vos adresses dérivées",
  "adv.refresh": "Actualiser",
  "adv.balances.intro":
    "Ces adresses sont dérivées mathématiquement de vos clés de portefeuille HD. N'importe qui peut vérifier la dérivation et envoyer des fonds pour accroître la confiance en vos clés.",
  "footer.license": "HD Wallet WASM — Licence Apache-2.0",
};

const bn = {
  "lang.label": "ভাষা",
  "nav.packages": "প্যাকেজ",
  "nav.features": "বৈশিষ্ট্য",
  "nav.quickstart": "দ্রুত শুরু",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "ব্লকচেইন",
  "nav.security": "নিরাপত্তা",
  "nav.login": "লগ ইন",
  "nav.logout": "লগ আউট",
  "nav.account": "অ্যাকাউন্ট",
  "hero.subtitle":
    "বিশুদ্ধ C++-এ একটি পূর্ণাঙ্গ স্তরানুক্রমিক নির্ধারক (HD) ওয়ালেট বাস্তবায়ন, ক্রস-প্ল্যাটফর্ম সামঞ্জস্যের জন্য WebAssembly-তে সংকলিত। BIP-32/39/44 সঙ্গতিপূর্ণ, বহু-বক্র ক্রিপ্টোগ্রাফি ও বহু-চেইন সমর্থনসহ।",
  "hero.demo": "ইন্টারঅ্যাক্টিভ ডেমো চেষ্টা করুন",
  "packages.heading": "প্যাকেজ",
  "packages.wasm.desc":
    "মূল WebAssembly লাইব্রেরি। BIP-32/39/44 HD কী উদ্ভবন, বহু-বক্র ক্রিপ্টোগ্রাফি, X.509 সার্টিফিকেট ইস্যু, ওয়ালেট প্রত্যয়ন, ঠিকানা তৈরি, স্বাক্ষর এবং ৫০+ ব্লকচেইনের জন্য এনক্রিপশন।",
  "packages.ui.desc":
    "যেকোনো ওয়েব অ্যাপের জন্য ড্রপ-ইন মোডাল UI। লগইন, কী ব্যবস্থাপনা, পরিচয় (vCard), ট্রাস্ট মানচিত্র এবং প্রতিদ্বন্দ্বিতামূলক নিরাপত্তা বন্ড মোডাল সরবরাহ করে। যেকোনো বোতামে যুক্ত করুন — CSS কাস্টম প্রপার্টির মাধ্যমে সম্পূর্ণ স্টাইলযোগ্য।",
  "packages.ui.note":
    'হেডলেস ইউটিলিটি (ঠিকানা উদ্ভবন, ওয়ালেট সংরক্ষণ) <code>hd-wallet-ui/lib</code>-এর মাধ্যমেও উপলব্ধ।',
  "features.heading": "বৈশিষ্ট্য",
  "features.bip.title": "BIP মান সঙ্গতিপূর্ণ",
  "features.bip.desc":
    "BIP-32 (HD কী), BIP-39 (স্মারক বাক্যাংশ), BIP-44/49/84 (অ্যাকাউন্ট স্তরক্রম) এবং SLIP-44 (মুদ্রার ধরন)-এর পূর্ণ বাস্তবায়ন।",
  "features.curve.title": "বহু-বক্র ক্রিপ্টোগ্রাফি",
  "features.curve.desc":
    "secp256k1 (বিটকয়েন, ইথেরিয়াম), Ed25519 (Solana, Polkadot), NIST P-256, P-384 এবং X25519 কী বিনিময়ের সমর্থন।",
  "features.chain.title": "বহু-চেইন সমর্থন",
  "features.chain.desc":
    "বিটকয়েন (সব ঠিকানার ধরন), ইথেরিয়াম/EVM, Solana, Cosmos/Tendermint, Polkadot/Substrate এবং SLIP-44-এর মাধ্যমে ৫০+ মুদ্রা।",
  "features.wasm.title": "নেটিভ WebAssembly",
  "features.wasm.desc":
    "ব্রাউজার, Node.js এবং WASI রানটাইমের জন্য WASM-এ সংকলিত। Go, Rust, Python এবং যেকোনো WASI-সঙ্গতিপূর্ণ হোস্টের সঙ্গে কাজ করে।",
  "features.x509.title": "X.509 ও ওয়ালেট প্রমাণ",
  "features.x509.desc":
    "মান P-256/P-384 সার্টিফিকেট ইস্যু করুন, PEM/DER/PKCS#12 বিনিময় করুন এবং সার্টিফিকেটকে নির্বাচিত ক্রিপ্টো কী-এর সঙ্গে যুক্ত করা ওয়ালেট প্রত্যয়ন এম্বেড করুন।",
  "features.hw.title": "হার্ডওয়্যার ওয়ালেট সমর্থন",
  "features.hw.desc":
    "USB/HID যোগাযোগের জন্য WASI ব্রিজ একীকরণসহ Trezor, Ledger এবং KeepKey ডিভাইসের জন্য বিমূর্তকরণ স্তর।",
  "features.sec.title": "নিরাপত্তা সর্বাগ্রে",
  "features.sec.desc":
    "নিরাপদ মেমরি মোছা, ঐচ্ছিক FIPS-সঙ্গতিপূর্ণ মোড এবং উৎপাদন ব্যবহারের জন্য বিস্তৃত ইনপুট যাচাই।",
  "quickstart.heading": "দ্রুত শুরু",
  "quickstart.addresses": "ঠিকানা",
  "quickstart.signing": "স্বাক্ষর",
  "quickstart.encryption": "এনক্রিপশন",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "TLS ও ডিভাইস পরিচয়ের জন্য মান ওয়েব PKI, সার্টিফিকেটকে HD-ওয়ালেট কী-এর সঙ্গে যুক্ত করা ওয়ালেট-সমর্থিত প্রত্যয়ন স্তরসহ।",
  "pki.eyebrow": "আমরা কেন এটি ব্যবহার করি",
  "pki.title": "X.509 হলো যা ইন্টারনেটের বাকি অংশ ইতিমধ্যেই বোঝে",
  "pki.p1":
    "ব্রাউজার, লোড ব্যালান্সার, রিভার্স প্রক্সি, mTLS স্থাপন, ডিভাইস পরিচয় ব্যবস্থা এবং কীস্টোর টুল — সবই ইতিমধ্যে X.509 বোঝে। এর অর্থ, আমরা যদি এমন একটি সার্টিফিকেট চাই যা বাস্তব অবকাঠামো ব্যবহার করতে পারে, তবে আমরা রিপো-নির্দিষ্ট পরিচয় বিন্যাস উদ্ভাবনের বদলে সাধারণ ওয়েব PKI ব্যবহার করি।",
  "pki.p2":
    "hd-wallet-wasm যা যোগ করে তা হলো একটি দ্বিতীয় প্রমাণ-পথ: সার্টিফিকেট একটি নির্বাচিত ওয়ালেট কী দ্বারা স্বাক্ষরিত ওয়ালেট প্রত্যয়ন বহন করতে পারে। সার্টিফিকেট TLS-এর জন্য আন্তঃক্রিয়াশীল থাকে, এবং যেসব অ্যাপ্লিকেশন ওয়ালেট পরিচয়ের প্রতি যত্নশীল তারা অতিরিক্ত প্রমাণ যাচাই করতে পারে।",
  "pki.tag.attest": "ওয়ালেট প্রত্যয়ন",
  "pki.flow.gen": "সার্টিফিকেট কী তৈরি করুন",
  "pki.flow.issue": "X.509 সার্টিফিকেট ইস্যু করুন",
  "pki.flow.embed": "ওয়ালেট প্রমাণ এম্বেড করুন",
  "pki.flow.verify": "চেইন + ওয়ালেট যাচাই করুন",
  "pki.card1.title": "এটি কীভাবে কাজ করে",
  "pki.card1.desc":
    "সার্টিফিকেট ইস্যু সাধারণ P-256 বা P-384 কী-তেই থাকে। রিপো স্ব-স্বাক্ষরিত সার্টিফিকেট তৈরি করতে, অধীনস্থ ইস্যু করতে, PEM ও DER রূপান্তর করতে এবং সাধারণ কীস্টোরের জন্য উপাদান PKCS#12 হিসেবে প্যাকেজ করতে পারে।",
  "pki.card2.title": "এটি কেন গুরুত্বপূর্ণ",
  "pki.card2.desc":
    "মান TLS টুল একটি সাধারণ সার্টিফিকেট পায়। ওয়ালেট-সচেতন যাচাইকারীরা একটি অতিরিক্ত প্রমাণ পায় যে সার্টিফিকেটটি একটি নির্বাচিত ওয়ালেট কী দ্বারা প্রত্যয়িত, বিদ্যমান PKI চেইন প্রতিস্থাপন না করেই।",
  "pki.card3.title": "আমরা এটি কীভাবে ব্যবহার করি",
  "pki.card3.desc":
    "ওয়ালেট প্রত্যয়ন SPKI ডাইজেস্টসহ প্রামাণিক সার্টিফিকেট ক্ষেত্রে স্বাক্ষর করে। এটি সার্টিফিকেট এবং নির্বাচিত ওয়ালেট পরিচয়ের (যেমন বিটকয়েন-রুট secp256k1 কী) মধ্যে একটি টেকসই বন্ধন তৈরি করে।",
  "pki.card4.title": "যাচাইকারীরা কী পরীক্ষা করে",
  "pki.card4.desc":
    "প্রথমে সাধারণ X.509 চেইন যাচাই করুন। তারপর সার্টিফিকেট বিশ্লেষণ করুন এবং এম্বেড করা ওয়ালেট প্রমাণ যাচাই করুন। সার্ভার সার্টিফিকেট একটি ওয়ালেট কী দ্বারা যুক্ত ছিল তা প্রমাণ করতে চাইলে উভয়কেই উত্তীর্ণ হতে হবে।",
  "chains.heading": "সমর্থিত ব্লকচেইন",
  "chains.sol.sub": "Ed25519 স্বাক্ষর",
  "chains.atom.sub": "Amino ও Direct স্বাক্ষর",
  "chains.dot.sub": "SS58 ঠিকানা",
  "chains.ltc.sub": "সব ঠিকানার ধরন",
  "chains.doge.sub": "P2PKH ঠিকানা",
  "chains.more": "+ আরও ৫০",
  "chains.more.sub": "SLIP-44-এর মাধ্যমে",
  "adv.heading": "প্রতিদ্বন্দ্বিতামূলক নিরাপত্তা",
  "adv.subheading":
    "যুক্তিবাদী কর্তারা আপস করা কী থেকে অর্থ সরিয়ে নেয়। না-সরানো মূল্য কী-এর অখণ্ডতা প্রমাণ করে।",
  "adv.intro.title": "প্রতিদ্বন্দ্বিতামূলক নিরাপত্তা কী?",
  "adv.intro.desc":
    "ক্রিপ্টোগ্রাফিক পাবলিক কী ক্রিপ্টোকারেন্সি নেটওয়ার্কে ঠিকানা উদ্ভব করতে পারে। ওই উদ্ভূত ঠিকানায় মূল্য জমা করে আপনি একটি <strong>গেম-থিওরি নিরাপত্তা বন্ড</strong> তৈরি করেন। প্রাইভেট কী আপস করা যেকোনো যুক্তিবাদী কর্তা অর্থ সরিয়ে নেবে — এই প্রতিদান তাৎক্ষণিক, বেনামি ও ঝুঁকিমুক্ত। ফলে ব্যালেন্স হয়ে ওঠে <strong>কী-অখণ্ডতার রিয়েল-টাইম নির্দেশক</strong>: না-সরানো মূল্য মানে অ-আপসকৃত কী।",
  "adv.flow.pubkey": "পাবলিক কী",
  "adv.flow.derive": "ঠিকানা উদ্ভব করুন",
  "adv.flow.deposit": "মূল্য জমা দিন",
  "adv.flow.monitor": "পর্যবেক্ষণ",
  "adv.flow.trusted": "বিশ্বস্ত",
  "adv.prin1.title": "কী উদ্ভবন",
  "adv.prin1.desc":
    "ডেটা স্বাক্ষরে ব্যবহৃত একটি পাবলিক কী গাণিতিকভাবে একাধিক ব্লকচেইন নেটওয়ার্কে (BIP-32/44) ঠিকানা উদ্ভব করতে পারে। একটি কী-জোড়া প্রমাণীকরণ ও মূল্য হেফাজত উভয়ের কাজ করে।",
  "adv.prin2.title": "মূল্যই বিশ্বাসের সংকেত",
  "adv.prin2.desc":
    "উদ্ভূত ঠিকানা অনুমতিহীন — যে কেউ একটি কী-এর প্রতি বিশ্বাস জানাতে অর্থ জমা দিতে পারে। সমষ্টিগত ব্যালেন্স আপসের অর্থনৈতিক খরচ পরিমাপ করে।",
  "adv.prin3.title": "যুক্তিবাদী কর্তার অনুমান",
  "adv.prin3.desc":
    "অর্থ সরানো প্রভাবশালী কৌশল: এটি <strong>তাৎক্ষণিক, অপরিবর্তনীয় এবং শূন্য প্রান্তিক ঝুঁকিসম্পন্ন</strong>। তাই না-সরানো মূল্য কোনো আপস না-হওয়াকে বোঝায়।",
  "adv.prin4.title": "রিয়েল-টাইম যাচাই",
  "adv.prin4.desc":
    "ব্লকচেইন অবস্থা সর্বজনীনভাবে নিরীক্ষাযোগ্য এবং প্রতি ব্লকে হালনাগাদ হয়। এটি <strong>কী-অখণ্ডতার নিরবচ্ছিন্ন, অনুমতিহীন প্রমাণ</strong> দেয় — কোনো সার্টিফিকেট নয়, বরং একটি জীবন্ত সংকেত।",
  "adv.whitepaper": "শ্বেতপত্র পড়ুন",
  "adv.login.prompt":
    "আপনার কী থেকে ঠিকানা উদ্ভব করতে এবং একাধিক ব্লকচেইন নেটওয়ার্কে লাইভ ব্যালেন্স দেখতে লগ ইন করুন।",
  "adv.balances.title": "আপনার উদ্ভূত ঠিকানা",
  "adv.refresh": "রিফ্রেশ",
  "adv.balances.intro":
    "এই ঠিকানাগুলো গাণিতিকভাবে আপনার HD ওয়ালেট কী থেকে উদ্ভূত। যে কেউ উদ্ভবন যাচাই করতে এবং আপনার কী-এর প্রতি বিশ্বাস বাড়াতে অর্থ পাঠাতে পারে।",
  "footer.license": "HD Wallet WASM — Apache-2.0 লাইসেন্স",
};

const pt = {
  "lang.label": "Idioma",
  "nav.packages": "Pacotes",
  "nav.features": "Recursos",
  "nav.quickstart": "Início rápido",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "Blockchains",
  "nav.security": "Segurança",
  "nav.login": "Entrar",
  "nav.logout": "Sair",
  "nav.account": "Conta",
  "hero.subtitle":
    "Uma implementação abrangente de carteira determinística hierárquica em C++ puro, compilada para WebAssembly para compatibilidade multiplataforma. Compatível com BIP-32/39/44, com criptografia multicurva e suporte multichain.",
  "hero.demo": "Testar a demonstração interativa",
  "packages.heading": "Pacotes",
  "packages.wasm.desc":
    "Biblioteca WebAssembly principal. Derivação de chaves HD BIP-32/39/44, criptografia multicurva, emissão de certificados X.509, atestações de carteira, geração de endereços, assinatura e criptografia para mais de 50 blockchains.",
  "packages.ui.desc":
    "Interface modal pronta para uso em qualquer aplicação web. Fornece login, gestão de chaves, identidade (vCard), mapa de confiança e modais de caução de segurança adversarial. Anexe a qualquer botão — totalmente estilizável via propriedades CSS.",
  "packages.ui.note":
    'Utilitários sem interface (derivação de endereços, armazenamento da carteira) também estão disponíveis via <code>hd-wallet-ui/lib</code>.',
  "features.heading": "Recursos",
  "features.bip.title": "Compatível com os padrões BIP",
  "features.bip.desc":
    "Implementação completa de BIP-32 (chaves HD), BIP-39 (frases mnemônicas), BIP-44/49/84 (hierarquia de contas) e SLIP-44 (tipos de moeda).",
  "features.curve.title": "Criptografia multicurva",
  "features.curve.desc":
    "Suporte a secp256k1 (Bitcoin, Ethereum), Ed25519 (Solana, Polkadot), NIST P-256, P-384 e troca de chaves X25519.",
  "features.chain.title": "Suporte multichain",
  "features.chain.desc":
    "Bitcoin (todos os tipos de endereço), Ethereum/EVM, Solana, Cosmos/Tendermint, Polkadot/Substrate e mais de 50 moedas via SLIP-44.",
  "features.wasm.title": "WebAssembly nativo",
  "features.wasm.desc":
    "Compilado para WASM para navegador, Node.js e runtimes WASI. Funciona com Go, Rust, Python e qualquer host compatível com WASI.",
  "features.x509.title": "X.509 e provas de carteira",
  "features.x509.desc":
    "Emita certificados padrão P-256/P-384, troque PEM/DER/PKCS#12 e incorpore atestações de carteira que vinculam um certificado a uma chave criptográfica selecionada.",
  "features.hw.title": "Suporte a carteiras físicas",
  "features.hw.desc":
    "Camada de abstração para dispositivos Trezor, Ledger e KeepKey com integração de ponte WASI para comunicação USB/HID.",
  "features.sec.title": "Segurança em primeiro lugar",
  "features.sec.desc":
    "Limpeza segura de memória, modo opcional compatível com FIPS e validação abrangente de entradas para uso em produção.",
  "quickstart.heading": "Início rápido",
  "quickstart.addresses": "Endereços",
  "quickstart.signing": "Assinatura",
  "quickstart.encryption": "Criptografia",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "PKI web padrão para TLS e identidade de dispositivos, com uma camada de atestação respaldada por carteira que vincula certificados a chaves de carteira HD.",
  "pki.eyebrow": "Por que a usamos",
  "pki.title": "X.509 é o que o resto da internet já entende",
  "pki.p1":
    "Navegadores, balanceadores de carga, proxies reversos, implantações mTLS, sistemas de identidade de dispositivos e ferramentas de keystore já falam X.509. Isso significa que, se quisermos um certificado que a infraestrutura real possa consumir, usamos PKI web normal em vez de inventar um formato de identidade próprio do repositório.",
  "pki.p2":
    "O que o hd-wallet-wasm acrescenta é um segundo caminho de prova: o certificado pode carregar uma atestação de carteira assinada por uma chave de carteira selecionada. O certificado permanece interoperável para TLS, e as aplicações que se importam com a identidade da carteira podem verificar a prova adicional.",
  "pki.tag.attest": "Atestações de carteira",
  "pki.flow.gen": "Gerar chave do certificado",
  "pki.flow.issue": "Emitir certificado X.509",
  "pki.flow.embed": "Incorporar prova de carteira",
  "pki.flow.verify": "Verificar cadeia + carteira",
  "pki.card1.title": "Como funciona",
  "pki.card1.desc":
    "A emissão de certificados permanece em chaves P-256 ou P-384 normais. O repositório pode criar certificados autoassinados, emitir subordinados, converter PEM e DER, e empacotar o material como PKCS#12 para keystores normais.",
  "pki.card2.title": "Por que importa",
  "pki.card2.desc":
    "As ferramentas TLS padrão recebem um certificado normal. Os verificadores cientes da carteira recebem uma prova adicional de que o certificado foi atestado por uma chave de carteira selecionada, sem substituir a cadeia PKI existente.",
  "pki.card3.title": "Como a usamos",
  "pki.card3.desc":
    "A atestação de carteira assina campos canônicos do certificado, incluindo o resumo SPKI. Isso cria um vínculo duradouro entre o certificado e a identidade de carteira escolhida, como uma chave secp256k1 raiz do Bitcoin.",
  "pki.card4.title": "O que os verificadores checam",
  "pki.card4.desc":
    "Primeiro validam a cadeia X.509 normal. Depois analisam o certificado e verificam a prova de carteira incorporada. Ambas precisam passar se você quiser provar que um certificado de servidor foi vinculado por uma chave de carteira.",
  "chains.heading": "Blockchains suportadas",
  "chains.sol.sub": "Assinaturas Ed25519",
  "chains.atom.sub": "Assinatura Amino e Direct",
  "chains.dot.sub": "Endereços SS58",
  "chains.ltc.sub": "Todos os tipos de endereço",
  "chains.doge.sub": "Endereços P2PKH",
  "chains.more": "+ 50 outras",
  "chains.more.sub": "via SLIP-44",
  "adv.heading": "Segurança adversarial",
  "adv.subheading":
    "Atores racionais esvaziam chaves comprometidas. O valor não esvaziado prova a integridade da chave.",
  "adv.intro.title": "O que é segurança adversarial?",
  "adv.intro.desc":
    "Chaves públicas criptográficas podem derivar endereços em redes de criptomoedas. Ao depositar valor nesses endereços derivados, você cria uma <strong>caução de segurança de teoria dos jogos</strong>. Um ator racional que comprometa a chave privada esvaziará os fundos — o pagamento é imediato, anônimo e sem risco. Isso torna o saldo um <strong>indicador em tempo real da integridade da chave</strong>: valor não esvaziado implica uma chave não comprometida.",
  "adv.flow.pubkey": "Chave pública",
  "adv.flow.derive": "Derivar endereço",
  "adv.flow.deposit": "Depositar valor",
  "adv.flow.monitor": "Monitorar",
  "adv.flow.trusted": "Confiável",
  "adv.prin1.title": "Derivação de chaves",
  "adv.prin1.desc":
    "Uma chave pública usada para assinar dados pode derivar matematicamente endereços em várias redes blockchain (BIP-32/44). Um mesmo par de chaves serve tanto para autenticação quanto para custódia de valor.",
  "adv.prin2.title": "O valor como sinal de confiança",
  "adv.prin2.desc":
    "Endereços derivados são sem permissão — qualquer um pode depositar fundos para sinalizar confiança em uma chave. O saldo agregado quantifica o custo econômico de um comprometimento.",
  "adv.prin3.title": "Premissa do ator racional",
  "adv.prin3.desc":
    "Esvaziar os fundos é a estratégia dominante: é <strong>imediato, irreversível e com risco marginal zero</strong>. Portanto, valor não esvaziado implica ausência de comprometimento.",
  "adv.prin4.title": "Verificação em tempo real",
  "adv.prin4.desc":
    "O estado da blockchain é publicamente auditável e se atualiza a cada bloco. Isso fornece uma <strong>prova contínua e sem permissão da integridade da chave</strong> — não um certificado, mas um sinal ao vivo.",
  "adv.whitepaper": "Ler o white paper",
  "adv.login.prompt":
    "Entre para derivar endereços a partir das suas chaves e conferir saldos ao vivo em várias redes blockchain.",
  "adv.balances.title": "Seus endereços derivados",
  "adv.refresh": "Atualizar",
  "adv.balances.intro":
    "Esses endereços são derivados matematicamente das suas chaves de carteira HD. Qualquer um pode verificar a derivação e enviar fundos para aumentar a confiança nas suas chaves.",
  "footer.license": "HD Wallet WASM — Licença Apache-2.0",
};

const ru = {
  "lang.label": "Язык",
  "nav.packages": "Пакеты",
  "nav.features": "Возможности",
  "nav.quickstart": "Быстрый старт",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "Блокчейны",
  "nav.security": "Безопасность",
  "nav.login": "Войти",
  "nav.logout": "Выйти",
  "nav.account": "Аккаунт",
  "hero.subtitle":
    "Полноценная реализация иерархического детерминированного кошелька на чистом C++, скомпилированная в WebAssembly для кроссплатформенной совместимости. Совместима с BIP-32/39/44, с мультикривой криптографией и поддержкой множества блокчейнов.",
  "hero.demo": "Попробовать интерактивную демонстрацию",
  "packages.heading": "Пакеты",
  "packages.wasm.desc":
    "Основная библиотека WebAssembly. Вывод HD-ключей по BIP-32/39/44, мультикривая криптография, выпуск сертификатов X.509, аттестации кошелька, генерация адресов, подпись и шифрование для более чем 50 блокчейнов.",
  "packages.ui.desc":
    "Готовый модальный интерфейс для любого веб-приложения. Обеспечивает вход, управление ключами, идентичность (vCard), карту доверия и модальные окна залога состязательной безопасности. Подключается к любой кнопке — полностью стилизуется через пользовательские свойства CSS.",
  "packages.ui.note":
    'Безынтерфейсные утилиты (вывод адресов, хранилище кошелька) также доступны через <code>hd-wallet-ui/lib</code>.',
  "features.heading": "Возможности",
  "features.bip.title": "Соответствие стандартам BIP",
  "features.bip.desc":
    "Полная реализация BIP-32 (HD-ключи), BIP-39 (мнемонические фразы), BIP-44/49/84 (иерархия аккаунтов) и SLIP-44 (типы монет).",
  "features.curve.title": "Мультикривая криптография",
  "features.curve.desc":
    "Поддержка secp256k1 (Bitcoin, Ethereum), Ed25519 (Solana, Polkadot), NIST P-256, P-384 и обмена ключами X25519.",
  "features.chain.title": "Поддержка множества блокчейнов",
  "features.chain.desc":
    "Bitcoin (все типы адресов), Ethereum/EVM, Solana, Cosmos/Tendermint, Polkadot/Substrate и более 50 монет через SLIP-44.",
  "features.wasm.title": "Нативный WebAssembly",
  "features.wasm.desc":
    "Скомпилировано в WASM для браузера, Node.js и сред WASI. Работает с Go, Rust, Python и любым WASI-совместимым хостом.",
  "features.x509.title": "X.509 и доказательства кошелька",
  "features.x509.desc":
    "Выпускайте стандартные сертификаты P-256/P-384, обменивайтесь PEM/DER/PKCS#12 и встраивайте аттестации кошелька, связывающие сертификат с выбранным криптоключом.",
  "features.hw.title": "Поддержка аппаратных кошельков",
  "features.hw.desc":
    "Слой абстракции для устройств Trezor, Ledger и KeepKey с интеграцией моста WASI для связи по USB/HID.",
  "features.sec.title": "Безопасность прежде всего",
  "features.sec.desc":
    "Безопасное стирание памяти, опциональный FIPS-совместимый режим и всесторонняя проверка входных данных для промышленного использования.",
  "quickstart.heading": "Быстрый старт",
  "quickstart.addresses": "Адреса",
  "quickstart.signing": "Подпись",
  "quickstart.encryption": "Шифрование",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "Стандартная веб-PKI для TLS и идентичности устройств, с уровнем аттестации на основе кошелька, связывающим сертификаты с ключами HD-кошелька.",
  "pki.eyebrow": "Почему мы это используем",
  "pki.title": "X.509 — это то, что остальной интернет уже понимает",
  "pki.p1":
    "Браузеры, балансировщики нагрузки, обратные прокси, развёртывания mTLS, системы идентичности устройств и инструменты хранилищ ключей — все они уже говорят на X.509. Это значит, что если нам нужен сертификат, который сможет использовать реальная инфраструктура, мы применяем обычную веб-PKI, а не изобретаем формат идентичности, специфичный для репозитория.",
  "pki.p2":
    "hd-wallet-wasm добавляет второй путь доказательства: сертификат может нести аттестацию кошелька, подписанную выбранным ключом кошелька. Сертификат остаётся совместимым с TLS, а приложения, которым важна идентичность кошелька, могут проверить дополнительное доказательство.",
  "pki.tag.attest": "Аттестации кошелька",
  "pki.flow.gen": "Сгенерировать ключ сертификата",
  "pki.flow.issue": "Выпустить сертификат X.509",
  "pki.flow.embed": "Встроить доказательство кошелька",
  "pki.flow.verify": "Проверить цепочку + кошелёк",
  "pki.card1.title": "Как это работает",
  "pki.card1.desc":
    "Выпуск сертификатов остаётся на обычных ключах P-256 или P-384. Репозиторий может создавать самоподписанные сертификаты, выпускать подчинённые, конвертировать PEM и DER и упаковывать материал в PKCS#12 для обычных хранилищ ключей.",
  "pki.card2.title": "Почему это важно",
  "pki.card2.desc":
    "Стандартные инструменты TLS получают обычный сертификат. Проверяющие, учитывающие кошелёк, получают дополнительное доказательство того, что сертификат аттестован выбранным ключом кошелька, без замены существующей цепочки PKI.",
  "pki.card3.title": "Как мы это используем",
  "pki.card3.desc":
    "Аттестация кошелька подписывает канонические поля сертификата, включая отпечаток SPKI. Это создаёт устойчивую привязку между сертификатом и выбранной идентичностью кошелька, например корневым ключом Bitcoin secp256k1.",
  "pki.card4.title": "Что проверяют верификаторы",
  "pki.card4.desc":
    "Сначала проверьте обычную цепочку X.509. Затем разберите сертификат и проверьте встроенное доказательство кошелька. Оба должны пройти проверку, если вы хотите доказать, что серверный сертификат привязан ключом кошелька.",
  "chains.heading": "Поддерживаемые блокчейны",
  "chains.sol.sub": "Подписи Ed25519",
  "chains.atom.sub": "Подпись Amino и Direct",
  "chains.dot.sub": "Адреса SS58",
  "chains.ltc.sub": "Все типы адресов",
  "chains.doge.sub": "Адреса P2PKH",
  "chains.more": "+ ещё 50",
  "chains.more.sub": "через SLIP-44",
  "adv.heading": "Состязательная безопасность",
  "adv.subheading":
    "Рациональные субъекты опустошают скомпрометированные ключи. Неопустошённая ценность доказывает целостность ключа.",
  "adv.intro.title": "Что такое состязательная безопасность?",
  "adv.intro.desc":
    "Криптографические открытые ключи могут выводить адреса в сетях криптовалют. Внося ценность на эти выведенные адреса, вы создаёте <strong>залог безопасности по теории игр</strong>. Любой рациональный субъект, скомпрометировавший закрытый ключ, опустошит средства — выплата мгновенна, анонимна и безрисковая. Это делает баланс <strong>индикатором целостности ключа в реальном времени</strong>: неопустошённая ценность означает нескомпрометированный ключ.",
  "adv.flow.pubkey": "Открытый ключ",
  "adv.flow.derive": "Вывести адрес",
  "adv.flow.deposit": "Внести ценность",
  "adv.flow.monitor": "Мониторинг",
  "adv.flow.trusted": "Доверенный",
  "adv.prin1.title": "Вывод ключей",
  "adv.prin1.desc":
    "Открытый ключ, используемый для подписи данных, может математически выводить адреса в нескольких блокчейн-сетях (BIP-32/44). Одна пара ключей служит как для аутентификации, так и для хранения ценности.",
  "adv.prin2.title": "Ценность как сигнал доверия",
  "adv.prin2.desc":
    "Выведенные адреса не требуют разрешений — любой может внести средства, чтобы обозначить доверие к ключу. Совокупный баланс количественно выражает экономическую стоимость компрометации.",
  "adv.prin3.title": "Допущение о рациональном субъекте",
  "adv.prin3.desc":
    "Опустошение средств — доминирующая стратегия: оно <strong>мгновенно, необратимо и несёт нулевой предельный риск</strong>. Поэтому неопустошённая ценность означает отсутствие компрометации.",
  "adv.prin4.title": "Проверка в реальном времени",
  "adv.prin4.desc":
    "Состояние блокчейна публично проверяемо и обновляется с каждым блоком. Это обеспечивает <strong>непрерывное, не требующее разрешений доказательство целостности ключа</strong> — не сертификат, а живой сигнал.",
  "adv.whitepaper": "Читать белую книгу",
  "adv.login.prompt":
    "Войдите, чтобы вывести адреса из ваших ключей и проверить балансы в реальном времени в нескольких блокчейн-сетях.",
  "adv.balances.title": "Ваши выведенные адреса",
  "adv.refresh": "Обновить",
  "adv.balances.intro":
    "Эти адреса математически выведены из ключей вашего HD-кошелька. Любой может проверить вывод и отправить средства, чтобы повысить доверие к вашим ключам.",
  "footer.license": "HD Wallet WASM — Лицензия Apache-2.0",
};

const ur = {
  "lang.label": "زبان",
  "nav.packages": "پیکجز",
  "nav.features": "خصوصیات",
  "nav.quickstart": "فوری آغاز",
  "nav.pki": "X.509 PKI",
  "nav.blockchains": "بلاک چینز",
  "nav.security": "سیکیورٹی",
  "nav.login": "لاگ اِن",
  "nav.logout": "لاگ آؤٹ",
  "nav.account": "اکاؤنٹ",
  "hero.subtitle":
    "خالص C++ میں ایک جامع درجہ بندی شدہ تعیّناتی (HD) والٹ نفاذ، جو کراس پلیٹ فارم ہم آہنگی کے لیے WebAssembly میں مرتب کیا گیا ہے۔ BIP-32/39/44 کے مطابق، کثیر منحنی خفیہ نگاری اور کثیر چین معاونت کے ساتھ۔",
  "hero.demo": "انٹرایکٹو ڈیمو آزمائیں",
  "packages.heading": "پیکجز",
  "packages.wasm.desc":
    "بنیادی WebAssembly لائبریری۔ BIP-32/39/44 HD کلید اخذ، کثیر منحنی خفیہ نگاری، X.509 سرٹیفکیٹ اجرا، والٹ توثیقات، ایڈریس سازی، دستخط، اور 50 سے زائد بلاک چینز کے لیے خفیہ کاری۔",
  "packages.ui.desc":
    "کسی بھی ویب ایپ کے لیے تیار موڈل انٹرفیس۔ لاگ اِن، کلید انتظام، شناخت (vCard)، اعتماد نقشہ اور مخاصمانہ سیکیورٹی بانڈ موڈلز فراہم کرتا ہے۔ کسی بھی بٹن سے منسلک کریں — CSS اپنی مرضی کی خصوصیات کے ذریعے مکمل قابلِ ترتیب۔",
  "packages.ui.note":
    'ہیڈ لیس افادیتیں (ایڈریس اخذ، والٹ ذخیرہ) <code>hd-wallet-ui/lib</code> کے ذریعے بھی دستیاب ہیں۔',
  "features.heading": "خصوصیات",
  "features.bip.title": "BIP معیارات کے مطابق",
  "features.bip.desc":
    "BIP-32 (HD کلیدیں)، BIP-39 (یادداشتی جملے)، BIP-44/49/84 (اکاؤنٹ درجہ بندی) اور SLIP-44 (سکہ اقسام) کا مکمل نفاذ۔",
  "features.curve.title": "کثیر منحنی خفیہ نگاری",
  "features.curve.desc":
    "secp256k1 (بٹ کوائن، ایتھیریم)، Ed25519 (سولانا، پولکاڈوٹ)، NIST P-256، P-384 اور X25519 کلید تبادلے کی معاونت۔",
  "features.chain.title": "کثیر چین معاونت",
  "features.chain.desc":
    "بٹ کوائن (تمام ایڈریس اقسام)، ایتھیریم/EVM، سولانا، Cosmos/Tendermint، Polkadot/Substrate، اور SLIP-44 کے ذریعے 50 سے زائد سکے۔",
  "features.wasm.title": "مقامی WebAssembly",
  "features.wasm.desc":
    "براؤزر، Node.js اور WASI رن ٹائمز کے لیے WASM میں مرتب۔ Go، Rust، Python اور کسی بھی WASI ہم آہنگ میزبان کے ساتھ کام کرتا ہے۔",
  "features.x509.title": "X.509 اور والٹ ثبوت",
  "features.x509.desc":
    "معیاری P-256/P-384 سرٹیفکیٹ جاری کریں، PEM/DER/PKCS#12 کا تبادلہ کریں، اور ایسی والٹ توثیقات شامل کریں جو سرٹیفکیٹ کو منتخب کرپٹو کلید سے جوڑ دیں۔",
  "features.hw.title": "ہارڈویئر والٹ معاونت",
  "features.hw.desc":
    "USB/HID مواصلات کے لیے WASI پل انضمام کے ساتھ Trezor، Ledger اور KeepKey آلات کے لیے تجرید کی تہہ۔",
  "features.sec.title": "سیکیورٹی سب سے پہلے",
  "features.sec.desc":
    "محفوظ میموری صفائی، اختیاری FIPS ہم آہنگ موڈ، اور پیداواری استعمال کے لیے جامع اِن پٹ توثیق۔",
  "quickstart.heading": "فوری آغاز",
  "quickstart.addresses": "ایڈریسز",
  "quickstart.signing": "دستخط",
  "quickstart.encryption": "خفیہ کاری",
  "pki.heading": "X.509 PKI",
  "pki.subheading":
    "TLS اور آلہ شناخت کے لیے معیاری ویب PKI، ایک والٹ سے تعاون یافتہ توثیق تہہ کے ساتھ جو سرٹیفکیٹس کو HD والٹ کلیدوں سے جوڑتی ہے۔",
  "pki.eyebrow": "ہم اسے کیوں استعمال کرتے ہیں",
  "pki.title": "X.509 وہی ہے جسے باقی انٹرنیٹ پہلے ہی سمجھتا ہے",
  "pki.p1":
    "براؤزر، لوڈ بیلنسر، ریورس پراکسی، mTLS تعیناتیاں، آلہ شناخت نظام اور کی اسٹور اوزار سب پہلے ہی X.509 بولتے ہیں۔ اس کا مطلب ہے کہ اگر ہمیں ایسا سرٹیفکیٹ چاہیے جسے حقیقی بنیادی ڈھانچہ استعمال کر سکے، تو ہم ریپو مخصوص شناختی فارمیٹ ایجاد کرنے کے بجائے عام ویب PKI استعمال کرتے ہیں۔",
  "pki.p2":
    "hd-wallet-wasm جو اضافہ کرتا ہے وہ ایک دوسرا ثبوت راستہ ہے: سرٹیفکیٹ منتخب والٹ کلید سے دستخط شدہ والٹ توثیق لے جا سکتا ہے۔ سرٹیفکیٹ TLS کے لیے قابلِ باہمی عمل رہتا ہے، اور جو ایپلی کیشنز والٹ شناخت کی پروا کرتی ہیں وہ اضافی ثبوت کی تصدیق کر سکتی ہیں۔",
  "pki.tag.attest": "والٹ توثیقات",
  "pki.flow.gen": "سرٹیفکیٹ کلید بنائیں",
  "pki.flow.issue": "X.509 سرٹیفکیٹ جاری کریں",
  "pki.flow.embed": "والٹ ثبوت شامل کریں",
  "pki.flow.verify": "چین + والٹ کی تصدیق کریں",
  "pki.card1.title": "یہ کیسے کام کرتا ہے",
  "pki.card1.desc":
    "سرٹیفکیٹ اجرا عام P-256 یا P-384 کلیدوں پر ہی رہتا ہے۔ ریپو خود دستخط شدہ سرٹیفکیٹ بنا سکتا ہے، ماتحت جاری کر سکتا ہے، PEM اور DER تبدیل کر سکتا ہے، اور عام کی اسٹورز کے لیے مواد کو PKCS#12 کے طور پر پیک کر سکتا ہے۔",
  "pki.card2.title": "یہ کیوں اہم ہے",
  "pki.card2.desc":
    "معیاری TLS اوزار کو ایک عام سرٹیفکیٹ ملتا ہے۔ والٹ سے آگاہ تصدیق کنندگان کو ایک اضافی ثبوت ملتا ہے کہ سرٹیفکیٹ کسی منتخب والٹ کلید سے توثیق شدہ ہے، موجودہ PKI چین کو بدلے بغیر۔",
  "pki.card3.title": "ہم اسے کیسے استعمال کرتے ہیں",
  "pki.card3.desc":
    "والٹ توثیق SPKI ڈائجسٹ سمیت معیاری سرٹیفکیٹ خانوں پر دستخط کرتی ہے۔ یہ سرٹیفکیٹ اور منتخب والٹ شناخت (مثلاً بٹ کوائن روٹ secp256k1 کلید) کے درمیان ایک پائیدار بندھن بناتی ہے۔",
  "pki.card4.title": "تصدیق کنندگان کیا جانچتے ہیں",
  "pki.card4.desc":
    "پہلے عام X.509 چین کی توثیق کریں۔ پھر سرٹیفکیٹ کا تجزیہ کریں اور شامل شدہ والٹ ثبوت کی تصدیق کریں۔ اگر آپ ثابت کرنا چاہتے ہیں کہ سرور سرٹیفکیٹ کسی والٹ کلید سے جڑا تھا تو دونوں کا کامیاب ہونا ضروری ہے۔",
  "chains.heading": "معاون بلاک چینز",
  "chains.sol.sub": "Ed25519 دستخط",
  "chains.atom.sub": "Amino اور Direct دستخط",
  "chains.dot.sub": "SS58 ایڈریسز",
  "chains.ltc.sub": "تمام ایڈریس اقسام",
  "chains.doge.sub": "P2PKH ایڈریسز",
  "chains.more": "+ مزید 50",
  "chains.more.sub": "SLIP-44 کے ذریعے",
  "adv.heading": "مخاصمانہ سیکیورٹی",
  "adv.subheading":
    "معقول کردار سمجھوتہ شدہ کلیدوں سے رقم نکال لیتے ہیں۔ غیر نکالی گئی قدر کلید کی سالمیت ثابت کرتی ہے۔",
  "adv.intro.title": "مخاصمانہ سیکیورٹی کیا ہے؟",
  "adv.intro.desc":
    "خفیہ نگاری کی عوامی کلیدیں کرپٹو کرنسی نیٹ ورکس پر ایڈریسز اخذ کر سکتی ہیں۔ اِن اخذ شدہ ایڈریسز پر قدر جمع کر کے آپ ایک <strong>گیم تھیوری سیکیورٹی بانڈ</strong> بناتے ہیں۔ کوئی بھی معقول کردار جو نجی کلید سے سمجھوتہ کرے وہ رقم نکال لے گا — یہ ادائیگی فوری، گمنام اور بلا خطر ہے۔ اس سے بیلنس <strong>کلید کی سالمیت کا حقیقی وقت اشاریہ</strong> بن جاتا ہے: غیر نکالی گئی قدر کا مطلب ہے غیر سمجھوتہ شدہ کلید۔",
  "adv.flow.pubkey": "عوامی کلید",
  "adv.flow.derive": "ایڈریس اخذ کریں",
  "adv.flow.deposit": "قدر جمع کریں",
  "adv.flow.monitor": "نگرانی",
  "adv.flow.trusted": "قابلِ اعتماد",
  "adv.prin1.title": "کلید اخذ",
  "adv.prin1.desc":
    "ڈیٹا پر دستخط کے لیے استعمال ہونے والی عوامی کلید ریاضیاتی طور پر متعدد بلاک چین نیٹ ورکس (BIP-32/44) پر ایڈریسز اخذ کر سکتی ہے۔ ایک ہی کلید جوڑا توثیق اور قدر کی حفاظت دونوں کے لیے کام آتا ہے۔",
  "adv.prin2.title": "قدر بطور اعتماد اشارہ",
  "adv.prin2.desc":
    "اخذ شدہ ایڈریسز بلا اجازت ہیں — کوئی بھی کسی کلید پر اعتماد ظاہر کرنے کے لیے رقم جمع کر سکتا ہے۔ مجموعی بیلنس سمجھوتے کی معاشی لاگت کو مقدار میں ظاہر کرتا ہے۔",
  "adv.prin3.title": "معقول کردار کا مفروضہ",
  "adv.prin3.desc":
    "رقم نکالنا غالب حکمتِ عملی ہے: یہ <strong>فوری، ناقابلِ واپسی اور صفر حاشیائی خطرے والا</strong> ہے۔ لہٰذا غیر نکالی گئی قدر کسی سمجھوتے کے نہ ہونے کو ظاہر کرتی ہے۔",
  "adv.prin4.title": "حقیقی وقت تصدیق",
  "adv.prin4.desc":
    "بلاک چین حالت عوامی طور پر قابلِ آڈٹ ہے اور ہر بلاک پر تازہ ہوتی ہے۔ یہ <strong>کلید کی سالمیت کا مسلسل، بلا اجازت ثبوت</strong> فراہم کرتی ہے — کوئی سرٹیفکیٹ نہیں بلکہ ایک زندہ اشارہ۔",
  "adv.whitepaper": "وائٹ پیپر پڑھیں",
  "adv.login.prompt":
    "اپنی کلیدوں سے ایڈریسز اخذ کرنے اور متعدد بلاک چین نیٹ ورکس پر لائیو بیلنس دیکھنے کے لیے لاگ اِن کریں۔",
  "adv.balances.title": "آپ کے اخذ شدہ ایڈریسز",
  "adv.refresh": "ریفریش",
  "adv.balances.intro":
    "یہ ایڈریسز ریاضیاتی طور پر آپ کی HD والٹ کلیدوں سے اخذ کیے گئے ہیں۔ کوئی بھی اخذ کی تصدیق کر سکتا ہے اور آپ کی کلیدوں پر اعتماد بڑھانے کے لیے رقم بھیج سکتا ہے۔",
  "footer.license": "HD Wallet WASM — Apache-2.0 لائسنس",
};

export const LOCALES = { en, zh, hi, es, ar, fr, bn, pt, ru, ur };
