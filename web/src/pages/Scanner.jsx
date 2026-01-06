import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import axios from 'axios'
import './Scanner.css'

const API_URL = 'http://localhost:5000'

// Risk explanations database with TECHNICAL DETAILS
const RISK_EXPLANATIONS = {
  'Stealing Attack': {
    description: 'This address has been linked to wallet draining attacks that steal funds through malicious smart contract interactions.',
    severity: 'critical',
    recommendation: 'Do NOT interact with this address. Revoke any existing approvals immediately.',
    technicalDetails: {
      pattern: 'Wallet Drainer',
      code: `// Malicious approve() exploitation
function stealTokens(address victim) {
  IERC20(token).transferFrom(
    victim,      // Your wallet address
    attacker,    // Drainer wallet
    balance      // ALL your tokens
  );
}

// The attack requires prior approval:
// approve(attackerContract, MAX_UINT256)`,
      indicators: [
        'Calls transferFrom() on victim wallets without consent',
        'Requests unlimited token approvals (type(uint256).max)',
        'Uses delegatecall to proxy malicious behavior',
        'Multiple rapid transactions draining different victims',
        'Contract contains setApprovalForAll() calls'
      ],
      variables: ['_allowances', 'approved', 'spender']
    }
  },
  'Phishing': {
    description: 'This address is associated with phishing campaigns designed to trick users into revealing private keys or signing malicious transactions.',
    severity: 'critical',
    recommendation: 'Block this address and report it to the relevant authorities.',
    technicalDetails: {
      pattern: 'Signature Phishing',
      code: `// Fake "claim" function that actually drains
function claimReward() external {
  // User thinks they're claiming airdrop
  // Actually signs: setApprovalForAll(attacker, true)
  
  bytes memory payload = abi.encodeWithSignature(
    "setApprovalForAll(address,bool)",
    attackerAddress,
    true
  );
  _executeSignature(msg.sender, payload);
}`,
      indicators: [
        'Mimics legitimate protocol interfaces (Uniswap, OpenSea)',
        'Requests eth_sign or personal_sign for arbitrary data',
        'Uses misleading function names (claim, mint, verify)',
        'Contract deployed by known phishing addresses',
        'Domain spoofing detected in metadata'
      ],
      variables: ['signature', 'permit', 'v, r, s']
    }
  },
  'HONEYPOT': {
    description: 'This token contract is designed to trap funds - you can buy but cannot sell. The contract contains code that blocks or heavily taxes sell transactions.',
    severity: 'critical',
    recommendation: 'Do NOT purchase this token. If you hold any, consider them lost.',
    technicalDetails: {
      pattern: 'Honeypot _transfer() Block',
      code: `// Honeypot pattern in _transfer function
function _transfer(
  address from, 
  address to, 
  uint256 amount
) internal {
  // Checks if selling (to == DEX pair)
  if (to == uniswapV2Pair) {
    // BLOCKS ALL SELLS except owner
    require(from == owner(), "Selling not allowed");
    // OR applies 99% tax:
    // taxAmount = amount * 99 / 100;
  }
  // Buys work normally to attract victims
  super._transfer(from, to, amount);
}`,
      indicators: [
        '_transfer() has conditional sell restrictions',
        'Different logic paths for buy vs sell (pair address check)',
        'Variables like tradingEnabled, canSell, sellAllowed',
        'Blacklist mapping targeting sellers: isBlacklisted[from]',
        'Max transaction limits ONLY applied on sells'
      ],
      variables: ['uniswapV2Pair', 'tradingEnabled', 'isBlacklisted', '_maxSellAmount']
    }
  },
  'Creator Made Honeypots': {
    description: 'The creator of this contract has previously deployed honeypot tokens. This is a strong indicator of malicious intent.',
    severity: 'high',
    recommendation: 'Avoid any contracts deployed by this creator.',
    technicalDetails: {
      pattern: 'Serial Scammer Pattern',
      code: `// Deployer address analysis reveals:
Deployer: 0xScammer...
├── Token1 (HONEYPOT) - Block #14000000
│   └── 347 victims, $89,000 stolen
├── Token2 (RUG PULL) - Block #14500000
│   └── LP removed after 6 hours
├── Token3 (HONEYPOT) - Block #15000000
│   └── 99% sell tax activated
└── THIS TOKEN - Block #15500000 ⚠️
    └── Same bytecode pattern detected`,
      indicators: [
        'Multiple failed/rugged projects from same deployer',
        'Reuses honeypot contract bytecode templates',
        'Similar token naming patterns (PEPE2.0, SHIB2.0)',
        'Deploys → Promotes → Rugs cycle',
        'Uses fresh wallet funded from mixer'
      ],
      variables: ['deployer', 'CREATE2 salt', 'bytecode hash']
    }
  },
  'Cannot Sell All': {
    description: 'The contract contains restrictions preventing holders from selling their full balance, often used in rug pull schemes.',
    severity: 'high',
    recommendation: 'This is a major red flag. Avoid purchasing this token.',
    technicalDetails: {
      pattern: 'Max Sell Restriction',
      code: `// Max sell percentage restriction
uint256 public maxSellPercent = 1; // Only 1%!

modifier checkSellLimit(uint256 amount) {
  uint256 maxSell = balanceOf(msg.sender) * maxSellPercent / 100;
  require(
    amount <= maxSell,
    "Exceeds max sell limit"
  );
  _;
}

function _transfer(...) checkSellLimit(amount) {
  // You can only sell 1% of holdings per tx
}`,
      indicators: [
        'maxSellAmount or maxSellPercent state variable',
        'Cooldown timers: lastSellTime[address]',
        'Balance-based restrictions in _transfer',
        'Only owner can bypass limits: if(from != owner)',
        'Percentage decreases over time'
      ],
      variables: ['maxSellPercent', 'maxSellAmount', '_maxTxAmount', 'sellCooldown']
    }
  },
  'Cannot Buy': {
    description: 'The contract has trading restrictions that prevent new purchases, often seen after a rug pull.',
    severity: 'high',
    recommendation: 'Trading is effectively disabled on this token.',
    technicalDetails: {
      pattern: 'Trading Disabled',
      code: `bool public tradingEnabled = false;

function enableTrading() external onlyOwner {
  tradingEnabled = true;
}

function _transfer(
  address from, 
  address to, 
  uint256 amount
) internal {
  if (!tradingEnabled) {
    // Only owner can move tokens
    require(
      from == owner() || to == owner(),
      "Trading not yet enabled"
    );
  }
}
// enableTrading() was NEVER called`,
      indicators: [
        'tradingEnabled boolean = false',
        'enableTrading() function never called (check Etherscan txs)',
        'Liquidity removed from DEX pools',
        'Contract ownership not renounced',
        'Owner holds majority of supply'
      ],
      variables: ['tradingEnabled', 'tradingOpen', 'swapEnabled', 'launchTime']
    }
  },
  'Hidden Owner': {
    description: 'The contract ownership is obfuscated, making it difficult to identify who controls privileged functions.',
    severity: 'medium',
    recommendation: 'Exercise caution - hidden ownership can enable sudden rug pulls.',
    technicalDetails: {
      pattern: 'Obfuscated Ownership',
      code: `// Hidden owner pattern - appears renounced but isn't
address private _hiddenOwner; // Private, not visible
mapping(address => bool) private _admins;

function owner() public view returns (address) {
  return address(0); // Returns zero - appears renounced!
}

modifier onlyOwner() {
  require(
    _hiddenOwner == msg.sender || _admins[msg.sender],
    "Not authorized"
  );
  _;
}
// Real control via private _hiddenOwner variable`,
      indicators: [
        'Private owner variable: address private _owner',
        'owner() public function returns address(0)',
        'Multiple admin/operator mappings',
        'Proxy pattern hiding real implementation',
        'modifier checks private variable, not public owner()'
      ],
      variables: ['_hiddenOwner', '_admin', '_operator', '_controller', 'proxyAdmin']
    }
  },
  'Owner Can Change Balances': {
    description: 'The contract owner has the ability to modify token balances arbitrarily, allowing them to mint tokens or drain wallets.',
    severity: 'critical',
    recommendation: 'This gives the owner complete control over your funds. Avoid this token.',
    technicalDetails: {
      pattern: 'Direct Balance Manipulation',
      code: `// CRITICAL: Owner can arbitrarily change balances
function setBalance(address account, uint256 amount) 
  external onlyOwner 
{
  _balances[account] = amount; // Direct manipulation!
  // No event emitted - hidden from explorers
}

function burnFrom(address account, uint256 amount)
  external onlyOwner 
{
  _balances[account] -= amount; // Steal tokens
  _balances[owner()] += amount; // Give to owner
}`,
      indicators: [
        'setBalance() or _setBalance() function exists',
        'Direct _balances[addr] = amount writes',
        'burnFrom() without approval checks',
        'No Transfer event on balance changes',
        'Internal function called by owner-only wrapper'
      ],
      variables: ['_balances', '_tOwned', '_rOwned', 'balances']
    }
  },
  'Can Reclaim Ownership': {
    description: 'Even if ownership appears renounced, the contract contains functions to reclaim owner privileges.',
    severity: 'high',
    recommendation: 'Renounced ownership is fake. The deployer can regain control at any time.',
    technicalDetails: {
      pattern: 'Fake Renouncement',
      code: `address private _previousOwner;
uint256 private _lockTime;

function renounceOwnership() public override onlyOwner {
  // Stores owner before "renouncing"
  _previousOwner = _owner;
  _owner = address(0);
  _lockTime = block.timestamp + 365 days;
  emit OwnershipTransferred(_owner, address(0));
}

function reclaimOwnership() public {
  require(msg.sender == _previousOwner);
  require(block.timestamp > _lockTime);
  _owner = _previousOwner; // OWNER IS BACK!
  emit OwnershipTransferred(address(0), _owner);
}`,
      indicators: [
        'unlock(), lock(), or reclaimOwnership() function exists',
        '_previousOwner variable stored on renounce',
        'Time-locked ownership with unlock condition',
        'Ownership transferred to contract address (not burned)',
        'Check contract bytecode for hidden reclaim logic'
      ],
      variables: ['_previousOwner', '_lockTime', 'unlockTime', 'geUnlockTime']
    }
  },
  'Transfer Pausable': {
    description: 'The contract owner can pause all token transfers, potentially locking your funds.',
    severity: 'medium',
    recommendation: 'Be aware that trading can be halted at any time by the owner.',
    technicalDetails: {
      pattern: 'Pausable Transfers',
      code: `// OpenZeppelin Pausable pattern
bool private _paused = false;

modifier whenNotPaused() {
  require(!_paused, "Pausable: paused");
  _;
}

function _transfer(...) internal whenNotPaused {
  // ALL transfers blocked when paused
}

function pause() external onlyOwner {
  _paused = true;
  emit Paused(msg.sender);
}`,
      indicators: [
        'Inherits Pausable contract',
        'paused or _paused boolean state variable',
        'whenNotPaused modifier on _transfer',
        'pause()/unpause() owner-only functions',
        'Emergency stop functionality'
      ],
      variables: ['_paused', 'paused', 'isPaused', 'tradingPaused']
    }
  },
  'Mintable': {
    description: 'New tokens can be created (minted) after deployment, which can dilute token value.',
    severity: 'low',
    recommendation: 'Not always malicious (e.g., stablecoins), but be aware of inflation risk.',
    technicalDetails: {
      pattern: 'Minting Capability',
      code: `// Owner can mint unlimited tokens
function mint(address to, uint256 amount) 
  external onlyOwner 
{
  _totalSupply += amount;
  _balances[to] += amount;
  emit Transfer(address(0), to, amount);
}

// No max supply cap = unlimited inflation
// Owner could mint billions and dump`,
      indicators: [
        'mint() or _mint() function callable by owner',
        'No maxSupply or cap variable',
        'Owner can mint to any address',
        'Check if mint events exist in tx history',
        'Inflationary tokenomics'
      ],
      variables: ['_totalSupply', 'maxSupply', 'cap', 'mintingFinished']
    }
  },
  'Honeypot Related': {
    description: 'This address has interacted with known honeypot contracts or received funds from honeypot operations.',
    severity: 'high',
    recommendation: 'High likelihood of malicious activity. Proceed with extreme caution.',
    technicalDetails: {
      pattern: 'Honeypot Association',
      code: `// Transaction flow analysis shows:
Scammer Deployer
    ↓ deploys
Honeypot Token Contract
    ↓ victims buy
Victim Wallets → Token (can't sell)
    ↓ LP removed
Liquidity Pool → Scammer Wallet
    ↓ profit laundered
THIS ADDRESS (receives stolen ETH)`,
      indicators: [
        'Received ETH/tokens from known honeypot contracts',
        'Part of scam money laundering flow',
        'Connected to flagged addresses via transactions',
        'Interacted with multiple honeypot tokens',
        'Timing correlates with honeypot liquidity removals'
      ],
      variables: ['Transaction hash links', 'Fund flow graph', 'Taint score']
    }
  },
  'Money Laundering': {
    description: 'This address has been flagged for involvement in money laundering activities, often using mixers or complex transaction chains.',
    severity: 'high',
    recommendation: 'Interacting with this address may expose you to legal risks.',
    technicalDetails: {
      pattern: 'Laundering Flow',
      code: `// Typical money laundering pattern
Stolen Funds (Hack/Scam)
    ↓
Tornado Cash (0.1 - 100 ETH pools)
    ↓
Fresh Wallet (no prior history)
    ↓
DEX Swaps (ETH → USDC → WBTC)
    ↓
Cross-chain Bridge (Ethereum → BSC/Polygon)
    ↓
CEX Deposit (with KYC bypass attempts)`,
      indicators: [
        'Received funds from flagged mixer contracts',
        'Complex multi-hop transaction patterns',
        'Rapid cross-chain bridge usage',
        'Split transactions to avoid detection thresholds',
        'Timing patterns suggesting automated laundering'
      ],
      variables: ['Taint percentage', 'Hop count', 'Mixer exposure']
    }
  },
  'Mixer Usage': {
    description: 'This address has used cryptocurrency mixers (like Tornado Cash) to obscure transaction history.',
    severity: 'medium',
    recommendation: 'While mixers have legitimate uses, they are often used to launder stolen funds.',
    technicalDetails: {
      pattern: 'Mixer Interaction',
      code: `// Tornado Cash usage pattern
// Deposit (breaks linkability)
TornadoCash.deposit{value: 1 ether}(
  commitment  // Pedersen hash of secret + nullifier
);

// Later withdrawal (new address)
TornadoCash.withdraw(
  proof,      // zk-SNARK proof
  root,       // Merkle root
  nullifier,  // Prevents double-spend
  recipient,  // Fresh address
  relayer,    // Optional gas relayer
  fee         // Relayer fee
);`,
      indicators: [
        'Direct interaction with Tornado Cash contracts',
        'Deposits matching common denominations (0.1, 1, 10, 100 ETH)',
        'Withdrawals to newly created addresses',
        'Use of relayers to pay gas',
        'OFAC-sanctioned mixer addresses in transaction history'
      ],
      variables: ['commitment', 'nullifier', 'root', 'relayer']
    }
  },
  'Sanctioned Address': {
    description: 'This address is on official sanctions lists (OFAC or similar). Interaction may violate international law.',
    severity: 'critical',
    recommendation: 'Do NOT interact. This could have serious legal consequences.',
    technicalDetails: {
      pattern: 'OFAC SDN List',
      code: `// OFAC Specially Designated Nationals Entry
{
  "address": "0x...",
  "dateAdded": "2022-08-08",
  "program": "CYBER2",
  "entity": "Tornado Cash",
  "sanctions": ["OFAC", "EU", "UK"],
  "legalRisk": "CRITICAL"
}

// US Legal Code 50 USC 1705
// Penalties: Up to 20 years imprisonment
// Civil penalty: Up to $1,000,000 per violation`,
      indicators: [
        'Listed on OFAC SDN list',
        'Associated with Lazarus Group (DPRK)',
        'Connected to ransomware operations',
        'Linked to sanctioned entities (Tornado Cash)',
        'Part of designated terrorist financing network'
      ],
      variables: ['SDN List ID', 'Program code', 'Entity name']
    }
  },
  'Fake Token Creator': {
    description: 'This address has created fake/copycat tokens designed to impersonate legitimate projects.',
    severity: 'high',
    recommendation: 'Any tokens from this creator are likely scams.',
    technicalDetails: {
      pattern: 'Token Impersonation',
      code: `// Fake token deployment pattern
contract FakeARB {
  string public name = "Arbitrum";     // Mimics real name
  string public symbol = "ARB";         // Same symbol
  uint8 public decimals = 18;
  
  // BUT: Different contract address!
  // Real ARB: 0x912CE59144191C1204E64559FE8253a0e49E6548
  // This:     0xFAKE...
  
  // Hidden honeypot in _transfer
  function _transfer(...) {
    if (!isOwner[from]) revert(); // Can't sell
  }
}`,
      indicators: [
        'Token name/symbol identical to popular tokens',
        'Recently deployed (< 24 hours)',
        'No liquidity lock or very short lock',
        'Contract not verified on Etherscan',
        'Different contract address than official'
      ],
      variables: ['name', 'symbol', 'totalSupply', 'deployer']
    }
  },
  'Malicious Contracts Created': {
    description: 'This address has deployed contracts that were later identified as malicious.',
    severity: 'critical',
    recommendation: 'Avoid all contracts and tokens from this deployer.',
    technicalDetails: {
      pattern: 'Serial Deployer',
      code: `// Malicious deployer analysis
Deployer: 0xMalicious...
├── 0xA1: DrainerContract (1,200 victims)
│   └── Stole $2.3M via permit phishing
├── 0xB2: HoneypotToken (850 victims)  
│   └── 99% sell tax after launch
├── 0xC3: FakeAirdrop (3,400 victims)
│   └── setApprovalForAll exploit
└── 0xD4: NEW CONTRACT ← YOU ARE HERE
    └── ASSUME MALICIOUS`,
      indicators: [
        'Multiple contracts flagged as malicious',
        'Pattern of deploying and abandoning projects',
        'Reuses similar exploit code across contracts',
        'Fresh deployer wallet funded from mixer',
        'CREATE2 used for address grinding'
      ],
      variables: ['Deployer nonce', 'Contract bytecode hash', 'Creation tx']
    }
  },
  'Cybercrime': {
    description: 'This address has been linked to cybercrime activities including hacking, exploits, or coordinated attacks.',
    severity: 'critical',
    recommendation: 'Blacklist this address immediately.',
    technicalDetails: {
      pattern: 'Exploit Attribution',
      code: `// Common exploit patterns observed
1. Flash Loan Attack:
   Aave.flashLoan() → PriceOracle.manipulate() → 
   Protocol.drain() → Aave.repay()

2. Reentrancy:
   Contract.withdraw() → Attacker.receive() → 
   Contract.withdraw() → ... (repeat)

3. Access Control Bypass:
   Proxy.initialize() // Missing initializer guard
   
4. This address received funds from:
   - Ronin Bridge Hack ($625M)
   - Wormhole Exploit ($320M)  
   - Nomad Bridge ($190M)`,
      indicators: [
        'Received funds from known hacks',
        'Flash loan attack transaction patterns',
        'MEV sandwich attack profits',
        'Attribution by chain analysis firms',
        'Associated with known hacker groups (Lazarus, etc.)'
      ],
      variables: ['Exploit signature', 'Attack vector', 'Stolen amount']
    }
  },
  'Financial Crime': {
    description: 'This address is associated with financial crimes such as fraud, Ponzi schemes, or investment scams.',
    severity: 'high',
    recommendation: 'Exercise extreme caution. Verify through multiple sources.',
    technicalDetails: {
      pattern: 'Ponzi/Fraud',
      code: `// Classic Ponzi contract pattern
contract YieldFarm {
  uint256 constant APY = 36500; // 100% daily!
  
  mapping(address => uint256) public deposits;
  mapping(address => uint256) public lastClaim;
  
  function deposit() external payable {
    deposits[msg.sender] += msg.value;
  }
  
  function claim() external {
    uint256 reward = calculateReward(msg.sender);
    // Pays from new deposits, not actual yield
    payable(msg.sender).transfer(reward);
  }
  
  function rugPull() external onlyOwner {
    payable(owner).transfer(address(this).balance);
  }
}`,
      indicators: [
        'Unrealistic APY promises (100%+ daily)',
        'Referral/pyramid mechanics',
        'No real yield generation strategy',
        'TVL drop after initial growth',
        'Owner withdrawal of pooled funds'
      ],
      variables: ['APY', 'referralBonus', 'lockPeriod', 'owner']
    }
  },
  'Darkweb Activity': {
    description: 'Transaction patterns suggest involvement with darkweb marketplaces or services.',
    severity: 'high',
    recommendation: 'Interaction could expose you to regulatory scrutiny.',
    technicalDetails: {
      pattern: 'Darkweb Linkage',
      code: `// Transaction analysis indicators
- Payment amounts matching darkweb market prices
- BTC/XMR swap patterns via DEX aggregators
- Timing correlation with marketplace activity
- Known vendor wallet interactions

// Common flow:
Buyer Wallet (clean)
    ↓ 0.05 ETH exact amount
Exchange/DEX
    ↓ ETH → XMR atomic swap
Monero (untraceable)
    ↓
Vendor Wallet
    ↓
This Address (cash-out endpoint)`,
      indicators: [
        'Transactions with known darkweb wallets',
        'Privacy coin (XMR, ZEC) swap patterns',
        'Specific payment amounts matching listings',
        'Geographic IP correlation (Tor exit nodes)',
        'Timing matches marketplace uptime'
      ],
      variables: ['Transaction amount', 'Swap path', 'Timing correlation']
    }
  }
}

// Website Risk Explanations with Technical Details
const WEBSITE_RISK_EXPLANATIONS = {
  'brand_impersonation': {
    name: 'Brand Impersonation',
    description: 'This website is impersonating a legitimate Web3 project. The domain contains brand names but is NOT the official site.',
    severity: 'critical',
    technicalDetails: {
      pattern: 'Domain Spoofing / Typosquatting',
      code: null,
      warning: `🎭 BRAND IMPERSONATION DETECTED

This is a FAKE website designed to look like a legitimate service!

How attackers trick you:
• Register similar domain (uniswap-app.org)
• Clone the real website's appearance
• Replace contract addresses with malicious ones
• Promote via Discord DMs, Twitter ads, Google ads

⚠️ ALWAYS VERIFY:
• Bookmark official sites and use those bookmarks
• Check the URL letter by letter
• Never trust links from DMs or emails
• Search for the official site on Google`,
      indicators: [
        'Domain contains known brand (uniswap, opensea, metamask)',
        'TLD differs from official (.xyz, .app instead of .org)',
        'Extra words added (airdrop, claim, bonus, mint)',
        'Subtle misspellings (metamaks, openseaa)',
        'Recently registered domain (< 30 days)'
      ]
    }
  },
  'suspicious_keywords': {
    name: 'Suspicious URL Keywords',
    description: 'The URL contains keywords commonly associated with crypto scams like "airdrop", "claim", "free", or "bonus".',
    severity: 'high',
    technicalDetails: {
      pattern: 'Social Engineering Keywords',
      code: null,
      warning: `🎣 SCAM KEYWORD DETECTED IN URL

URLs with these words are almost ALWAYS scams:
• "airdrop" - Fake token drops
• "claim" - Creates false urgency  
• "free" - Too good to be true
• "bonus" - Bait tactics
• "giveaway" - Impersonation scams
• "verify" - Phishing for private keys

✅ REAL protocols don't use these in URLs:
   app.uniswap.org/swap

❌ SCAM patterns:
   uniswap-airdrop-claim.xyz/free-tokens

💡 If someone promised you free tokens via DM, it's a SCAM.`,
      indicators: [
        'URL contains urgency words (claim, verify, urgent)',
        'Promises free tokens or NFTs',
        'Asks to "verify" or "validate" wallet',
        'Uses "connect wallet" in domain itself',
        'Claims official airdrops from major protocols'
      ]
    }
  },
  'suspicious_tld': {
    name: 'Suspicious Domain Extension',
    description: 'The website uses a domain extension (TLD) commonly abused by scammers due to low cost and minimal verification.',
    severity: 'medium',
    technicalDetails: {
      pattern: 'High-Risk TLD Analysis',
      code: null,
      warning: `⚠️ SUSPICIOUS DOMAIN EXTENSION

This site uses a domain extension often abused by scammers:

🔴 HIGH RISK (Free/Cheap):
   .tk, .ml, .ga, .cf, .gq - FREE domains
   .xyz - Only $1/year
   .top, .click - Minimal verification

🟡 MEDIUM RISK:
   .io, .app, .site, .online - Can be legit, but verify

🟢 LOWER RISK:
   .com, .org, .net - Higher cost & verification
   .finance, .exchange - Industry-specific

💡 Scammers prefer cheap domains because they're disposable.
   Check domain age at whois.domaintools.com`,
      indicators: [
        'Uses free TLD (.tk, .ml, .ga, .cf, .gq)',
        'Recently available TLDs with low barrier',
        'TLD doesn\'t match industry standard',
        'Combined with suspicious keywords',
        'WHOIS shows recent registration'
      ]
    }
  },
  'wallet_drainer': {
    name: 'Wallet Drainer Detected',
    description: 'This site contains code patterns consistent with wallet draining attacks that steal all tokens upon wallet connection.',
    severity: 'critical',
    technicalDetails: {
      pattern: 'setApprovalForAll / Permit Drainer',
      code: null, // No fake code - we don't have the actual source
      warning: `⚠️ WHAT DRAINERS DO:

1. Request setApprovalForAll() - gives them access to ALL your NFTs
2. Request permit() signatures - allows gasless token theft  
3. Use eth_sign for arbitrary messages - can sign away your assets
4. Hide malicious code in obfuscated JavaScript

🔍 HOW TO VERIFY:
• Check the transaction details in your wallet before signing
• Never approve "unlimited" token amounts
• Revoke suspicious approvals at revoke.cash`,
      indicators: [
        'Calls setApprovalForAll() immediately on connect',
        'Requests permit signatures for ERC20 tokens',
        'Uses eth_sign for arbitrary data signing',
        'Obfuscated/minified JavaScript hiding drainer logic',
        'External scripts loaded from suspicious domains'
      ]
    }
  },
  'phishing_site': {
    name: 'Confirmed Phishing Site',
    description: 'This website has been confirmed in security databases as a phishing site actively stealing user credentials or funds.',
    severity: 'critical',
    technicalDetails: {
      pattern: 'Database Match - GoPlus/PhishTank',
      code: null,
      warning: `🚨 THIS SITE IS IN PHISHING DATABASES

Confirmed malicious by:
• GoPlus Security Database
• PhishTank Community Reports  
• Chainabuse Scam Reports
• OpenPhish Detection

⛔ DO NOT:
• Connect your wallet
• Enter any personal information
• Download any files
• Click any links

✅ INSTEAD:
• Close this site immediately
• Report it at chainabuse.com
• If you connected, revoke approvals at revoke.cash`,
      indicators: [
        'Listed in GoPlus phishing database',
        'Multiple user reports on Chainabuse',
        'PhishTank confirmed submission',
        'Associated with known scam wallets',
        'SSL certificate issues or mismatches'
      ]
    }
  },
  'unknown_dapp': {
    name: 'Unverified dApp',
    description: 'This dApp is not in any security database. While not necessarily malicious, extra caution is recommended.',
    severity: 'low',
    technicalDetails: {
      pattern: 'No Database Records',
      code: null,
      warning: `ℹ️ UNVERIFIED - PROCEED WITH CAUTION

This site is NOT in any security database, which means:
• It could be new and legitimate
• It could be a scam not yet reported
• No security audits found

🔍 BEFORE CONNECTING:
• Research the project on Twitter/Discord
• Check if the team is doxxed (publicly known)
• Look for independent audit reports
• Check TVL on DefiLlama or similar
• Search for user reviews

💡 SAFETY TIP:
Start with a small test transaction before committing larger amounts.`,
      indicators: [
        'Not in GoPlus trust list',
        'No audit records found',
        'Domain registered recently',
        'Limited social media presence',
        'No TVL tracking on DefiLlama'
      ]
    }
  }
}

// Legitimate alternatives database
const LEGITIMATE_ALTERNATIVES = {
  'uniswap': {
    name: 'Uniswap',
    official: 'https://app.uniswap.org',
    description: 'The largest decentralized exchange on Ethereum',
    verify: 'Look for the official .org domain and verified Twitter @Uniswap'
  },
  'opensea': {
    name: 'OpenSea',
    official: 'https://opensea.io',
    description: 'The largest NFT marketplace',
    verify: 'Always use opensea.io - never opensea.com or variations'
  },
  'metamask': {
    name: 'MetaMask',
    official: 'https://metamask.io',
    description: 'The most popular Web3 wallet',
    verify: 'Download only from metamask.io or official app stores'
  },
  'pancakeswap': {
    name: 'PancakeSwap',
    official: 'https://pancakeswap.finance',
    description: 'Leading DEX on BNB Chain',
    verify: 'Official domain is pancakeswap.finance'
  },
  'aave': {
    name: 'Aave',
    official: 'https://app.aave.com',
    description: 'Decentralized lending protocol',
    verify: 'Use app.aave.com for the application'
  },
  'binance': {
    name: 'Binance',
    official: 'https://www.binance.com',
    description: 'World\'s largest crypto exchange',
    verify: 'Always binance.com - check for phishing variants'
  },
  'coinbase': {
    name: 'Coinbase',
    official: 'https://www.coinbase.com',
    description: 'US-regulated crypto exchange',
    verify: 'Official site is coinbase.com'
  },
  'ethereum': {
    name: 'Ethereum',
    official: 'https://ethereum.org',
    description: 'Official Ethereum Foundation site',
    verify: 'ethereum.org is the only official site'
  },
  'lido': {
    name: 'Lido',
    official: 'https://lido.fi',
    description: 'Liquid staking protocol',
    verify: 'lido.fi - never lido.finance or similar'
  },
  'curve': {
    name: 'Curve',
    official: 'https://curve.fi',
    description: 'Stablecoin DEX',
    verify: 'curve.fi is the official domain'
  },
  'github': {
    name: 'GitHub',
    official: 'https://github.com',
    description: 'Code hosting and collaboration platform',
    verify: 'github.com is the only official domain'
  },
  'google': {
    name: 'Google',
    official: 'https://www.google.com',
    description: 'Search engine and tech services',
    verify: 'google.com is the official domain'
  },
  'microsoft': {
    name: 'Microsoft',
    official: 'https://www.microsoft.com',
    description: 'Technology company',
    verify: 'microsoft.com or live.com for services'
  },
  'apple': {
    name: 'Apple',
    official: 'https://www.apple.com',
    description: 'Technology company',
    verify: 'apple.com is the only official domain'
  },
  'amazon': {
    name: 'Amazon',
    official: 'https://www.amazon.com',
    description: 'E-commerce and cloud services',
    verify: 'amazon.com - beware of variants'
  },
  'paypal': {
    name: 'PayPal',
    official: 'https://www.paypal.com',
    description: 'Online payment service',
    verify: 'paypal.com is the only official domain'
  },
  'twitter': {
    name: 'Twitter/X',
    official: 'https://twitter.com',
    description: 'Social media platform',
    verify: 'twitter.com or x.com are official'
  },
  'facebook': {
    name: 'Facebook',
    official: 'https://www.facebook.com',
    description: 'Social media platform',
    verify: 'facebook.com is the official domain'
  },
  'instagram': {
    name: 'Instagram',
    official: 'https://www.instagram.com',
    description: 'Photo and video sharing platform',
    verify: 'instagram.com is the official domain'
  },
  'discord': {
    name: 'Discord',
    official: 'https://discord.com',
    description: 'Communication platform',
    verify: 'discord.com or discord.gg for invites'
  },
  'telegram': {
    name: 'Telegram',
    official: 'https://telegram.org',
    description: 'Messaging platform',
    verify: 'telegram.org or t.me are official'
  }
}

// Typosquat character map for normalization
const TYPOSQUAT_MAP = {
  '1': 'i', 'l': 'i', '!': 'i',
  '0': 'o',
  '3': 'e',
  '4': 'a', '@': 'a',
  '5': 's', '$': 's',
  '7': 't',
  '8': 'b'
}

// Normalize text by replacing common typosquat characters
function normalizeTyposquat(text) {
  let normalized = text.toLowerCase()
  // Replace single character substitutions
  for (const [fake, real] of Object.entries(TYPOSQUAT_MAP)) {
    normalized = normalized.split(fake).join(real)
  }
  // Replace multi-character substitutions
  normalized = normalized.replace(/vv/g, 'w').replace(/uu/g, 'w')
  normalized = normalized.replace(/rn/g, 'm').replace(/nn/g, 'm')
  return normalized
}

// Function to detect which legitimate brand is being impersonated
function detectImpersonatedBrand(url) {
  const urlLower = url.toLowerCase()
  const normalizedUrl = normalizeTyposquat(urlLower)
  
  for (const [key, brand] of Object.entries(LEGITIMATE_ALTERNATIVES)) {
    // Check exact match
    if (urlLower.includes(key)) {
      return brand
    }
    // Check typosquatted version (but not on legitimate domain)
    if (normalizedUrl.includes(key) && !urlLower.includes(key)) {
      return brand
    }
  }
  return null
}

// Function to analyze website risks and generate detailed explanation
function analyzeWebsiteRisks(data) {
  const analysis = {
    explanations: [],
    technicalDetails: [],
    impersonatedBrand: null,
    recommendations: []
  }
  
  // Check for typosquatting from backend API response (highest priority)
  if (data.is_typosquat && data.impersonating) {
    const imp = data.impersonating
    analysis.impersonatedBrand = {
      name: imp.brand || imp.domain,
      official: imp.official_url || `https://${imp.domain}`,
      description: imp.info?.description || `Official ${imp.brand || imp.domain} website`,
      verify: imp.info?.verify || `Always verify you're on the official domain: ${imp.domain}`
    }
    analysis.explanations.push(WEBSITE_RISK_EXPLANATIONS['brand_impersonation'])
    analysis.recommendations.push(`⚠️ This is a FAKE site! Visit the REAL ${imp.brand || imp.domain} at: ${imp.official_url || imp.domain}`)
  }
  
  // Check for brand impersonation or typosquatting from ML analysis risk factors
  if (!analysis.impersonatedBrand && data.ml_prediction?.analysis?.risk_factors) {
    const typosquatFactor = data.ml_prediction.analysis.risk_factors.find(f => 
      f.factor === 'Typosquatting Detected' || f.factor === 'Brand Impersonation Detected'
    )
    if (typosquatFactor) {
      // Extract brand name from the value (e.g., 'Impersonating "github"')
      const match = typosquatFactor.value?.match(/[Ii]mpersonating "(\w+)"/)
      const brandKey = match ? match[1].toLowerCase() : null
      
      // Use brand_info from risk factor if available
      if (typosquatFactor.brand_info) {
        analysis.impersonatedBrand = {
          name: typosquatFactor.brand_info.name,
          official: typosquatFactor.official_url || typosquatFactor.brand_info.official,
          description: typosquatFactor.brand_info.description || `Official ${typosquatFactor.brand_info.name} website`,
          verify: `Always verify you're on: ${typosquatFactor.official_domain}`
        }
      } else if (brandKey && LEGITIMATE_ALTERNATIVES[brandKey]) {
        analysis.impersonatedBrand = LEGITIMATE_ALTERNATIVES[brandKey]
      }
      
      if (analysis.impersonatedBrand) {
        analysis.explanations.push(WEBSITE_RISK_EXPLANATIONS['brand_impersonation'])
        analysis.recommendations.push(`Visit the official ${analysis.impersonatedBrand.name} at: ${analysis.impersonatedBrand.official}`)
      }
    }
  }
  
  // Fallback: Check for brand impersonation using URL matching (frontend detection)
  if (!analysis.impersonatedBrand && (data.ml_prediction?.is_phishing || data.score >= 50)) {
    const brand = detectImpersonatedBrand(data.url)
    if (brand) {
      analysis.impersonatedBrand = brand
      analysis.explanations.push(WEBSITE_RISK_EXPLANATIONS['brand_impersonation'])
      analysis.recommendations.push(`Visit the official ${brand.name} at: ${brand.official}`)
    }
  }
  
  // Check flags for specific patterns
  const flags = data.flags || []
  flags.forEach(flag => {
    if (flag.includes('Phishing detected') || flag.includes('PHISHING')) {
      analysis.explanations.push(WEBSITE_RISK_EXPLANATIONS['wallet_drainer'])
    }
    if (flag.includes('suspicious keyword') || flag.includes('airdrop') || flag.includes('claim')) {
      if (!analysis.explanations.find(e => e.name === 'Suspicious URL Keywords')) {
        analysis.explanations.push(WEBSITE_RISK_EXPLANATIONS['suspicious_keywords'])
      }
    }
    if (flag.includes('Unverified') || flag.includes('Not in GoPlus')) {
      if (!analysis.explanations.find(e => e.name === 'Unverified dApp')) {
        analysis.explanations.push(WEBSITE_RISK_EXPLANATIONS['unknown_dapp'])
      }
    }
  })
  
  // Add phishing explanation if confirmed
  if (data.is_phishing) {
    analysis.explanations.unshift(WEBSITE_RISK_EXPLANATIONS['phishing_site'])
  }
  
  // Generate recommendations
  if (data.score >= 70) {
    analysis.recommendations.push('Do NOT connect your wallet to this site')
    analysis.recommendations.push('Report this site to chainabuse.com')
    analysis.recommendations.push('If you connected, revoke approvals at revoke.cash')
  } else if (data.score >= 40) {
    analysis.recommendations.push('Exercise extreme caution before connecting')
    analysis.recommendations.push('Research the project thoroughly')
    analysis.recommendations.push('Start with a fresh wallet and small amounts')
  } else if (data.score >= 20) {
    analysis.recommendations.push('Verify authenticity through official channels')
    analysis.recommendations.push('Check project\'s official Twitter/Discord')
  }
  
  return analysis
}

// Simple explanations for non-technical users
function getSimpleExplanation(riskName) {
  const explanations = {
    'Brand Impersonation': 
      'This website is pretending to be a well-known crypto service (like Uniswap or OpenSea) but it\'s NOT the real one. Scammers copy the look of popular sites to trick you. If you connect your wallet here, they could steal all your crypto and NFTs.',
    
    'Suspicious URL Keywords': 
      'The website address contains words like "airdrop", "free", "claim", or "bonus" which are classic tricks scammers use. Real crypto projects rarely give away free tokens through random websites. This is almost always a trap to steal your funds.',
    
    'Suspicious Domain Extension': 
      'This website uses a cheap or free domain extension (.xyz, .tk, .ml) that scammers love because they\'re easy to get and throw away. Legitimate crypto projects usually use .com, .org, or .io domains that cost more and have better verification.',
    
    'Wallet Drainer Detected': 
      'This site contains hidden code designed to empty your wallet! When you click "Connect Wallet" or "Claim", it secretly requests permission to transfer ALL your tokens and NFTs to the scammer. One wrong click = everything gone.',
    
    'Confirmed Phishing Site': 
      'This website has been CONFIRMED as a scam by security researchers. Multiple people have already lost money here. It\'s in our database of known phishing sites. There\'s absolutely no reason to ever connect your wallet here.',
    
    'Unverified dApp': 
      'We couldn\'t find any information about this website in security databases. It might be new, unknown, or intentionally hiding. While it\'s not necessarily a scam, you should be extra careful and research the project before connecting your wallet.'
  }
  
  return explanations[riskName] || 'This risk indicator suggests the website may not be trustworthy. Always verify through official channels before connecting your wallet.'
}

// Get specific recommendations based on risk type
function getWebsiteRecommendation(severity, riskName) {
  if (severity === 'critical') {
    if (riskName === 'Wallet Drainer Detected' || riskName === 'Confirmed Phishing Site') {
      return 'LEAVE THIS SITE IMMEDIATELY. Do not click anything. If you already connected your wallet, go to revoke.cash right now and revoke ALL approvals. Move your funds to a new wallet if possible.'
    }
    return 'Do NOT interact with this website under any circumstances. Close the tab immediately and report it to chainabuse.com to help protect others.'
  }
  
  if (severity === 'high') {
    if (riskName === 'Brand Impersonation') {
      return 'This is likely a fake version of a legitimate site. Find the real website by searching on Google or checking the project\'s official Twitter/Discord. Never click links in DMs or emails claiming to be from crypto projects.'
    }
    return 'This website shows multiple warning signs. If you must use it, create a brand new wallet with a small test amount first. Never use your main wallet on suspicious sites.'
  }
  
  if (severity === 'medium') {
    return 'Proceed with caution. Research this project thoroughly before connecting. Check their Twitter, Discord, and look for reviews. When in doubt, ask in community forums if the site is legitimate.'
  }
  
  return 'While no major issues were found, always verify website authenticity through official channels. Bookmark legitimate sites to avoid typosquatting attacks.'
}

function Scanner() {
  const [activeTab, setActiveTab] = useState('address')
  const [addressInput, setAddressInput] = useState('')
  const [websiteInput, setWebsiteInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [codeAnalysis, setCodeAnalysis] = useState(null)
  const [codeAnalysisLoading, setCodeAnalysisLoading] = useState(false)
  const [simulationResult, setSimulationResult] = useState(null)
  const [simulationLoading, setSimulationLoading] = useState(false)
  const [dappSimulationResult, setDappSimulationResult] = useState(null)
  const [dappSimulationLoading, setDappSimulationLoading] = useState(false)
  const [error, setError] = useState(null)
  const [expandedSection, setExpandedSection] = useState(null)

  const checkAddress = async () => {
    if (!addressInput || addressInput.length !== 42) {
      setError('Please enter a valid Ethereum address (0x...)')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)
    setSimulationResult(null)

    try {
      const response = await axios.get(`${API_URL}/score/${addressInput}`)
      console.log('[DEBUG] Full API response:', response.data)
      console.log('[DEBUG] contract_analysis:', response.data.contract_analysis)
      if (response.data.contract_analysis) {
        console.log('[DEBUG] has_source:', response.data.contract_analysis.has_source)
        console.log('[DEBUG] findings count:', response.data.contract_analysis.findings?.length)
      }
      setResult({ type: 'address', data: response.data })
      
      // Automatically run honeypot simulation after getting address results
      runSimulation()
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to check address. Make sure the API is running.')
    } finally {
      setLoading(false)
    }
  }

  const runSimulation = async () => {
    if (!addressInput || addressInput.length !== 42) {
      setError('Please enter a valid Ethereum address')
      return
    }

    setSimulationLoading(true)
    setSimulationResult(null)

    try {
      const response = await axios.get(`${API_URL}/simulate/${addressInput}`, {
        timeout: 120000 // 2 minute timeout for simulation
      })
      console.log('[SIMULATION] Result:', response.data)
      setSimulationResult(response.data)
    } catch (err) {
      const errorMsg = err.response?.data?.error || err.message
      
      // Check if Ganache not running
      if (errorMsg.includes('Cannot connect') || errorMsg.includes('ECONNREFUSED')) {
        setSimulationResult({
          error: 'Ganache not running',
          setup_required: true,
          instructions: err.response?.data?.instructions || [
            '1. Start Ganache: .\\start_ganache.bat',
            '2. Keep it running in background',
            '3. Try simulation again'
          ]
        })
      } else {
        setSimulationResult({
          error: errorMsg,
          details: err.response?.data
        })
      }
    } finally {
      setSimulationLoading(false)
    }
  }

  const runDappSimulation = async () => {
    if (!websiteInput) {
      return
    }

    setDappSimulationLoading(true)
    setDappSimulationResult(null)

    try {
      const response = await axios.get(`${API_URL}/simulate-dapp`, {
        params: { url: websiteInput },
        timeout: 60000 // 60 second timeout for dApp simulation
      })
      console.log('[DAPP SIMULATION] Result:', response.data)
      setDappSimulationResult(response.data)
    } catch (err) {
      const errorMsg = err.response?.data?.error || err.message
      setDappSimulationResult({
        error: errorMsg,
        details: err.response?.data
      })
    } finally {
      setDappSimulationLoading(false)
    }
  }

  const checkWebsite = async () => {
    if (!websiteInput) {
      setError('Please enter a website URL')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)
    setCodeAnalysis(null)
    // Clear previous dApp simulation result to prevent flash of old data
    setDappSimulationResult(null)
    setDappSimulationLoading(false)

    try {
      const response = await axios.get(`${API_URL}/site`, {
        params: { url: websiteInput }
      })
      setResult({ type: 'website', data: response.data })
      
      // Run dApp simulation FIRST to get context for code analysis
      setDappSimulationLoading(true)
      try {
        const simResponse = await axios.get(`${API_URL}/simulate-dapp`, {
          params: { url: websiteInput },
          timeout: 60000
        })
        console.log('[DAPP SIMULATION] Result:', simResponse.data)
        setDappSimulationResult(simResponse.data)
        setDappSimulationLoading(false)
        
        // Now run code analysis WITH simulation context
        setCodeAnalysisLoading(true)
        try {
          // Extract simulation context
          const isMalicious = simResponse.data?.is_malicious || false
          const confidence = simResponse.data?.confidence || 0
          const simulationIsSafe = !isMalicious
          
          // Try browser mode with context-aware parameters
          const codeResponse = await axios.get(`${API_URL}/analyze-browser`, {
            params: { 
              url: websiteInput,
              simulation_is_safe: simulationIsSafe,
              simulation_confidence: confidence
            },
            timeout: 60000
          })
          
          if (codeResponse.data) {
            codeResponse.data.note = codeResponse.data.method === 'browser' 
              ? `Used real browser to load and analyze JavaScript${simulationIsSafe ? ' (filtered by safe simulation)' : ''}` 
              : 'Analyzed via HTTP request'
          }
          
          setCodeAnalysis(codeResponse.data)
        } catch (codeErr) {
          console.log('Code analysis failed:', codeErr.message)
          setCodeAnalysis({ 
            error: codeErr.response?.data?.error || codeErr.message || 'Analysis timed out',
            url: websiteInput
          })
        } finally {
          setCodeAnalysisLoading(false)
        }
      } catch (simErr) {
        console.log('[DAPP SIMULATION] Failed:', simErr.message)
        const errorMsg = simErr.response?.data?.error || simErr.message
        setDappSimulationResult({
          error: errorMsg,
          details: simErr.response?.data
        })
        setDappSimulationLoading(false)
        
        // Still run code analysis but without simulation context
        setCodeAnalysisLoading(true)
        try {
          const codeResponse = await axios.get(`${API_URL}/analyze-browser`, {
            params: { url: websiteInput },
            timeout: 60000
          })
          
          if (codeResponse.data) {
            codeResponse.data.note = codeResponse.data.method === 'browser' 
              ? 'Used real browser to load and analyze JavaScript' 
              : 'Analyzed via HTTP request'
          }
          
          setCodeAnalysis(codeResponse.data)
        } catch (codeErr) {
          console.log('Code analysis failed:', codeErr.message)
          setCodeAnalysis({ 
            error: codeErr.response?.data?.error || codeErr.message || 'Analysis timed out',
            url: websiteInput
          })
        } finally {
          setCodeAnalysisLoading(false)
        }
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to check website. Make sure the API is running.')
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (score) => {
    if (score >= 80) return '#dc3545'
    if (score >= 50) return '#fd7e14'
    if (score >= 30) return '#ffc107'
    return '#27ae60'
  }

  const getRiskLevel = (score) => {
    if (score >= 80) return 'DANGEROUS'
    if (score >= 50) return 'SUSPICIOUS'
    if (score >= 30) return 'CAUTION'
    return 'SAFE'
  }

  const getRiskExplanation = (flag) => {
    return RISK_EXPLANATIONS[flag] || {
      description: `This address has been flagged for: ${flag}`,
      severity: 'medium',
      recommendation: 'Proceed with caution and verify through additional sources.'
    }
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'linear-gradient(135deg, #dc2626, #b91c1c)'
      case 'high': return 'linear-gradient(135deg, #ea580c, #c2410c)'
      case 'medium': return 'linear-gradient(135deg, #ca8a04, #a16207)'
      case 'low': return 'linear-gradient(135deg, #16a34a, #15803d)'
      default: return 'linear-gradient(135deg, #6b7280, #4b5563)'
    }
  }

  const getEtherscanLink = (address) => `https://etherscan.io/address/${address}`
  const getGoPlusLink = (address) => `https://gopluslabs.io/token-security/1/${address}`

  return (
    <div className="scanner-page">
      <div className="scanner-bg-effects">
        <div className="scanner-orb scanner-orb-1"></div>
        <div className="scanner-orb scanner-orb-2"></div>
        <div className="scanner-grid"></div>
      </div>

      <div className="container">
        <motion.div
          className="scanner-header"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <span className="section-number">02</span>
          <h1 className="scanner-title">
            SECURITY<br /><span className="highlight">SCANNER</span>
          </h1>
          <p className="scanner-subtitle">
            DEEP ANALYSIS OF ETHEREUM ADDRESSES AND DAPPS USING AI + GOPLUS SECURITY API.
            VERIFY ANY ADDRESS BEFORE YOU INTERACT.
          </p>
        </motion.div>

        <motion.div
          className="scanner-card"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="scanner-tabs">
            <button
              className={`scanner-tab ${activeTab === 'address' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('address')
                setResult(null)
                setError(null)
              }}
            >
              <span className="tab-number">01</span>
              ETHEREUM ADDRESS
            </button>
            <button
              className={`scanner-tab ${activeTab === 'website' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('website')
                setResult(null)
                setError(null)
              }}
            >
              <span className="tab-number">02</span>
              WEBSITE / DAPP
            </button>
          </div>

          <div className="scanner-input-area">
            {activeTab === 'address' ? (
              <div className="scanner-input-group">
                <div className="scanner-input-wrapper">
                  <input
                    type="text"
                    className="scanner-input"
                    placeholder="Enter Ethereum address (0x...)"
                    value={addressInput}
                    onChange={(e) => setAddressInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && checkAddress()}
                  />
                  <span className="scanner-input-hint">42 characters starting with 0x</span>
                </div>
                <button
                  className="scanner-btn"
                  onClick={checkAddress}
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <span className="scanner-spinner"></span>
                      Scanning...
                    </>
                  ) : (
                    <>
                      <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                        <circle cx="9" cy="9" r="6" stroke="currentColor" strokeWidth="2" />
                        <path d="M13.5 13.5L17 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                      </svg>
                      Scan Address
                    </>
                  )}
                </button>
              </div>
            ) : (
              <div className="scanner-input-group">
                <div className="scanner-input-wrapper">
                  <input
                    type="text"
                    className="scanner-input"
                    placeholder="Enter website URL (https://...)"
                    value={websiteInput}
                    onChange={(e) => setWebsiteInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && checkWebsite()}
                  />
                  <span className="scanner-input-hint">Full URL including https://</span>
                </div>
                <button
                  className="scanner-btn"
                  onClick={checkWebsite}
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <span className="scanner-spinner"></span>
                      Scanning...
                    </>
                  ) : (
                    <>
                      <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                        <circle cx="9" cy="9" r="6" stroke="currentColor" strokeWidth="2" />
                        <path d="M13.5 13.5L17 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                      </svg>
                      Scan Website
                    </>
                  )}
                </button>
              </div>
            )}
          </div>

          <AnimatePresence>
            {error && (
              <motion.div
                className="scanner-error"
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
              >
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                  <circle cx="10" cy="10" r="8" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M10 6V10M10 14V14.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                </svg>
                {error}
              </motion.div>
            )}
          </AnimatePresence>

          <AnimatePresence>
            {result && (
              <motion.div
                className="scanner-result"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
              >
                {/* Result Header */}
                <div className="result-header">
                  <div className="result-score-container">
                    <div
                      className="result-score"
                      style={{ color: getRiskColor(result.data.score) }}
                    >
                      {result.data.score}
                    </div>
                    <div className="result-score-label">Risk Score</div>
                  </div>
                  <div className="result-verdict-container">
                    <div
                      className="result-verdict"
                      style={{ background: getRiskColor(result.data.score) }}
                    >
                      {result.type === 'website'
                        ? result.data.verdict
                        : getRiskLevel(result.data.score)}
                    </div>
                    {result.type === 'address' && (
                      <div className="result-prediction">
                        ML Prediction: <strong>{result.data.prediction}</strong>
                      </div>
                    )}
                  </div>
                </div>

                {/* Quick Links */}
                {result.type === 'address' && (
                  <div className="result-links">
                    <a
                      href={getEtherscanLink(addressInput)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="result-link"
                    >
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M6 2H3C2.44772 2 2 2.44772 2 3V13C2 13.5523 2.44772 14 3 14H13C13.5523 14 14 13.5523 14 13V10M10 2H14M14 2V6M14 2L7 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                      View on Etherscan
                    </a>
                    <a
                      href={getGoPlusLink(addressInput)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="result-link"
                    >
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M6 2H3C2.44772 2 2 2.44772 2 3V13C2 13.5523 2.44772 14 3 14H13C13.5523 14 14 13.5523 14 13V10M10 2H14M14 2V6M14 2L7 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                      View on GoPlus
                    </a>
                  </div>
                )}

                {/* Automatic Honeypot Simulation Status */}
                {result.type === 'address' && simulationLoading && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    style={{
                      marginTop: '24px',
                      padding: '16px',
                      background: 'rgba(102, 126, 234, 0.1)',
                      borderRadius: '12px',
                      border: '2px solid rgba(102, 126, 234, 0.3)',
                      textAlign: 'center',
                      color: '#667eea'
                    }}
                  >
                    <div style={{ fontSize: '16px', fontWeight: '600', marginBottom: '8px' }}>
                      🔬 Running Live Transaction Test...
                    </div>
                    <div style={{ fontSize: '14px', opacity: 0.8 }}>
                      Simulating buy/sell transactions on forked Ethereum network (5-10 seconds)
                    </div>
                  </motion.div>
                )}

                {/* CRITICAL: Honeypot Detected by Simulation */}
                {result.type === 'address' && simulationResult && !simulationResult.error && simulationResult.is_honeypot && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    style={{
                      marginTop: '24px',
                      padding: '24px',
                      background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.15) 100%)',
                      borderRadius: '16px',
                      border: '3px solid #ef4444',
                      boxShadow: '0 8px 32px rgba(239, 68, 68, 0.3)'
                    }}
                  >
                    <div style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '16px',
                      marginBottom: '16px'
                    }}>
                      <div style={{ fontSize: '48px', lineHeight: '1' }}>🚨</div>
                      <div style={{ flex: 1 }}>
                        <div style={{
                          fontSize: '24px',
                          fontWeight: '700',
                          color: '#ef4444',
                          marginBottom: '8px'
                        }}>
                          HONEYPOT CONFIRMED BY LIVE TEST
                        </div>
                        <div style={{
                          fontSize: '16px',
                          lineHeight: '1.6',
                          marginBottom: '12px'
                        }}>
                          <strong>⚠️ DO NOT BUY THIS TOKEN!</strong> Our simulator executed real buy/sell transactions on a forked Ethereum network 
                          and confirmed that <strong>you CANNOT sell this token after purchase</strong>. Your funds will be trapped forever.
                        </div>
                        <div style={{
                          display: 'inline-block',
                          padding: '8px 16px',
                          borderRadius: '8px',
                          background: '#ef4444',
                          color: 'white',
                          fontSize: '14px',
                          fontWeight: '600'
                        }}>
                          {simulationResult.confidence}% Confidence - Proven by Transaction Test
                        </div>
                      </div>
                    </div>

                    {/* Test Results */}
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr',
                      gap: '12px',
                      marginBottom: '16px',
                      padding: '16px',
                      background: 'rgba(0, 0, 0, 0.3)',
                      borderRadius: '12px'
                    }}>
                      <div>
                        <div style={{ fontSize: '14px', opacity: 0.8, marginBottom: '4px' }}>Buy Test:</div>
                        <div style={{ fontSize: '16px', fontWeight: '600' }}>
                          {simulationResult.buy_test?.success ? '✅ Succeeded' : '❌ Failed'}
                        </div>
                        {simulationResult.buy_test?.tokens_received && (
                          <div style={{ fontSize: '13px', opacity: 0.7, marginTop: '4px' }}>
                            Got {parseFloat(simulationResult.buy_test.tokens_received).toFixed(4)} tokens
                          </div>
                        )}
                      </div>
                      <div>
                        <div style={{ fontSize: '14px', opacity: 0.8, marginBottom: '4px' }}>Sell Test:</div>
                        <div style={{ fontSize: '16px', fontWeight: '600', color: '#ef4444' }}>
                          ❌ BLOCKED - Transaction Reverted
                        </div>
                        <div style={{ fontSize: '13px', opacity: 0.7, marginTop: '4px' }}>
                          Cannot sell tokens back to ETH
                        </div>
                      </div>
                    </div>

                    {/* Malicious Code Details */}
                    {simulationResult.malicious_code && simulationResult.malicious_code.length > 0 && (
                      <div style={{
                        padding: '16px',
                        background: 'rgba(0, 0, 0, 0.4)',
                        borderRadius: '12px'
                      }}>
                        <div style={{
                          fontSize: '16px',
                          fontWeight: '700',
                          marginBottom: '12px',
                          color: '#fbbf24'
                        }}>
                          📝 Malicious Code Found:
                        </div>
                        {simulationResult.malicious_code.slice(0, 3).map((finding, idx) => (
                          <div
                            key={idx}
                            style={{
                              padding: '12px',
                              background: 'rgba(0, 0, 0, 0.3)',
                              borderRadius: '8px',
                              marginBottom: idx < Math.min(2, simulationResult.malicious_code.length - 1) ? '8px' : '0',
                              borderLeft: '4px solid #ef4444'
                            }}
                          >
                            <div style={{
                              display: 'flex',
                              gap: '8px',
                              marginBottom: '6px',
                              flexWrap: 'wrap'
                            }}>
                              <span style={{
                                padding: '4px 8px',
                                borderRadius: '4px',
                                background: '#ef4444',
                                fontSize: '11px',
                                fontWeight: '600'
                              }}>
                                {finding.severity}
                              </span>
                              <span style={{
                                padding: '4px 8px',
                                borderRadius: '4px',
                                background: 'rgba(255, 255, 255, 0.1)',
                                fontSize: '11px'
                              }}>
                                Line {finding.line_number}
                              </span>
                              <span style={{
                                padding: '4px 8px',
                                borderRadius: '4px',
                                background: 'rgba(251, 191, 36, 0.2)',
                                color: '#fbbf24',
                                fontSize: '11px',
                                fontWeight: '600'
                              }}>
                                {finding.confidence} Confidence
                              </span>
                            </div>
                            <div style={{ fontSize: '13px', marginBottom: '8px', lineHeight: '1.5' }}>
                              {finding.description}
                            </div>
                            <pre style={{
                              background: 'rgba(0, 0, 0, 0.5)',
                              padding: '8px',
                              borderRadius: '6px',
                              overflow: 'auto',
                              fontSize: '12px',
                              lineHeight: '1.4',
                              margin: 0
                            }}>
                              <code>{finding.code_snippet}</code>
                            </pre>
                          </div>
                        ))}
                        {simulationResult.malicious_code.length > 3 && (
                          <div style={{ fontSize: '13px', opacity: 0.7, marginTop: '8px', textAlign: 'center' }}>
                            +{simulationResult.malicious_code.length - 3} more issues found
                          </div>
                        )}
                      </div>
                    )}

                    {/* Source Not Verified Message */}
                    {simulationResult.is_honeypot && (!simulationResult.malicious_code || simulationResult.malicious_code.length === 0) && (
                      <div style={{
                        padding: '12px',
                        background: 'rgba(245, 158, 11, 0.2)',
                        borderRadius: '8px',
                        fontSize: '13px',
                        borderLeft: '4px solid #f59e0b'
                      }}>
                        ⚠️ Contract source code not verified on Etherscan. Cannot show exact malicious lines, 
                        but the <strong>sell transaction failure is 99% proof</strong> of honeypot behavior.
                      </div>
                    )}

                    <div style={{
                      marginTop: '16px',
                      padding: '12px',
                      background: 'rgba(102, 126, 234, 0.2)',
                      borderRadius: '8px',
                      fontSize: '12px',
                      textAlign: 'center',
                      color: '#a5b4fc'
                    }}>
                      🔬 Detection Method: Runtime Transaction Simulation on Forked Ethereum Network
                    </div>
                  </motion.div>
                )}

                {/* SAFE: No Honeypot Detected */}
                {result.type === 'address' && simulationResult && !simulationResult.error && !simulationResult.is_honeypot && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    style={{
                      marginTop: '24px',
                      padding: '20px',
                      background: simulationResult.warning 
                        ? 'linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(251, 191, 36, 0.1) 100%)'
                        : 'linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(22, 163, 74, 0.1) 100%)',
                      borderRadius: '12px',
                      border: `2px solid ${simulationResult.warning ? '#f59e0b' : '#22c55e'}`
                    }}
                  >
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      marginBottom: '12px'
                    }}>
                      <span style={{ fontSize: '32px' }}>{simulationResult.warning ? '⚠️' : '✅'}</span>
                      <div>
                        <div style={{
                          fontSize: '20px',
                          fontWeight: '700',
                          color: simulationResult.warning ? '#f59e0b' : '#22c55e'
                        }}>
                          {simulationResult.pattern === 'WHITELISTED'
                            ? '✓ Verified Legitimate Token'
                            : simulationResult.pattern === 'NOT_A_TOKEN' 
                              ? 'Not a Tradeable Token'
                              : simulationResult.pattern === 'NO_LIQUIDITY'
                                ? '💧 No Uniswap Liquidity'
                              : simulationResult.pattern === 'TRADING_PAUSED'
                                ? '⏸️ Trading Paused/Frozen'
                              : simulationResult.warning 
                                ? 'Trading Restrictions Detected' 
                                : 'No Honeypot Detected'}
                        </div>
                        <div style={{ fontSize: '14px', opacity: 0.9, marginTop: '4px' }}>
                          {simulationResult.pattern === 'WHITELISTED'
                            ? 'This token is verified as legitimate on CoinGecko or major exchanges. Simulation skipped.'
                            : simulationResult.pattern === 'NOT_A_TOKEN'
                              ? `This contract does not implement standard ERC20 functions. ${simulationResult.contract_type === 'SYSTEM_CONTRACT' ? 'It appears to be a system contract, DeFi protocol, or multisig wallet.' : 'Cannot perform trading simulation.'}`
                              : simulationResult.pattern === 'NO_LIQUIDITY'
                                ? `No liquidity pool found on ${simulationResult.tried_dexes?.join(', ') || 'Uniswap V2, Sushiswap, Uniswap V3'}. This token may trade on other DEXes (Pancakeswap, 1inch, Curve) or have no active trading pairs. Check DexTools or DexScreener for liquidity on other exchanges.`
                              : simulationResult.pattern === 'TRADING_PAUSED'
                                ? 'This token has valid ERC20 interface but trading appears paused/frozen or lacks liquidity. This may be temporary or intentional by the contract owner.'
                              : simulationResult.warning 
                                ? simulationResult.warning
                                : `Live transaction test confirmed both buy and sell operations work correctly (${simulationResult.confidence}% confidence)`
                          }
                        </div>
                      </div>
                    </div>
                    {!simulationResult.warning && !simulationResult.whitelisted && simulationResult.buy_test && simulationResult.sell_test && (
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: '1fr 1fr',
                        gap: '12px',
                        padding: '12px',
                        background: 'rgba(0, 0, 0, 0.2)',
                        borderRadius: '8px'
                      }}>
                        <div style={{ fontSize: '13px' }}>
                          <strong>Buy Test:</strong> ✅ {simulationResult.buy_test?.note || (simulationResult.buy_test?.tokens_received && `Got ${parseFloat(simulationResult.buy_test.tokens_received).toFixed(4)} tokens`)}
                        </div>
                        <div style={{ fontSize: '13px' }}>
                          <strong>Sell Test:</strong> ✅ {simulationResult.sell_test?.note || (simulationResult.sell_test?.eth_received && `Got ${(parseFloat(simulationResult.sell_test.eth_received) / 1e18).toFixed(6)} ETH`)}
                        </div>
                      </div>
                    )}
                    {simulationResult.whitelisted && (
                      <div style={{
                        marginTop: '12px',
                        padding: '12px',
                        background: 'rgba(34, 197, 94, 0.2)',
                        borderRadius: '8px',
                        fontSize: '13px',
                        border: '1px solid rgba(34, 197, 94, 0.3)'
                      }}>
                        <strong>✓ Whitelisted Token</strong>
                        <div style={{ marginTop: '8px', opacity: 0.9 }}>
                          This token has been manually verified as legitimate through:
                          <ul style={{ marginTop: '8px', marginBottom: 0, paddingLeft: '20px' }}>
                            <li>CoinGecko listing with verified contract address</li>
                            <li>Trading volume on major decentralized exchanges (Uniswap, etc.)</li>
                            <li>Community verification and holder count</li>
                          </ul>
                          <div style={{ marginTop: '8px', fontSize: '12px', opacity: 0.7 }}>
                            Honeypot simulation was skipped for this verified token.
                          </div>
                        </div>
                      </div>
                    )}
                    {simulationResult.warning && (
                      <div style={{
                        marginTop: '12px',
                        padding: '12px',
                        background: 'rgba(0, 0, 0, 0.2)',
                        borderRadius: '8px',
                        fontSize: '13px'
                      }}>
                        {simulationResult.pattern === 'NOT_A_TOKEN' ? (
                          <>
                            <strong>Note:</strong> This address is not a standard ERC20 token. Possible types:
                            <ul style={{ marginTop: '8px', marginBottom: 0, paddingLeft: '20px' }}>
                              <li>System contract (e.g., ETH2 Deposit Contract: 0x00000000219ab540356cBB839Cbe05303d7705Fa)</li>
                              <li>Multisig wallet (Gnosis Safe, etc.)</li>
                              <li>DeFi protocol contract (lending, AMM, vault)</li>
                              <li>NFT contract (ERC721/ERC1155)</li>
                              <li>Governance contract or DAO treasury</li>
                            </ul>
                            {simulationResult.missing_functions && simulationResult.missing_functions.length > 0 && (
                              <div style={{ marginTop: '8px', fontSize: '12px', opacity: 0.8 }}>
                                Missing ERC20 functions: {simulationResult.missing_functions.join(', ')}
                              </div>
                            )}
                          </>
                        ) : (
                          <>
                            <strong>Note:</strong> {simulationResult.warning}
                          </>
                        )}
                      </div>
                    )}
                  </motion.div>
                )}

                {/* Simulation Error */}
                {result.type === 'address' && simulationResult?.error && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    style={{
                      marginTop: '24px',
                      padding: '16px',
                      background: 'rgba(245, 158, 11, 0.1)',
                      borderRadius: '12px',
                      border: '2px solid rgba(245, 158, 11, 0.3)'
                    }}
                  >
                    <div style={{
                      fontSize: '14px',
                      fontWeight: '600',
                      marginBottom: '8px',
                      color: '#f59e0b'
                    }}>
                      ⚠️ Live Simulation Unavailable
                    </div>
                    <div style={{ fontSize: '13px', marginBottom: '12px', opacity: 0.9 }}>
                      {(() => {
                        const error = simulationResult.error;
                        
                        // Provide user-friendly explanations
                        if (error.includes('not implement standard ERC20')) {
                          return (
                            <>
                              <strong>Non-Standard Token:</strong> This token doesn't follow the standard ERC20 interface. 
                              This is highly suspicious and common in scam tokens. <strong style={{ color: '#ef4444' }}>⚠️ AVOID THIS TOKEN</strong>
                            </>
                          );
                        } else if (error.includes('not deployed') || error.includes('no bytecode')) {
                          return (
                            <>
                              <strong>Invalid Contract:</strong> No contract code found at this address. 
                              This may be a regular wallet address, not a token contract.
                            </>
                          );
                        } else if (error.includes('not accessible') || error.includes('not synced')) {
                          return (
                            <>
                              <strong>Network Issue:</strong> Cannot connect to the contract. 
                              The blockchain fork may need resync. Try again or check if Ganache is running properly.
                            </>
                          );
                        } else if (error.includes('Ganache not running')) {
                          return error;
                        } else {
                          return error;
                        }
                      })()}
                    </div>
                    {simulationResult.setup_required && simulationResult.instructions && (
                      <details style={{ fontSize: '13px', marginTop: '12px' }}>
                        <summary style={{ cursor: 'pointer', fontWeight: '600' }}>Setup Instructions</summary>
                        <ul style={{ margin: '8px 0 0 0', paddingLeft: '20px', lineHeight: '1.8' }}>
                          {simulationResult.instructions.map((step, idx) => (
                            <li key={idx}>{step}</li>
                          ))}
                        </ul>
                      </details>
                    )}
                  </motion.div>
                )}

                {/* Contract Source Code Analysis - REAL Solidity Code */}
                {result.type === 'address' && result.data.contract_analysis && result.data.contract_analysis.has_source && (
                  <div className="result-section">
                    <div className="section-header">
                      <h3 className="section-title">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                          <path d="M6 3L3 10L6 17M14 3L17 10L14 17M12 2L8 18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                        Smart Contract Source Analysis
                        {result.data.contract_analysis.risk_level && (
                          <span className={`code-risk-badge ${result.data.contract_analysis.risk_level.toLowerCase()}`}>
                            {result.data.contract_analysis.risk_level}
                          </span>
                        )}
                      </h3>
                      <p className="section-subtitle">
                        Analyzed verified contract: <code>{result.data.contract_analysis.contract_name}</code>
                      </p>
                    </div>

                    {result.data.contract_analysis.findings && result.data.contract_analysis.findings.length > 0 ? (
                      <>
                        {/* Summary Stats */}
                        <div className="code-analysis-summary">
                          <div className="code-stat critical">
                            <span className="stat-value">{result.data.contract_analysis.summary.critical || 0}</span>
                            <span className="stat-label">Critical</span>
                          </div>
                          <div className="code-stat high">
                            <span className="stat-value">{result.data.contract_analysis.summary.high || 0}</span>
                            <span className="stat-label">High</span>
                          </div>
                          <div className="code-stat medium">
                            <span className="stat-value">{result.data.contract_analysis.summary.medium || 0}</span>
                            <span className="stat-label">Medium</span>
                          </div>
                        </div>

                        {/* Actual Solidity Code Findings */}
                        <div className="detected-code-list">
                          {result.data.contract_analysis.findings.slice(0, 15).map((finding, idx) => {
                            const isExpanded = expandedSection === `contract-finding-${idx}`
                            return (
                              <motion.div
                                key={idx}
                                className={`code-finding-item ${finding.severity}`}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: idx * 0.05 }}
                              >
                                <div
                                  className="code-finding-header"
                                  onClick={() => setExpandedSection(isExpanded ? null : `contract-finding-${idx}`)}
                                >
                                  <div className="code-finding-info">
                                    <span className={`severity-badge ${finding.severity}`}>
                                      {finding.severity.toUpperCase()}
                                    </span>
                                    <span className="finding-category">{finding.category}</span>
                                    {finding.confidence && (
                                      <span 
                                        className="finding-confidence"
                                        style={{
                                          marginLeft: '8px',
                                          padding: '4px 8px',
                                          borderRadius: '6px',
                                          fontSize: '11px',
                                          fontWeight: '600',
                                          background: finding.confidence >= 80 ? 'rgba(239, 68, 68, 0.1)' : 
                                                     finding.confidence >= 60 ? 'rgba(249, 115, 22, 0.1)' : 
                                                     'rgba(234, 179, 8, 0.1)',
                                          color: finding.confidence >= 80 ? '#ef4444' : 
                                                 finding.confidence >= 60 ? '#f97316' : 
                                                 '#eab308',
                                          border: `1px solid ${finding.confidence >= 80 ? '#ef444433' : 
                                                               finding.confidence >= 60 ? '#f9731633' : 
                                                               '#eab30833'}`
                                        }}
                                      >
                                        {finding.confidence}% confidence
                                      </span>
                                    )}
                                    <span className="finding-line">Line {finding.line_number}</span>
                                  </div>
                                  <svg
                                    className={`expand-arrow ${isExpanded ? 'expanded' : ''}`}
                                    width="20"
                                    height="20"
                                    viewBox="0 0 20 20"
                                    fill="none"
                                  >
                                    <path d="M6 8L10 12L14 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                                  </svg>
                                </div>

                                <AnimatePresence>
                                  {isExpanded && (
                                    <motion.div
                                      className="code-finding-details"
                                      initial={{ height: 0, opacity: 0 }}
                                      animate={{ height: 'auto', opacity: 1 }}
                                      exit={{ height: 0, opacity: 0 }}
                                      transition={{ duration: 0.2 }}
                                    >
                                      <div className="finding-description">
                                        <strong>⚠️ What this means:</strong>
                                        <p>{finding.description}</p>
                                      </div>

                                      {/* The actual Solidity code from the contract */}
                                      <div className="detected-code-block">
                                        <div className="code-block-header">
                                          <span>🔍 Actual Contract Code (Line {finding.line_number})</span>
                                          <button
                                            className="copy-code-btn"
                                            onClick={(e) => {
                                              e.stopPropagation()
                                              navigator.clipboard.writeText(finding.code_snippet || finding.context || finding.matched_code)
                                            }}
                                          >
                                            Copy
                                          </button>
                                        </div>
                                        <pre className="actual-code solidity-code">
                                          <code>{finding.code_snippet || finding.context || finding.matched_code}</code>
                                        </pre>
                                        {finding.matched_code && finding.matched_code !== finding.context && (
                                          <div className="matched-highlight">
                                            <strong>Matched Pattern:</strong>
                                            <code className="matched-code">{finding.matched_code}</code>
                                          </div>
                                        )}
                                      </div>

                                      <div className="finding-recommendation">
                                        <strong>🛡️ Risk Assessment:</strong>
                                        <p>
                                          {finding.severity === 'critical' 
                                            ? 'CRITICAL: This pattern is almost always malicious. Do NOT interact with this contract.'
                                            : finding.severity === 'high'
                                            ? 'HIGH RISK: This pattern is commonly used in scam contracts. Extreme caution required.'
                                            : 'MEDIUM RISK: This pattern can be legitimate but is often abused. Verify the project thoroughly.'}
                                        </p>
                                      </div>
                                    </motion.div>
                                  )}
                                </AnimatePresence>
                              </motion.div>
                            )
                          })}
                        </div>

                        {result.data.contract_analysis.findings.length > 15 && (
                          <p className="more-findings">
                            +{result.data.contract_analysis.findings.length - 15} more findings in contract code...
                          </p>
                        )}
                      </>
                    ) : (
                      <div className="code-analysis-clean">
                        <span className="clean-icon">✅</span>
                        <p>No suspicious patterns detected in contract source code.</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Risk Flags with Explanations (GoPlus Labels) */}
                {result.type === 'address' && result.data.goplus_flags && result.data.goplus_flags.length > 0 && (
                  <div className="result-section">
                    <div className="section-header">
                      <h3 className="section-title">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                          <path d="M10 2L2 18H18L10 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
                          <path d="M10 8V11M10 14V14.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                        </svg>
                         Risk Flags ({result.data.goplus_flags.length})
                      </h3>
                    </div>
                    <div className="risk-flags-list">
                      {result.data.goplus_flags.map((flag, i) => {
                        const explanation = getRiskExplanation(flag)
                        const isExpanded = expandedSection === `flag-${i}`
                        return (
                          <motion.div
                            key={i}
                            className={`risk-flag-item ${explanation.severity}`}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: i * 0.05 }}
                          >
                            <div
                              className="risk-flag-header"
                              onClick={() => setExpandedSection(isExpanded ? null : `flag-${i}`)}
                            >
                              <div className="risk-flag-info">
                                <span
                                  className="risk-flag-severity"
                                  style={{ background: getSeverityColor(explanation.severity) }}
                                >
                                  {explanation.severity.toUpperCase()}
                                </span>
                                <span className="risk-flag-name">{flag}</span>
                              </div>
                              <svg
                                className={`risk-flag-arrow ${isExpanded ? 'expanded' : ''}`}
                                width="20"
                                height="20"
                                viewBox="0 0 20 20"
                                fill="none"
                              >
                                <path d="M6 8L10 12L14 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                              </svg>
                            </div>
                            <AnimatePresence>
                              {isExpanded && (
                                <motion.div
                                  className="risk-flag-details"
                                  initial={{ height: 0, opacity: 0 }}
                                  animate={{ height: 'auto', opacity: 1 }}
                                  exit={{ height: 0, opacity: 0 }}
                                  transition={{ duration: 0.2 }}
                                >
                                  <div className="risk-flag-description">
                                    <strong>What this means:</strong>
                                    <p>{explanation.description}</p>
                                  </div>
                                  
                                  {/* Technical Details Section */}
                                  {explanation.technicalDetails && (
                                    <div className="risk-flag-technical">
                                      <div className="technical-header">
                                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                                          <path d="M5 3L2 8L5 13M11 3L14 8L11 13M9 2L7 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                                        </svg>
                                        <strong>Technical Pattern: {explanation.technicalDetails.pattern}</strong>
                                      </div>
                                      
                                      {/* Show warning text OR code block */}
                                      {explanation.technicalDetails.warning ? (
                                        <div className="warning-block">
                                          <pre style={{ 
                                            whiteSpace: 'pre-wrap', 
                                            background: 'rgba(239, 68, 68, 0.1)', 
                                            border: '1px solid rgba(239, 68, 68, 0.3)',
                                            borderRadius: '8px',
                                            padding: '1rem',
                                            fontSize: '0.85rem',
                                            lineHeight: '1.6',
                                            color: '#f1f5f9'
                                          }}>
                                            {explanation.technicalDetails.warning}
                                          </pre>
                                        </div>
                                      ) : explanation.technicalDetails.code ? (
                                        <div className="code-block">
                                          <div className="code-header">
                                            <span>Solidity Pattern</span>
                                            <button 
                                              className="copy-btn"
                                              onClick={(e) => {
                                                e.stopPropagation()
                                                navigator.clipboard.writeText(explanation.technicalDetails.code)
                                              }}
                                            >
                                              Copy
                                            </button>
                                          </div>
                                          <pre><code>{explanation.technicalDetails.code}</code></pre>
                                        </div>
                                      ) : null}
                                      
                                      <div className="technical-indicators">
                                        <strong>Detection Indicators:</strong>
                                        <ul>
                                          {explanation.technicalDetails.indicators.map((indicator, idx) => (
                                            <li key={idx}>
                                              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                                                <path d="M2 6L5 9L10 3" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                                              </svg>
                                              {indicator}
                                            </li>
                                          ))}
                                        </ul>
                                      </div>
                                      
                                      {explanation.technicalDetails.variables && (
                                        <div className="technical-variables">
                                          <strong>Key Variables to Check:</strong>
                                          <div className="variable-tags">
                                            {explanation.technicalDetails.variables.map((variable, idx) => (
                                              <code key={idx} className="variable-tag">{variable}</code>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                  
                                  <div className="risk-flag-recommendation">
                                    <strong>Recommendation:</strong>
                                    <p>{explanation.recommendation}</p>
                                  </div>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </motion.div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* Website Results */}
                {result.type === 'website' && (
                  <>
                    {/* Run analysis to get detailed explanations */}
                    {(() => {
                      const analysis = analyzeWebsiteRisks(result.data)
                      return (
                        <>
                          {result.data.is_verified_dapp && (
                            <motion.div
                              className="result-alert success"
                              initial={{ opacity: 0, x: -20 }}
                              animate={{ opacity: 1, x: 0 }}
                            >
                              <div className="alert-icon">✅</div>
                              <div className="alert-content">
                                <div className="alert-title">Verified dApp</div>
                                <div className="alert-description">
                                  This dApp is on the GoPlus trusted list, indicating it has been verified as legitimate.
                                </div>
                              </div>
                            </motion.div>
                          )}

                          {result.data.is_audited && (
                            <motion.div
                              className="result-alert success"
                              initial={{ opacity: 0, x: -20 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: 0.1 }}
                            >
                              <div className="alert-icon">🔒</div>
                              <div className="alert-content">
                                <div className="alert-title">Audited Smart Contracts</div>
                                <div className="alert-description">
                                  This project's smart contracts have been audited by security firms, reducing the risk of vulnerabilities.
                                </div>
                              </div>
                            </motion.div>
                          )}

                          {/* dApp Runtime Simulation - Moved before ML Analysis */}
                          {result.type === 'website' && (
                            <motion.div
                              className="result-section"
                              initial={{ opacity: 0, y: 20 }}
                              animate={{ opacity: 1, y: 0 }}
                              transition={{ delay: 0.1 }}
                            >
                              <div className="section-header">
                                <h3 className="section-title">
                                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                                    <path d="M10 2L2 6L10 10L18 6L10 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                                    <path d="M2 14L10 18L18 14" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                                  </svg>
                                  Runtime dApp Simulation
                                </h3>
                              </div>

                              {dappSimulationLoading ? (
                                <motion.div
                                  initial={{ opacity: 0 }}
                                  animate={{ opacity: 1 }}
                                  style={{
                                    padding: '20px',
                                    background: 'rgba(102, 126, 234, 0.1)',
                                    borderRadius: '12px',
                                    border: '2px solid rgba(102, 126, 234, 0.3)',
                                    textAlign: 'center',
                                    color: '#667eea'
                                  }}
                                >
                                  <div style={{ fontSize: '16px', fontWeight: '600', marginBottom: '8px' }}>
                                    🔬 Running Live Browser Simulation...
                                  </div>
                                  <div style={{ fontSize: '14px', opacity: 0.8 }}>
                                    Testing domain patterns, loading page with mock wallet, monitoring transactions (10-30 seconds)
                                  </div>
                                </motion.div>
                              ) : dappSimulationResult?.error ? (
                                <div style={{
                                  padding: '16px',
                                  background: 'rgba(239, 68, 68, 0.1)',
                                  borderRadius: '12px',
                                  border: '2px solid rgba(239, 68, 68, 0.3)',
                                  color: '#ef4444'
                                }}>
                                  <p>⚠️ Simulation error: {dappSimulationResult.error}</p>
                                </div>
                              ) : dappSimulationResult ? (
                                <>
                                  {/* MALICIOUS dApp Detected */}
                                  {dappSimulationResult.is_malicious && (
                                    <motion.div
                                      initial={{ opacity: 0, scale: 0.95 }}
                                      animate={{ opacity: 1, scale: 1 }}
                                      style={{
                                        padding: '24px',
                                        background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.15) 100%)',
                                        borderRadius: '16px',
                                        border: '3px solid #ef4444',
                                        boxShadow: '0 8px 32px rgba(239, 68, 68, 0.3)'
                                      }}
                                    >
                                      <div style={{
                                        display: 'flex',
                                        alignItems: 'flex-start',
                                        gap: '16px',
                                        marginBottom: '16px'
                                      }}>
                                        <div style={{ fontSize: '48px', lineHeight: '1' }}>🚨</div>
                                        <div style={{ flex: 1 }}>
                                          <div style={{
                                            fontSize: '24px',
                                            fontWeight: '700',
                                            color: '#ef4444',
                                            marginBottom: '8px'
                                          }}>
                                            MALICIOUS dApp DETECTED
                                          </div>
                                          <div style={{
                                            fontSize: '16px',
                                            lineHeight: '1.6',
                                            marginBottom: '12px'
                                          }}>
                                            <strong>⚠️ DO NOT CONNECT YOUR WALLET!</strong> Our runtime simulator loaded this site in a real browser with a mock wallet 
                                            and detected <strong>{(dappSimulationResult.risk_factors || dappSimulationResult.threats || []).length} malicious behavior(s)</strong>.
                                          </div>
                                          <div style={{
                                            display: 'inline-block',
                                            padding: '8px 16px',
                                            borderRadius: '8px',
                                            background: '#ef4444',
                                            color: 'white',
                                            fontSize: '14px',
                                            fontWeight: '600'
                                          }}>
                                            {dappSimulationResult.confidence}% Confidence - Proven by Browser Test
                                          </div>
                                        </div>
                                      </div>

                                      {/* Threats moved to Risk Factors section below */}

                                      <div style={{
                                        marginTop: '16px',
                                        padding: '12px',
                                        background: 'rgba(102, 126, 234, 0.2)',
                                        borderRadius: '8px',
                                        fontSize: '12px',
                                        textAlign: 'center',
                                        color: '#a5b4fc'
                                      }}>
                                        🔬 Detection Method: Runtime Browser Simulation with Mock Wallet Injection
                                      </div>
                                    </motion.div>
                                  )}

                                  {/* SAFE dApp */}
                                  {!dappSimulationResult.is_malicious && (
                                    <motion.div
                                      initial={{ opacity: 0, scale: 0.95 }}
                                      animate={{ opacity: 1, scale: 1 }}
                                      style={{
                                        padding: '20px',
                                        background: 'linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(22, 163, 74, 0.1) 100%)',
                                        borderRadius: '12px',
                                        border: '2px solid #22c55e'
                                      }}
                                    >
                                      <div style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px',
                                        marginBottom: '12px'
                                      }}>
                                        <span style={{ fontSize: '32px' }}>✅</span>
                                        <div>
                                          <div style={{
                                            fontSize: '20px',
                                            fontWeight: '700',
                                            color: '#22c55e'
                                          }}>
                                            No Malicious Behavior Detected
                                          </div>
                                          <div style={{ fontSize: '14px', opacity: 0.9, marginTop: '4px' }}>
                                            Runtime simulation found no malicious patterns ({dappSimulationResult.confidence}% confidence)
                                          </div>
                                        </div>
                                      </div>
                                      {dappSimulationResult.threats && dappSimulationResult.threats.length > 0 && (
                                        <div style={{
                                          padding: '12px',
                                          background: 'rgba(0, 0, 0, 0.2)',
                                          borderRadius: '8px',
                                          fontSize: '13px'
                                        }}>
                                          <strong>Minor observations:</strong> {dappSimulationResult.threats.length} low-priority findings (not malicious)
                                        </div>
                                      )}
                                    </motion.div>
                                  )}
                                </>
                              ) : (
                                <div style={{
                                  padding: '16px',
                                  background: 'rgba(255, 255, 255, 0.05)',
                                  borderRadius: '12px',
                                  textAlign: 'center',
                                  opacity: 0.6
                                }}>
                                  Waiting for simulation to complete...
                                </div>
                              )}
                            </motion.div>
                          )}

                          {/* ML Model Prediction with Score Breakdown */}
                          {result.data.ml_prediction && (
                            <div className="result-section">
                              <div className="section-header">
                                <h3 className="section-title">
                                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                                    <path d="M10 2L2 6L10 10L18 6L10 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                                    <path d="M2 14L10 18L18 14" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                                    <path d="M2 10L10 14L18 10" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                                  </svg>
                                  ML Model Analysis
                                </h3>
                              </div>
                              
                              {/* Compact ML Score Row */}
                              <div className="ml-compact-row">
                                <div className="ml-score-compact">
                                  <span className="score-label">Risk Score</span>
                                  <span className="score-value" style={{ color: getRiskColor(result.data.ml_prediction.score) }}>
                                    {result.data.ml_prediction.score}
                                  </span>
                                </div>
                                <div className="ml-bar-compact">
                                  <motion.div
                                    className="bar-fill"
                                    style={{ background: getRiskColor(result.data.ml_prediction.score) }}
                                    initial={{ width: 0 }}
                                    animate={{ width: `${result.data.ml_prediction.score}%` }}
                                    transition={{ duration: 0.5 }}
                                  />
                                </div>
                                <div className={`ml-verdict-compact ${result.data.ml_prediction.is_phishing ? 'dangerous' : 'safe'}`}>
                                  {result.data.ml_prediction.is_phishing ? '🚨 Phishing' : '✓ Safe'}
                                </div>
                                <div className="ml-confidence-compact">
                                  {(result.data.ml_prediction.confidence * 100).toFixed(0)}% conf.
                                </div>
                              </div>
                              
                              {/* ML Analysis Explanation */}
                              {result.data.ml_prediction.analysis && (
                                <>
                                  {/* Summary + Recommendation in one line */}
                                  <div className={`recommendation-box compact ${result.data.ml_prediction.is_phishing ? 'warning' : 'info'}`}>
                                    <span className="rec-summary">{result.data.ml_prediction.analysis.summary}</span>
                                    {result.data.ml_prediction.analysis.recommendation && (
                                      <span className="rec-action">→ {result.data.ml_prediction.analysis.recommendation}</span>
                                    )}
                                  </div>

                                  {/* Combined Risk Factors - sorted by severity */}
                                  {(() => {
                                    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
                                    const mlFactors = (result.data.ml_prediction.analysis.risk_factors || []).map(f => ({
                                      ...f,
                                      type: 'ml',
                                      severity: f.importance
                                    }))
                                    
                                    // Add dApp simulation threats to risk factors
                                    const dappThreats = (dappSimulationResult?.risk_factors || dappSimulationResult?.threats || []).map(t => ({
                                      factor: t.type,
                                      description: t.description,
                                      severity: t.severity?.toLowerCase() || 'medium',
                                      value: t.evidence || 'Detected by runtime browser simulation',
                                      type: 'dapp_simulation',
                                      confidence: t.confidence
                                    }))
                                    
                                    const allFactors = [...mlFactors, ...dappThreats].sort((a, b) => 
                                      (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
                                    )
                                    
                                    if (allFactors.length === 0) return null
                                    
                                    return (
                                      <div className="ml-factors-section">
                                        <h4 className="factors-title">
                                          <span style={{ color: '#ef4444' }}>⚠️</span> Risk Factors ({allFactors.length})
                                          {dappThreats.length > 0 && (
                                            <span style={{ fontSize: '12px', opacity: 0.7, marginLeft: '8px' }}>({dappThreats.length} from browser simulation)</span>
                                          )}
                                        </h4>
                                        <div className="risk-flags-list">
                                          {allFactors.map((factor, i) => {
                                            const isExpanded = expandedSection === `ml-web-factor-${i}`
                                            return (
                                              <motion.div
                                                key={i}
                                                className={`risk-flag-item ${factor.severity}`}
                                                initial={{ opacity: 0, y: 10 }}
                                                animate={{ opacity: 1, y: 0 }}
                                                transition={{ delay: i * 0.05 }}
                                              >
                                                <div
                                                  className="risk-flag-header"
                                                  onClick={() => setExpandedSection(isExpanded ? null : `ml-web-factor-${i}`)}
                                                >
                                                  <div className="risk-flag-info">
                                                    <span
                                                      className="risk-flag-severity"
                                                      style={{ background: getSeverityColor(factor.severity) }}
                                                    >
                                                      {factor.severity.toUpperCase()}
                                                    </span>
                                                    <span className="risk-flag-name">{factor.factor}</span>
                                                  </div>
                                                  <svg
                                                    className={`risk-flag-arrow ${isExpanded ? 'expanded' : ''}`}
                                                    width="20"
                                                    height="20"
                                                    viewBox="0 0 20 20"
                                                    fill="none"
                                                  >
                                                    <path d="M6 8L10 12L14 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                                                  </svg>
                                                </div>
                                                <AnimatePresence>
                                                  {isExpanded && (
                                                    <motion.div
                                                      className="risk-flag-details"
                                                      initial={{ height: 0, opacity: 0 }}
                                                      animate={{ height: 'auto', opacity: 1 }}
                                                      exit={{ height: 0, opacity: 0 }}
                                                      transition={{ duration: 0.2 }}
                                                    >
                                                      <div className="risk-flag-description">
                                                        <strong>What this means:</strong>
                                                        <p>{factor.description}</p>
                                                      </div>
                                                      <div className="risk-flag-recommendation">
                                                        <strong>Detected:</strong>
                                                        <p><code>{factor.value}</code></p>
                                                      </div>
                                                    </motion.div>
                                                  )}
                                                </AnimatePresence>
                                              </motion.div>
                                            )
                                          })}
                                        </div>
                                      </div>
                                    )
                                  })()}

                                  {/* Safe Factors from ML - REMOVED */}

                                  {/* Technical Feature Analysis
                                  {result.data.ml_prediction.analysis.feature_analysis && (
                                    <div className="ml-behavioral-summary" style={{ marginTop: '16px' }}>
                                      <h4 className="factors-title">🔍 Technical Analysis</h4>
                                      <ul className="behavioral-list">
                                        {result.data.ml_prediction.analysis.feature_analysis.map((item, i) => (
                                          <li key={i}>{item}</li>
                                        ))}
                                      </ul>
                                    </div>
                                  )} */}
                                </>
                              )}
                            </div>
                          )}
 

                          {/* Source Code Analysis - Moved before dApp Simulation */}
                          {result.type === 'website' && (
                            <motion.div
                              className="result-section"
                              initial={{ opacity: 0, y: 20 }}
                              animate={{ opacity: 1, y: 0 }}
                              transition={{ delay: 0.2 }}
                            >
                              <div className="section-header">
                                <h3 className="section-title">
                                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                                    <path d="M6 3L3 10L6 17M14 3L17 10L14 17M12 2L8 18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                                  </svg>
                                  Source Code Analysis
                                  {codeAnalysis && codeAnalysis.summary && (
                                    <span className={`code-risk-badge ${codeAnalysis.risk_level?.toLowerCase()}`}>
                                      {codeAnalysis.risk_level}
                                    </span>
                                  )}
                                </h3>
                              </div>

                              {codeAnalysisLoading ? (
                                <div className="code-analysis-loading">
                                  <div className="loading-spinner"></div>
                                  <p>Analyzing website source code for malicious patterns...</p>
                                </div>
                              ) : codeAnalysis?.error ? (
                                <div className="code-analysis-error">
                                  <p>⚠️ Could not fetch source code: {codeAnalysis.error}</p>
                                </div>
                              ) : codeAnalysis?.findings?.length > 0 ? (
                                <>
                                  <div className="code-analysis-summary">
                                    <div className="code-stat critical">
                                      <span className="stat-value">{codeAnalysis.summary.critical || 0}</span>
                                      <span className="stat-label">Critical</span>
                                    </div>
                                    <div className="code-stat high">
                                      <span className="stat-value">{codeAnalysis.summary.high || 0}</span>
                                      <span className="stat-label">High</span>
                                    </div>
                                    <div className="code-stat medium">
                                      <span className="stat-value">{codeAnalysis.summary.medium || 0}</span>
                                      <span className="stat-label">Medium</span>
                                    </div>
                                    <div className="code-stat info">
                                      <span className="stat-value">{codeAnalysis.summary.info || 0}</span>
                                      <span className="stat-label">Info</span>
                                    </div>
                                  </div>
                                  <div className="detected-code-list">
                                    {codeAnalysis.findings.slice(0, 5).map((finding, idx) => {
                                      const isExpanded = expandedSection === `code-finding-${idx}`
                                      return (
                                        <motion.div
                                          key={idx}
                                          className={`code-finding-item ${finding.severity}`}
                                          initial={{ opacity: 0, y: 10 }}
                                          animate={{ opacity: 1, y: 0 }}
                                          transition={{ delay: idx * 0.05 }}
                                        >
                                          <div
                                            className="code-finding-header"
                                            onClick={() => setExpandedSection(isExpanded ? null : `code-finding-${idx}`)}
                                          >
                                            <div className="code-finding-info">
                                              <span className={`severity-badge ${finding.severity}`}>
                                                {finding.severity.toUpperCase()}
                                              </span>
                                              <span className="finding-category">{finding.category}</span>
                                              <span className="finding-line">Line {finding.line_number}</span>
                                            </div>
                                            <svg
                                              className={`expand-arrow ${isExpanded ? 'expanded' : ''}`}
                                              width="20"
                                              height="20"
                                              viewBox="0 0 20 20"
                                              fill="none"
                                            >
                                              <path d="M6 8L10 12L14 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                                            </svg>
                                          </div>
                                          <AnimatePresence>
                                            {isExpanded && (
                                              <motion.div
                                                className="code-finding-details"
                                                initial={{ height: 0, opacity: 0 }}
                                                animate={{ height: 'auto', opacity: 1 }}
                                                exit={{ height: 0, opacity: 0 }}
                                                transition={{ duration: 0.2 }}
                                              >
                                                <div className="finding-description">
                                                  <strong>⚠️ What this means:</strong>
                                                  <p>{finding.description}</p>
                                                </div>
                                                <div className="finding-source">
                                                  <span className="source-label">Source:</span>
                                                  <code className="source-file">{finding.source}</code>
                                                </div>
                                                <div className="detected-code-block">
                                                  <div className="code-block-header">
                                                    <span>🔍 Detected Code (Line {finding.line_number})</span>
                                                    <button
                                                      className="copy-code-btn"
                                                      onClick={(e) => {
                                                        e.stopPropagation()
                                                        navigator.clipboard.writeText(finding.context || finding.matched_code)
                                                      }}
                                                    >
                                                      Copy
                                                    </button>
                                                  </div>
                                                  <pre className="actual-code">
                                                    <code>{finding.context || finding.matched_code}</code>
                                                  </pre>
                                                  {finding.matched_code && finding.matched_code !== finding.context && (
                                                    <div className="matched-highlight">
                                                      <strong>Matched Pattern:</strong>
                                                      <code className="matched-code">{finding.matched_code}</code>
                                                    </div>
                                                  )}
                                                </div>
                                                <div className="finding-recommendation">
                                                  <strong>🛡️ Action Required:</strong>
                                                  <p>
                                                    {finding.severity === 'critical' 
                                                      ? 'DO NOT interact with this website! This code is designed to steal your assets.'
                                                      : finding.severity === 'high'
                                                      ? 'This pattern is commonly used in wallet drainers. Proceed with extreme caution.'
                                                      : 'Verify this is a legitimate use of this function before proceeding.'}
                                                  </p>
                                                </div>
                                              </motion.div>
                                            )}
                                          </AnimatePresence>
                                        </motion.div>
                                      )
                                    })}
                                  </div>
                                  {codeAnalysis.findings.length > 5 && (
                                    <p className="more-findings">
                                      +{codeAnalysis.findings.length - 5} more findings (showing top 5)
                                    </p>
                                  )}
                                </>
                              ) : (
                                <div className="code-analysis-clean">
                                  <span className="clean-icon">✅</span>
                                  {codeAnalysis?.is_trusted_domain ? (
                                    <>
                                      <p><strong>Trusted Domain</strong></p>
                                      <p className="trusted-note">This is a verified legitimate dApp. Normal DeFi functions (approve, permit, etc.) are expected and not flagged.</p>
                                    </>
                                  ) : (
                                    <p>No malicious code patterns detected in {codeAnalysis?.scripts_analyzed || 0} scripts analyzed.</p>
                                  )}
                                </div>
                              )}
                            </motion.div>
                          )}
                        </>
                      )
                    })()}
                  </>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* How It Works Section */}
        <motion.div
          className="how-it-works"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <h2 className="how-title">How It Works</h2>
          <div className="how-steps">
            <div className="how-step">
              <div className="step-number">1</div>
              <h3>Enter Address or URL</h3>
              <p>Paste any Ethereum address or dApp website you want to verify.</p>
            </div>
            <div className="how-step">
              <div className="step-number">2</div>
              <h3>Multi-Layer Analysis</h3>
              <p>Our system queries Etherscan, GoPlus Security API, and runs ML model inference.</p>
            </div>
            <div className="how-step">
              <div className="step-number">3</div>
              <h3>Detailed Report</h3>
              <p>Get a comprehensive risk score with detailed explanations and actionable recommendations.</p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default Scanner
