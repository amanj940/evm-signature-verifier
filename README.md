# EVM Signature Verifier 🔐

Standardized cryptographic signature verification engine for EVM-compatible networks, featuring strict EIP-712 structured data hashing, ECDSA malleability guards, and nonce-based replay protection.

[![Foundry](https://img.shields.io/badge/Foundry-1.5.1-red.svg)](https://getfoundry.sh/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.28-blue.svg)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ Core Features

- **EIP-712 Typed Data Hashing**: Prevents cross-dApp signature spoofing through dynamic `DOMAIN_SEPARATOR` bound to `chainId` and contract address.
- **Strict Anti-Malleability Guards**: Rejects high `s` values (`s > secp256k1n / 2`) and malformed `v` recovery IDs to defeat transaction malleability attacks.
- **On-Chain Replay Protection**: Tracks digested authorizations and increments sequential per-user nonces.
- **Gas Optimized**: Assembly-optimized `mload` extraction for `(r, s, v)` tuples.

---

## 📂 Architecture

```text
evm-signature-verifier/
├── src/
│   └── SignatureVerifier.sol    # Core verification contract
├── test/
│   └── SignatureVerifier.t.sol  # Foundry invariant & unit test suite
├── .github/workflows/
│   └── test.yml                 # Automated CI test workflow
└── foundry.toml                 # Foundry compiler configuration
```

---

## 🚀 Quickstart

### Prerequisites
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge`, `cast`)

### Compile & Test
```bash
# Clone the repository
git clone https://github.com/<owner>/evm-signature-verifier.git
cd evm-signature-verifier

# Run comprehensive test suite
forge test -vvv
```

---

## 🛡️ Security Guarantees

1. **Replay Rejection**: Each signature digest is permanently recorded in `executedHashes`.
2. **Deadline Expiration**: Enforces block timestamp constraints on every authorization.
3. **Canonical ECDSA**: Strict compliance with OpenZeppelin and yellow paper cryptographic recovery standards.
