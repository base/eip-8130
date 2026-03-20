# EIP-8130

Reference implementation for [EIP-8130: Account Abstraction by Account Configuration](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8130.md).

> **Warning** — This is an active work in progress. The spec is changing and the code has not been audited. Do not use in production.

## Overview

EIP-8130 defines a new transaction type and onchain system contract that together provide account abstraction. Accounts configure authorized owners and verifiers in the system contract; the protocol validates transactions using onchain verifier contracts that implement `IVerifier.verify(hash, data)`.

## Contracts

| Contract | Description |
|----------|-------------|
| `AccountConfiguration` | System contract for owner authorization, account creation, and change sequencing |
| `DefaultAccount` | Default wallet implementation auto-delegated to EOAs |
| `DefaultHighRateAccount` | Wallet variant that blocks ETH transfers when locked for higher mempool rate limits |

### Verifiers

| Contract | Algorithm |
|----------|-----------|
| `K1Verifier` | secp256k1 (ECDSA) |
| `P256Verifier` | secp256r1 / P-256 (raw) |
| `WebAuthnVerifier` | secp256r1 / P-256 (WebAuthn) |
| `SchnorrVerifier` | Schnorr over secp256k1 |
| `DelegateVerifier` | Delegated validation (1-hop) |
| `BLSVerifier` | BLS12-381 |
| `MultisigVerifier` | M-of-N K1 multisig |
| `Groth16Verifier` | Groth16 ZK-SNARK over BN254 |
| `AlwaysValidVerifier` | Always valid — keyless relay |

### Payer Verifiers

| Contract | Pricing Oracle |
|----------|---------------|
| `ChainlinkPayerVerifier` | Chainlink ETH/USD feed (with optional blocklist) |
| `AeroPayerVerifier` | Aerodrome DEX (any token with liquidity) |

## Usage

### Build

```shell
forge build
```

### Test

```shell
forge test
```

## License

MIT
