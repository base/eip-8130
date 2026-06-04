# EIP-8130

Reference implementation for [EIP-8130: Account Abstraction by Account Configuration](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8130.md).

> **Warning** — This is an active work in progress. The spec is changing and the code has not been audited. Do not use in production.

## Overview

EIP-8130 defines a new transaction type and onchain system contract that together provide account abstraction. Accounts configure authorized actors and verifiers in the system contract; the protocol validates transactions using onchain verifier contracts that implement `IVerifier.verify(hash, data)`.

## Contracts

| Contract | Description |
|----------|-------------|
| `AccountConfiguration` | System contract for actor authorization, account creation, and change sequencing |
| `DefaultAccount` | Default wallet implementation auto-delegated to EOAs |
| `DefaultHighRateAccount` | Wallet variant that blocks ETH transfers when locked for higher mempool rate limits |

### Verifiers

The canonical EIP-8130 verifier set. `AlwaysValidVerifier` is an example/test helper, not a canonical verifier.

| Contract | Algorithm |
|----------|-----------|
| `K1Verifier` | secp256k1 (ECDSA) |
| `P256Verifier` | secp256r1 / P-256 (raw) |
| `WebAuthnVerifier` | secp256r1 / P-256 (WebAuthn) |
| `DelegateVerifier` | Delegated validation (1-hop) |
| `AlwaysValidVerifier` | Always valid — keyless relay (example/testing only) |

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
