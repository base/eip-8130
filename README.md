# EIP-8130

Reference implementation for [EIP-8130: Account Abstraction by Account Configuration](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8130.md).

> **Warning** — This is an active work in progress. The spec is changing and the code has not been audited. Do not use in production.

## Overview

EIP-8130 defines a new transaction type and onchain system contract that together provide account abstraction — batching, gas sponsorship, and authentication using any cryptographic system. Accounts configure authorized keys and verifiers in the system contract; the protocol validates transactions using native implementations for recognized algorithms, and via sandboxed pure-function contracts for any other scheme.

## Contracts

| Contract | Description |
|----------|-------------|
| `AccountConfiguration` | System contract for key authorization, account creation, and change sequencing |
| `DefaultAccount` | Default wallet implementation auto-delegated to EOAs |
| `SandboxLib` | Library for sandbox verifier bytecode validation |

### Verifiers

| Contract | Algorithm |
|----------|-----------|
| `K1Verifier` | secp256k1 (ECDSA) |
| `P256Verifier` | secp256r1 / P-256 (raw) |
| `WebAuthnVerifier` | secp256r1 / P-256 (WebAuthn) |
| `DelegateVerifier` | Delegated validation (1-hop) |
| `BLSVerifier` | BLS12-381 (sandbox) |
| `SchnorrVerifier` | Schnorr over secp256k1 (sandbox) |
| `MultisigVerifier` | M-of-N K1 multisig (sandbox) |
| `Groth16Verifier` | Groth16 ZK-SNARK over BN254 (sandbox) |
| `AlwaysValidVerifier` | Always valid — keyless relay (sandbox) |

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
