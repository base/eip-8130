# EIP-8130

Reference implementation for [EIP-8130: Account Abstraction by Account Configuration](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8130.md).

> **Warning** — This is an active work in progress. The spec is changing and the code has not been audited. Do not use in production.

## Overview

EIP-8130 defines a new transaction type and onchain system contract that together provide account abstraction. Accounts configure authorized actors and authenticators in the system contract; the protocol validates transactions using onchain authenticator contracts that implement `IAuthenticator.authenticate(hash, data)`.

## Contracts

Four account implementations are deployed: `DefaultAccount` (the bare building block, deployed standalone as the direct EIP-7702 delegation target for EOAs), `DefaultHighRateAccount` (immutable smart account), `UpgradeableAccount` (general, upgradeable smart account), and `BackwardsCompatible4337Account` (opt-in ERC-4337 example). `DefaultHighRateAccount`, `UpgradeableAccount`, and `BackwardsCompatible4337Account` all inherit from `DefaultAccount`, but each is deployed as its own singleton, since a smart-account proxy is a permanent address that cannot re-delegate the way a 7702 EOA can. `BackwardsCompatible4337Account` is deployed for callers that need it, but nothing deployed by default depends on it.

| Contract | Role | Description |
|----------|------|-------------|
| `AccountConfiguration` | System | Actor authorization, account creation, and change sequencing |
| `DefaultAccount` | Deployed account (EOAs) | Bare minimum account: batched execution (`executeBatch`) + ERC-1271 (`isValidSignature`), all authorization deferred to `AccountConfiguration`. No ERC-4337. Works natively on 8130 chains via direct dispatch. Deployed standalone as the EIP-7702 delegation target for EOAs — they can re-delegate to a new implementation anytime, so no upgrade wrapper is needed |
| `BackwardsCompatible4337Account` | Deployed account (opt-in) | `DefaultAccount` + ERC-4337 (`validateUserOp`), so an account works on non-8130 chains via a bundler + EntryPoint. The EntryPoint is not hardcoded — it is a revocable `TRUSTED_EXECUTOR` actor in `AccountConfiguration`, so a compromised EntryPoint is disabled with one signed change and any version (v0.7/v0.8/…) is supported. Deployed by default but not used by either other deployed account; extend it (with or without UUPS) when 4337 is actually needed |
| `DefaultHighRateAccount` | Deployed account | The immutable account (behind a 45-byte ERC-1167 proxy). A `DefaultAccount` variant that blocks ETH transfers when locked for higher mempool rate limits |
| `UpgradeableAccount` | Deployed account | The general upgradeable account: UUPS-upgradeable `DefaultAccount` (behind `UpgradeableProxy`), with upgrades authorized by a CONFIG-scoped key. Carries no ERC-4337 surface by default — upgrade to a `BackwardsCompatible4337Account`-derived implementation if a given deployment needs it |

### Accounts and proxies

Every account is a small per-account proxy (deployed at a deterministic CREATE2 address) that delegatecalls to one shared implementation singleton. Two proxy strategies:

| Proxy bytecode (what the account *is*) | Implementation (what it *runs*) | Upgradeable? |
|----------|-------------|:---:|
| ERC-1167 minimal proxy (45 bytes) | `DefaultHighRateAccount` | No — immutable |
| `UpgradeableProxy` (93 bytes, ERC-1967 slot) | `UpgradeableAccount` | Yes — UUPS |

`UpgradeableAccount` and `UpgradeableProxy` are the two halves of the upgradeable path: the former is the logic (a singleton), the latter generates the per-account bytecode that holds the ERC-1967 implementation slot (empty slot → the hardcoded default implementation; set slot → the upgraded one). Only implementations that carry UUPS logic (`UpgradeableAccount`, or any implementation upgraded to) can be deployed behind `UpgradeableProxy`.

`AccountConfiguration.createAccount(userSalt, bytecode, initialActors)` is itself proxy-agnostic — it just `CREATE2`s whatever `bytecode` it's given. The caller decides which proxy strategy to use: an ERC-1167 clone of `DefaultHighRateAccount`, or the 93-byte result of `UpgradeableProxy.bytecode(upgradeableImpl)` for an upgradeable account.

### Authenticators

The canonical EIP-8130 authenticator set. secp256k1 (ECDSA) is built into `AccountConfiguration` as `K1_AUTHENTICATOR` (`address(1)`, native `ecrecover`) — it is the single path for the default EOA and every k1 actor, so there is no standalone contract to deploy. `AlwaysValidAuthenticator` is an example/test helper, not a canonical authenticator.

| Contract | Algorithm |
|----------|-----------|
| `K1_AUTHENTICATOR` (built in, `address(1)`) | secp256k1 (ECDSA) |
| `P256Authenticator` | secp256r1 / P-256 (raw) |
| `WebAuthnAuthenticator` | secp256r1 / P-256 (WebAuthn) |
| `DelegateAuthenticator` | Delegated validation (1-hop) |
| `AlwaysValidAuthenticator` | Always valid — keyless relay (example/testing only) |

## Usage

### Build

```shell
forge build
```

### Test

```shell
forge test
```

### Format

```shell
forge fmt
```

CI runs `forge fmt --check`, so commits with unformatted Solidity will fail. A pre-commit hook in `.githooks/` runs the same check locally. Enable it once per clone:

```shell
git config core.hooksPath .githooks
```

## License

MIT
