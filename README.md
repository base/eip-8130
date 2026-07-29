# EIP-8130

Reference implementation for [EIP-8130: Account Abstraction by Account Configuration](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8130.md).

> **Warning** — This is an active work in progress. The spec is changing and the code has not been audited. Do not use in production.

## Overview

EIP-8130 defines a new transaction type and onchain system contract that together provide account abstraction. Accounts configure authorized actors and authenticators in the system contract; the protocol validates transactions using onchain authenticator contracts that implement `IAuthenticator.authenticate(hash, data)`.

## Contracts

One account implementation is deployed: `DefaultAccount` — the canonical EIP-8130 account, deployed standalone as the direct EIP-7702 delegation target for EOAs. It is high-rate-payer-safe by default: while the account is locked in `AccountConfiguration`, outbound ETH value transfers are blocked (on both `execute` and `executeBatch`) — the account cannot move its own ETH in the txn — so the only balance decrease is gas, making balance predictable to mempools and allowing higher rate limits. Zero-value calls are unaffected by the lock. An ERC-1167 clone of `DefaultAccount` is the admission path for high-rate payer mode; because admission is ultimately a node allowlist, other conforming implementations (or an immutable proxy over `DefaultAccount`) can be allowlisted too.

Additional, **unaudited** example account variants — `UpgradeableAccount`/`UpgradeableProxy` (general upgradeable UUPS account) and `BackwardsCompatible4337Account` (opt-in ERC-4337) — live in a separate examples repository and are not deployed by this repo.

| Contract | Role | Description |
|----------|------|-------------|
| `AccountConfiguration` | System | Actor authorization, account creation, and change sequencing |
| `DefaultAccount` | Deployed account (EOAs) | The EIP-8130 account: single-call (`execute`) and batched (`executeBatch`) execution + ERC-1271 (`isValidSignature`), all authorization deferred to `AccountConfiguration`. No ERC-4337. Works natively on 8130 chains via direct dispatch. Deployed standalone as the EIP-7702 delegation target for EOAs — they can re-delegate anytime, so no upgrade wrapper is needed. High-rate-payer-safe by default: blocks outbound ETH value transfers while locked (gas is then the only balance decrease); an ERC-1167 clone is the high-rate admission path |

### Accounts and proxies

Every account is a small per-account proxy (deployed at a deterministic CREATE2 address) that delegatecalls to one shared implementation singleton. The immutable strategy deployed here is an ERC-1167 minimal proxy (45 bytes) in front of `DefaultAccount` — that fixed 1167 delegation is what qualifies the account as a high-rate payer (the node can trust the lock-respecting bytecode cannot be swapped out). An upgradeable (UUPS) strategy — `UpgradeableAccount` behind `UpgradeableProxy` — is provided as an unaudited example in a separate repository.

`AccountConfiguration.createAccount(userSalt, bytecode, initialActors)` is itself proxy-agnostic — it just `CREATE2`s whatever `bytecode` it's given. The caller decides which proxy strategy to use: an ERC-1167 clone of `DefaultAccount`, or an upgradeable proxy for an upgradeable account.

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
