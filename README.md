# EIP-8130

Reference implementation for [EIP-8130: Account Abstraction by Account Configuration](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8130.md).

> **Warning** — This is an active work in progress. The spec is changing and the code has not been audited. Do not use in production.

## Overview

EIP-8130 defines a new transaction type and onchain system contract that together provide account abstraction. Accounts configure authorized actors and authenticators in the system contract; the protocol validates transactions using onchain authenticator contracts that implement `IAuthenticator.authenticate(hash, data)`.

## Contracts

Two account implementations are deployed: `DefaultAccount` (the bare building block, deployed standalone as the direct EIP-7702 delegation target for EOAs) and `CanonicalHighRatePayerAccount` (immutable high-rate payer account). `CanonicalHighRatePayerAccount` inherits from `DefaultAccount` but is deployed as its own singleton, since a smart-account proxy is a permanent address that cannot re-delegate the way a 7702 EOA can. It can sponsor other txs or transact itself. While locked, outbound ETH value is blocked — the account cannot move its own ETH in the txn — so the only balance decrease is gas, making balance predictable to mempools and allowing higher rate limits. ERC-1167 clones of this implementation are the admission path for that high-rate payer mode.

Additional, **unaudited** example account variants — `UpgradeableAccount`/`UpgradeableProxy` (general upgradeable UUPS account) and `BackwardsCompatible4337Account` (opt-in ERC-4337) — live in a separate examples repository and are not deployed by this repo.

| Contract | Role | Description |
|----------|------|-------------|
| `Keystore` | System | Actor authorization, account creation, and change sequencing |
| `DefaultAccount` | Deployed account (EOAs) | Bare minimum account: batched execution (`executeBatch`) + ERC-1271 (`isValidSignature`), all authorization deferred to `Keystore`. No ERC-4337. Works natively on 8130 chains via direct dispatch. Deployed standalone as the EIP-7702 delegation target for EOAs — they can re-delegate to a new implementation anytime, so no upgrade wrapper is needed |
| `CanonicalHighRatePayerAccount` | Deployed account | High-rate payer account (behind a 45-byte ERC-1167 proxy). Can sponsor or transact itself. While locked, cannot move its own ETH in the txn — gas is the only balance decrease — enabling higher mempool rate limits |

### Accounts and proxies

Every account is a small per-account proxy (deployed at a deterministic CREATE2 address) that delegatecalls to one shared implementation singleton. The immutable strategy deployed here is an ERC-1167 minimal proxy (45 bytes) in front of `CanonicalHighRatePayerAccount` — that fixed 1167 delegation is what qualifies the account as a high-rate payer. An upgradeable (UUPS) strategy — `UpgradeableAccount` behind `UpgradeableProxy` — is provided as an unaudited example in a separate repository.

`Keystore.createAccount(userSalt, bytecode, initialActors)` is itself proxy-agnostic — it just `CREATE2`s whatever `bytecode` it's given. The caller decides which proxy strategy to use: an ERC-1167 clone of `CanonicalHighRatePayerAccount`, or an upgradeable proxy for an upgradeable account.

### Authenticators

The canonical EIP-8130 authenticator set. secp256k1 (ECDSA) is built into `Keystore` as `K1_AUTHENTICATOR` (`address(1)`, native `ecrecover`) — it is the single path for the default EOA and every k1 actor, so there is no standalone contract to deploy.

| Contract | Algorithm |
|----------|-----------|
| `K1_AUTHENTICATOR` (built in, `address(1)`) | secp256k1 (ECDSA) |
| `P256Authenticator` | secp256r1 / P-256 (raw) |
| `WebAuthnAuthenticator` | secp256r1 / P-256 (WebAuthn) |
| `DelegateAuthenticator` | Delegated validation (1-hop) |

## Usage

### Importing an existing wallet

`importAccount()` is not signature-relayable and takes no parameters. The account itself must call Keystore (`msg.sender`), and the account's code must return the actor set plus `computeImportDigest` of that set from a single callback, `confirmKeystoreImport()`. Keystore installs only that set, and only when the digest matches. Wallets that do not implement `IKeystoreImport` cannot be imported — including guarded Safes, delayed-upgrade and immutable wallets, 7579/6900 validators, 6551 TBAs, and Aragon plugins, until they upgrade.

Import carries no `chainId`: it is a live `msg.sender` call plus a live confirm, so the chain is already fixed by where the transaction lands. A wallet that wants to bind import to a specific chain can check `block.chainid` inside `confirmKeystoreImport`.

A wallet that always returns a valid `(digest, actors)` pair reopens `execute(keystore, importAccount())` for itself. Delegated EOAs can also add keys via `applySignedAccountChanges`.

After import, the actor set in Keystore is the source of truth. Subsequent owner changes on the wallet do not propagate; wallets should route their own signature validation through `authenticateActor` after import.

Import is an explicit wallet path, not an `execute()` call: `execute()` is reachable by every role that can drive it, whereas import moves where the account's authority lives, so gate it on a dedicated entry (`onlyOwner`, an owner signature, an initializer, a timelock) exactly as you would `upgradeTo`.

Two confirmation styles:

```solidity
// Transient (owner-gated entry). `execute(keystore, importAccount())` does not set the slot.
function importToKeystore() external onlyOwner {
    InitialActor[] memory actors = initialActors();
    bytes32 digest = KEYSTORE.computeImportDigest(address(this), actors);
    assembly { tstore(IMPORT_DIGEST_TSLOT, digest) }
    KEYSTORE.importAccount();
    assembly { tstore(IMPORT_DIGEST_TSLOT, 0) }
}

function confirmKeystoreImport()
    external
    view
    returns (bytes32 digest, InitialActor[] memory actors)
{
    actors = initialActors();
    assembly { digest := tload(IMPORT_DIGEST_TSLOT) }
    if (msg.sender != address(KEYSTORE) || digest == 0) return (bytes32(0), actors);
}
```

```solidity
// Stateless (init-time import). Always returns the code-derived set and its digest.
function confirmKeystoreImport()
    external
    view
    returns (bytes32 digest, InitialActor[] memory actors)
{
    actors = initialActors();
    if (msg.sender != address(KEYSTORE)) return (bytes32(0), actors);
    digest = KEYSTORE.computeImportDigest(address(this), actors);
}
```

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
