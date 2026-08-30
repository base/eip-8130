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

`importAccount()` is not signature-relayable and takes no parameters and no actor array. The account itself must call Keystore, the account's code returns the actor set via `getImportActors()`, and `confirmImportDigest` confirms the exact digest of that set. Keystore installs only a set the code returned and the code path confirmed. A role that can `execute` cannot install a different admin. Wallets that do not implement `IEIP8130Import` cannot be imported — including guarded Safes, delayed-upgrade and immutable wallets, 7579/6900 validators, 6551 TBAs, and Aragon plugins, until they upgrade.

Import carries no `chainId`: it is a live `msg.sender` call plus a live confirm, so the chain is already fixed by where the transaction lands and there is nothing to replay-scope. A wallet that wants to bind import to a specific chain can check `block.chainid` inside its own `confirmImportDigest`.

Import entries must not take an actor array from any self-reachable path. `confirmImportDigest` must only return the bound value for a digest the wallet derived itself (a wallet that always returns it reopens `execute()` for itself). A delegated (EIP-7702) EOA cannot import: `importAccount` reverts `DelegatedAccountCannotImport` when `msg.sender.code` starts with the `0xef0100` designator, because a malicious delegate could otherwise install actors and revoke the default EOA, and that Keystore state would survive redelegation (Keystore state is keyed by address, not code). Delegated EOAs add keys via `applySignedAccountChanges` instead.

After import, the actor set in Keystore is the source of truth. Subsequent owner changes on the wallet do not propagate; wallets should route their own signature validation through `authenticateActor` after import.

Import is an explicit wallet path, not an `execute()` call: `execute()` is reachable by every role that can drive it, whereas import moves where the account's authority lives, so gate it on a dedicated entry (`onlyOwner`, an owner signature verified wallet-side over the digest, an initializer, a timelock) exactly as you would `upgradeTo`. Nothing is passed to `importAccount()`; a signature-based wallet consumes its signature wallet-side and `confirmImportDigest` just attests the outcome.

The confirmation return is `keccak256(abi.encode(IMPORT_CONFIRMATION_MAGIC, digest))` so a static or calldata-echoing return cannot match. Two confirmation styles:

```solidity
// Transient (owner-gated entry). `execute(keystore, importAccount)` does not set the slot.
function importToKeystore() external onlyOwner {
    bytes32 digest = KEYSTORE.computeImportDigest(address(this), getImportActors());
    assembly { tstore(IMPORT_DIGEST_TSLOT, digest) }
    KEYSTORE.importAccount();
    assembly { tstore(IMPORT_DIGEST_TSLOT, 0) }
}

function confirmImportDigest(bytes32 d) external view returns (bytes32) {
    bytes32 expected; assembly { expected := tload(IMPORT_DIGEST_TSLOT) }
    if (msg.sender != address(KEYSTORE) || expected == 0 || d != expected) return bytes32(0);
    return keccak256(abi.encode(KEYSTORE.IMPORT_CONFIRMATION_MAGIC(), d));
}
```

```solidity
// Stateless (init-time import). Recomputes from getImportActors; no transient handshake.
function confirmImportDigest(bytes32 d) external view returns (bytes32) {
    InitialActor[] memory actors = getImportActors();
    if (d != KEYSTORE.computeImportDigest(address(this), actors)) return bytes32(0);
    return keccak256(abi.encode(KEYSTORE.IMPORT_CONFIRMATION_MAGIC(), d));
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
