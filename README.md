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

`importAccount` is not signature-relayable. The account itself must call Keystore, the account's code must choose the actor set via `getImportActors()`, and ERC-1271 only confirms the digest of that set. A role that can `execute` plus 1271 cannot install itself as scope-0 admin. Wallets that do not implement `IKeystoreImport` cannot be imported — including guarded Safes, delayed-upgrade and immutable wallets, 7579/6900 validators, 6551 TBAs, and Aragon plugins, until they upgrade.

After import, the actor set in Keystore is the source of truth. Subsequent owner changes on the wallet do not propagate; wallets should route their own signature validation through `authenticateActor` after import. `chainId == 0` remains a valid multichain import; with the `msg.sender` gate and hash-bound confirmation it cannot be used by a third party.

Reference integration (upgrade and import atomically with `upgradeToAndCall(newImpl, abi.encodeCall(importToKeystore, chainId))`):

```solidity
function importToKeystore(uint256 chainId) external onlyEntryPointOrOwner {
    InitialActor[] memory actors = getImportActors();
    bytes32 digest = KEYSTORE.computeImportDigest(address(this), chainId, actors);
    assembly { tstore(IMPORT_DIGEST_TSLOT, digest) }
    KEYSTORE.importAccount(chainId, "");
    assembly { tstore(IMPORT_DIGEST_TSLOT, 0) }
}

function isValidSignature(bytes32 hash, bytes calldata sig) public view override returns (bytes4) {
    if (sig.length == 0 && msg.sender == address(KEYSTORE)) {
        bytes32 expected; assembly { expected := tload(IMPORT_DIGEST_TSLOT) }
        return (expected != 0 && hash == expected) ? this.isValidSignature.selector : bytes4(0);
    }
    return super.isValidSignature(hash, sig);
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
