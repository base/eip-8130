# Example external factory (`SETDELEGATE` + EIP-8130)

Reference, **unaudited** example of an external account factory that combines
[EIP-7819](https://eips.ethereum.org/EIPS/eip-7819) (`SETDELEGATE`) with
[EIP-8130](https://eips.ethereum.org/EIPS/eip-8130) (Account Configuration).

EIP-8130 supports three first-class account-creation paths today: EOAs (auto-delegated to
`DEFAULT_ACCOUNT_ADDRESS`), already-deployed contract accounts (`importAccount`), and new accounts via the
`Create Entry` in `account_changes` (places runtime bytecode at a CREATE2 address).

Path 3 places the wallet's full runtime bytecode at every account address. For wallets that share a common
implementation across many accounts, this is wasteful (up to ~4.9M gas to deposit a 24 KB implementation,
repeated per account) and forecloses on-chain upgradeability.

`SETDELEGATE` (opcode `0xf6`, EIP-7819) lets a contract place a 23-byte delegation indicator
(`0xef0100 || target`) at a deterministic address. Combining it with EIP-8130's `importAccount` gives a
fourth, off-spec path with state and gas savings plus factory-mediated upgradeability — without
AccountConfiguration ever knowing the factory exists.

## Flow

```
Phase A (off-chain)   wallet computes counterfactual address
  actorsHash = keccak256(actorHash_0 || ... || actorHash_n)         // typed actor hashes
  salt       = keccak256(userSalt || actorsHash)
  account    = keccak256(0xef0100 || factory || salt)[12:]          // EIP-7819 derivation

Phase B (one tx)      invokes factory.deploy(initialActors, implementation, userSalt)
  B.1  SETDELEGATE(salt, implementation)
       → code(account) = 0xef0100 || implementation                 (23 bytes)
       → nonce(account) = 1                                         (EIP-7819 step 9)
  B.2  account.bootstrap(actorsHash)
       → implementation stores expected actors hash in account's storage
  B.3  ACCOUNT_CONFIG.importAccount(account, initialActors, "")
       → AccountConfig computes ActorInitialization digest
       → STATICCALL account.isValidSignature(digest, "")
         → Implementation's bootstrap branch (getChangeSequences(account).local == 0):
           digest matches expected → MAGIC
       → AccountConfig writes actor_config, bumps local sequence to 1

Phase C (optional)    close the implicit-EOA path
  Send a Config Change Entry (or applySignedActorChanges) with
    actor_change = revokeActor(bytes32(bytes20(account)))
  → AccountState.flags |= FLAG_REVOKE_DEFAULT_EOA for the account
  (importAccount already disables the implicit default-EOA path on the account itself; this revokes the
   self-actorId at the actor level if it was re-enabled via an explicit self actor.)

Phase D (later)       upgrade implementation
  account submits 8130 tx (authed by an actor) with calls = [[ factory.upgrade(...) ]]
  → msg.sender = account in factory.upgrade, factory runs SETDELEGATE(salt, newImpl)
  → code(account) = 0xef0100 || newImpl
```

## Squatting / front-running defenses

- `SETDELEGATE` address derivation includes `msg.sender`, so a different factory yields a different address.
- The salt commits to the actor set (`actorsHash`), so a different actor set yields a different salt and
  therefore a different address. Trying to put unintended actors at the same address is a hash collision.
- `SETDELEGATE → bootstrap → importAccount` runs in one transaction frame; no intermediate window exists for
  a different transaction to interpose state changes.
- After `importAccount` succeeds, `getChangeSequences(account).local == 1`, so the bootstrap branch in
  `isValidSignature` is permanently disabled. The implementation is in normal-ERC-1271-via-AccountConfig
  mode forever after.
- A codeless counterfactual address cannot be imported: a no-code STATICCALL returns empty data, the magic
  check fails, `importAccount` reverts. Squatting on counterfactual EOAs is impossible.

## Contracts

| Contract | Role |
|----------|------|
| `SetDelegateFactory` | Deploys via `SETDELEGATE`, primes implementation bootstrap, calls `importAccount`. Owns the address-derivation logic and the optional `upgrade` path. |
| `IBootstrap` | Minimal interface the implementation must expose for atomic priming. |
| `BootstrapAccount` | Minimal bootstrap-aware reference implementation. ERC-1271 has a BOOTSTRAP branch that validates the import digest against the primed `actorsHash`, and otherwise defers to `AccountConfiguration.authenticateActor`. |

## Spec-side prerequisite

This pattern relies on two `AccountConfiguration.importAccount` properties, both already in place on `main`:

1. **No delegation-indicator reject.** `importAccount` does not reject accounts whose code begins with the
   delegation indicator (`0xef0100`). An earlier draft rejected them, but that rule never closed an attack
   surface — a compromised k1 key already drains a delegated EOA via standard 7702 / 1559 transactions — while
   it did block the entire SETDELEGATE factory pattern. The ERC-1271 callback is the sole binding between the
   account and its initial actor set, which naturally rejects code-less addresses and dishonest implementations.
2. **`localSequence` written after the ERC-1271 callback.** `importAccount` defers its `localSequence = 1`
   write until after the STATICCALL, so the bootstrap-aware implementation can observe
   `getChangeSequences(this).local == 0` during the callback and take its bootstrap branch. The STATICCALL
   cannot write state, so deferring the write introduces no reentrancy risk.

## Caveats

- **EIP-7819 is Draft** and `SETDELEGATE` (opcode `0xf6`) is not yet executable on most chains. In tests,
  `SetDelegateFactory._setDelegate` is overridden by `TestableSetDelegateFactory` to simulate the opcode
  via `vm.etch`. Production uses the real opcode.
- The reference `BootstrapAccount` is intentionally minimal: no execution, caller-authorization, or
  receive-hook plumbing beyond Solady's `Receiver`. Combine with `DefaultAccount` (or equivalent) for a
  full account.
- `importAccount` disables the implicit default-EOA path on the imported account itself (parity with
  `createAccount`). The factory revokes nothing further automatically; if an explicit self k1 actor was
  included to keep the key live, close it later with an `applySignedActorChanges` that `revokeActor`s
  `bytes32(bytes20(account))` — or stack a Config Change Entry in the same 8130 tx.
- The `actorsHash` here is the **typed** hash (matching EIP-8130's `ActorInitialization` digest). If you
  also want addresses to match the Create Entry path, switch to the **packed** commitment
  `keccak256(actorId_0 || authenticator_0 || ...)` and reconstruct the typed digest in the implementation.

## Future protocol integration (optional)

These are forward-looking notes; nothing in this directory depends on them.

1. **Canonical factory set (off-chain, by analogy to canonical authenticators).** A companion spec could
   standardize the factory + implementation pair and a deterministic CREATE2 deployment address. Wallets and
   indexers honor the set off-chain; AccountConfiguration remains unaware.
2. **`account_changes` entry type `0x03 SetDelegateCreate`.** For atomic single-tx deploys via canonical
   factories within an 8130 transaction.
3. **Do nothing protocol-side.** Factories live entirely in user space; both spec prerequisites above are
   already satisfied on `main`.
