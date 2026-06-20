# Example Policies (EIP-8130 actor policies)

Reference, **unaudited** example of a policy manager for EIP-8130 restricted actors.

In EIP-8130, a restricted actor (e.g. a session key) is configured with a non-zero `policyType`, which stores a
`policy_manager` address and an opaque `policy_commitment` in the Account Configuration contract. The protocol
gate forces every call that actor makes to land on that single manager. These contracts are an example of what
that manager can be: one that enforces application-specific limits and then drives the account. (The protocol
gates identically on any non-zero `policyType` and does not interpret the value; this example uses `0x01`.)

## Flow

1. **Authorize + commit.** The account authorizes the session key with `policyType = 0x01`,
   `policy_manager = PolicyManager`, and `policy_commitment = keccak256` of an account-authorized
   [`PolicyBinding`](./PolicyManager.sol). The Account Configuration contract exposes this via
   [`getPolicy(account, actorId)`](../../interfaces/IAccountConfiguration.sol).
2. **Install.** The account calls `PolicyManager.install(actorId, binding)`. The manager re-derives the
   commitment and confirms `getPolicy` resolves to `(this, commitment)` — so an install can only succeed for a
   policy the account actually signed for this manager. The committed `policyConfig` is then handed to the
   policy's install hook, which stores it keyed by commitment.
3. **Use.** When the session key transacts, the protocol gate resolves the key's allowed target
   (`policy_manager(account, actorId)`) and reverts any call whose `call.to` isn't that address before dispatch, so
   the key's call can only arrive at `PolicyManager.execute(policy, executionData)` with `msg.sender == account`.
   Because reaching this manager already proves it is the key's gate, `execute` does not re-check the target: it
   reads the acting `actorId` from the [transaction-context precompile](../../interfaces/ITransactionContext.sol)
   (`getTransactionSenderActorId()`) and needs only the live `getPolicyCommitment(account, actorId)` (a single
   SLOAD) to locate the installed binding — a revoked or expired key has a zero commitment and stops immediately.
   It then invokes the policy, which enforces the committed policy against the per-use action and returns an
   `executeBatch` call plan that the manager — an execution-enabled actor (`EXTERNAL_CALLER_AUTHENTICATOR`) —
   forwards to the account.

```
session key ──(8130 gate: only PolicyManager)──▶ PolicyManager.execute
                                                     │  policy enforces commitment
                                                     ▼
                                                 account.executeBatch ──▶ token / target
```

## Contracts

| Contract | Role |
|----------|------|
| `PolicyManager` | Minimal manager: install verifies the account's signed commitment; `execute` reads the acting actor from the transaction-context precompile, reads its live commitment, then policy → `account.executeBatch`. |
| `Policy` | Base hook: `onInstall` (store committed config) + `onExecute` (enforce + build call plan). |
| `SessionPolicy` | Unified "session key" policy: combines a target allowlist, per-target selector rules, per-selector recipient allowlists, and per-token (and native-ETH) recurring/one-time spend limits — all enforced atomically on each call. |
| `RecurringAllowance` | Periodic-allowance accounting library (ported from base/account-policies); used by `SessionPolicy` for spend accounting. |

A key that needs several independent bindings installs each separately; the manager routes each by commitment.

### `SessionPolicy`: one policy, many dimensions

The manager validates exactly **one** `(policy, commitment)` per `execute` call, so installing several focused
policies cannot *jointly* gate the **same** call (each binding is checked in isolation). `SessionPolicy` is the
pattern for "this one call must satisfy target **and** selector **and** recipient **and** spend-limit": it decodes
its committed config into commitment-keyed mappings at install, so each `onExecute` resolves every dimension with
O(1) SLOADs. Per-call cost therefore tracks the constraints actually configured, so configure only the dimensions a
given key needs.

Recipient allowlists and spend-limit accounting require decoding a call's arguments, which is only possible for
selectors whose ABI is known: `SessionPolicy` hardcodes the standard ERC-20 set (`transfer`, `transferFrom`,
`approve`). A recipient allowlist may only be attached to one of those (enforced at install); spend limits are
consumed for those selectors on a limited token, native-ETH limits from each call's `value`, and every other
selector is governed by target/selector gating alone.

> Out of scope for this reference: signature-based install, replacement, and uninstall. See
> [base/account-policies](https://github.com/base/account-policies) for a fuller policy framework.
