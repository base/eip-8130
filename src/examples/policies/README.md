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
3. **Use.** When the session key transacts, the protocol dispatches its call _as the account_, so it arrives at
   `PolicyManager.execute(actorId, ...)` with `msg.sender == account`. The manager re-reads `getPolicy(account,
   actorId)` on every call and requires it to resolve to `(this, commitment)`, so a revoked or expired key stops
   immediately. It then invokes the policy, which enforces the committed policy against the per-use action and
   returns an `executeBatch` call plan that the manager — an execution-enabled actor (`EXTERNAL_CALLER_AUTHENTICATOR`)
   — forwards to the account.

```
session key ──(8130 gate: only PolicyManager)──▶ PolicyManager.execute
                                                     │  policy enforces commitment
                                                     ▼
                                                 account.executeBatch ──▶ token / target
```

## Contracts

| Contract | Role |
|----------|------|
| `PolicyManager` | Minimal manager: install verifies the account's signed `getPolicy` commitment; `execute` → policy → `account.executeBatch`. |
| `Policy` | Base hook: `onInstall` (store committed config) + `onExecute` (enforce + build call plan). |
| `ERC20SpendLimitPolicy` | Recurring (e.g. weekly) per-binding ERC-20 spend limit. |
| `SelectorGatingPolicy` | Restrict a key to one target and a fixed set of function selectors. |
| `RecurringAllowance` | Periodic-allowance accounting library (ported from base/account-policies). |

A key that needs limits on two tokens installs two bindings; the manager routes each by commitment.

> Out of scope for this reference: signature-based install, replacement, and uninstall. See
> [base/account-policies](https://github.com/base/account-policies) for a fuller policy framework.
