# Example Policies (EIP-8130 `policyType = 0x02`)

Reference, **unaudited** example of a custom policy manager for EIP-8130 restricted owners.

In EIP-8130, a restricted owner (e.g. a session key) is configured with `policyType = 0x02`, which stores a
`policy_manager` address and an opaque `policy_commitment` in the Account Configuration contract. The protocol
gate forces every call that owner makes to land on that single manager. These contracts are an example of what
that manager can be: one that enforces application-specific limits and then drives the account.

## Flow

1. **Authorize + commit.** The account authorizes the session key with `policyType = 0x02`,
   `policy_manager = PolicyManager`, and `policy_commitment = keccak256` of an account-authorized
   [`PolicyBinding`](./PolicyManager.sol). The Account Configuration contract exposes this via
   [`getPolicy(account, ownerId)`](../../interfaces/IAccountConfiguration.sol).
2. **Install.** The account calls `PolicyManager.install(ownerId, binding)`. The manager re-derives the
   commitment and confirms `getPolicy` resolves to `(this, commitment)` — so an install can only succeed for a
   policy the account actually signed for this manager. The committed `policyConfig` is then handed to the
   policy's install hook, which stores it keyed by commitment.
3. **Use.** When the session key transacts, the protocol dispatches its call _as the account_, so it arrives at
   `PolicyManager.execute(...)` with `msg.sender == account` — the authorization boundary. The manager invokes
   the policy, which enforces the committed policy against the per-use action and returns an `executeBatch` call
   plan. The manager — an execution-enabled owner (`EXTERNAL_CALLER_VERIFIER`) — forwards it to the account.

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
