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
   [`getPolicy(account, actorId)`](../../AccountConfiguration.sol).
2. **Install.** Anyone (the account itself, the session key, or a third party) calls
   `PolicyManager.install(actorId, binding)`. The manager re-derives the commitment and confirms `getPolicy`
   resolves to `(this, commitment)` — so an install can only succeed for a policy the account actually signed for
   this manager, which is what makes the call permissionless. The committed `policyConfig` is then handed to the
   policy's install hook, which stores it keyed by commitment. Install is one-shot per commitment, so it can never
   reset an installed binding's accounting (e.g. spend counters); changing any binding field yields a different
   commitment — a separate, independently-accounted binding.
3. **Use.** When the session key transacts, the protocol gate resolves the key's allowed target
   (`policy_manager(account, actorId)`) and reverts any call whose `call.to` isn't that address before dispatch, so
   the key's call can only arrive at `PolicyManager.execute(policy, executionData)` with `msg.sender == account`.
   Because reaching this manager already proves it is the key's gate, `execute` does not re-check the target: it
   reads the acting `actorId` from the [transaction-context precompile](../../interfaces/ITransactionContext.sol)
   (`getTransactionSenderActorId()`) and needs only the live `getPolicyCommitment(account, actorId)` (a single
   SLOAD) to locate the installed binding — a revoked or expired key has a zero commitment and stops immediately.
   It then invokes the policy, which enforces the committed policy against the per-use action and returns an
   `executeBatch` call plan that the manager — an execution-enabled actor (`TRUSTED_EXECUTOR`) —
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
| `PolicyManager` | Minimal manager: install (permissionless) verifies the account's signed commitment; `execute` (account-acting) reads the acting actor from the transaction-context precompile; `executeFor` / `executeForMany` (external-caller) let an authorized outside party drive one or many accounts. All paths run the policy → `account.executeBatch`. |
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

#### Worked example

Configure one session key that (1) has full, uncapped access to one ERC-20 (the "MyApp" token), (2) may spend at
most **$5 of USDC per month**, and (3) may call the MyApp app contract as much as it wants, but only through two
chosen selectors. Three call scopes + one spend limit:

```solidity
address MYAPP_TOKEN; // the "MyApp" ERC-20
address USDC;        // 6 decimals
address MYAPP;       // the MyApp app contract
bytes4  selStake = MyApp.stake.selector;
bytes4  selClaim = MyApp.claim.selector;

// Spend limits: ONLY USDC ($5/month). MyApp token has no entry, so it is uncapped.
SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](1);
limits[0] = SessionPolicy.TokenLimit({token: USDC, limit: 5e6, period: 30 days});

SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](3);

// (a) MyApp token: full access — empty rules => any selector; no TokenLimit => no spend cap.
scopes[0] = SessionPolicy.CallScope({target: MYAPP_TOKEN, selectorRules: new SessionPolicy.SelectorRule[](0)});

// (b) USDC: `transfer` only, so the $5/month cap can't be sidestepped by another selector.
SessionPolicy.SelectorRule[] memory usdcRules = new SessionPolicy.SelectorRule[](1);
usdcRules[0] = SessionPolicy.SelectorRule({selector: IERC20.transfer.selector, recipients: new address[](0)});
scopes[1] = SessionPolicy.CallScope({target: USDC, selectorRules: usdcRules});

// (c) MyApp contract: two chosen selectors, unlimited calls.
SessionPolicy.SelectorRule[] memory appRules = new SessionPolicy.SelectorRule[](2);
appRules[0] = SessionPolicy.SelectorRule({selector: selStake, recipients: new address[](0)});
appRules[1] = SessionPolicy.SelectorRule({selector: selClaim, recipients: new address[](0)});
scopes[2] = SessionPolicy.CallScope({target: MYAPP, selectorRules: appRules});

bytes memory policyConfig = abi.encode(SessionPolicy.Config({tokenLimits: limits, callScopes: scopes}));
```

With that installed, the key may transfer any amount of the MyApp token, spend up to $5 of USDC per rolling month
(refreshing the next month), and call `stake` / `claim` on MyApp without limit — while a USDC transfer over budget
reverts `ExceededAllowance`, a third MyApp selector reverts `SelectorNotAllowed`, and any other contract reverts
`TargetNotAllowed`. Two choices to note: modeling "full token access" as *any selector* also permits `approve` /
`transferFrom` on that token (use a single `transfer` rule to restrict to transfers); and USDC is pinned to
`transfer` precisely so the cap is airtight. End-to-end test:
[`test_workedExample_fullTokenAccess_monthlyUsdc_appSelectors`](../../../test/unit/examples/SessionPolicy.t.sol).

### External callers (subscriptions)

The flows above are *account-acting*: a session key on the account transacts, the protocol dispatches as the
account, and `execute` learns the acting actor from the transaction-context precompile. But sometimes the actor
isn't a key on the account at all — e.g. a **subscription provider** that wants to make **one** batch call pulling
from many accounts, rather than each account running its own session key. For that, identity must come from the
caller, not the protocol.

`executeFor(account, policy, executionData)` is the external-caller entrypoint:

- **Identity is the caller:** `actorId = bytes20(msg.sender)`, and `account` is an explicit argument. The caller
  can't forge the identity because it's derived from `msg.sender`.
- **No protocol routing, so the manager re-checks itself:** it re-adds the `policy_manager(account, actorId) ==
  address(this)` check that the account-acting `execute` omits (the 8130 gate guarantees routing only on the
  dispatched path). So a provider can only pull through the exact manager the account authorized.
- **One identity, many accounts:** `executeForMany(accounts[], policy, executionData[])` runs each account in its
  own self-call so a single failure (revoked/expired binding, over budget, a reverting account call) is **isolated
  and skipped** (emitting `PullSkipped`) rather than reverting the whole batch — one delinquent subscriber doesn't
  block the rest.

**Opt-in (per account, once).** The account's only on-chain obligation is a single **off-chain signature** over an
actor change. Because `applySignedActorChanges` is signature-gated and `install` is permissionless (gated by the
signed commitment, not by `msg.sender`), the provider can submit everything itself — apply the signed change,
`install`, then `executeFor` — so the account never needs to send a transaction. The account authorizes the provider
as a *policy-only* actor — it has no authority of its own, it only carries a binding the manager enforces:

```solidity
// actorId = bytes20(provider). The provider never signs an 8130 tx; it acts by being msg.sender.
AccountConfiguration.ActorConfig({
    authenticator: EXTERNAL_POLICY_AUTHENTICATOR, // recognized actor; NO direct executeBatch; not 8130-usable
    scope:         0x02,                          // SCOPE_SENDER — required non-zero (a policy actor can't be scopeless),
                                                  //   but inert here since the sentinel can't authenticate a tx
    expiry:        0,
    policyType:    0x01                           // gated; policy_manager = manager, policy_commitment = own salt
});
```

Critically, the provider must **not** be registered with `TRUSTED_EXECUTOR` — that sentinel grants
*direct, unrestricted* `executeBatch` and would let the provider bypass the policy entirely. `EXTERNAL_POLICY_AUTHENTICATOR`
is a no-code sentinel: the actor is recognized (non-zero authenticator) but can neither drive the account directly
nor authenticate an 8130 transaction. Give the provider its **own salt** so its commitment — and therefore its
spend budget — is isolated from any session keys on the account. End-to-end tests:
[`ExternalPolicyCaller.t.sol`](../../../test/unit/examples/ExternalPolicyCaller.t.sol).

> Out of scope for this reference: signature-based install, replacement, and uninstall. See
> [base/account-policies](https://github.com/base/account-policies) for a fuller policy framework.
