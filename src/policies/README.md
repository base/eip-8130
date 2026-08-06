# Example Policies (EIP-8130 actor policies)

Reference, **unaudited** example of a policy manager for EIP-8130 restricted actors.

In EIP-8130, a restricted actor (e.g. a session key) is configured with `scope & SCOPE_POLICY != 0`, which stores a
`policy_manager` address and an opaque `policy_commitment` in the Keystore contract. The protocol
gate forces every call that actor makes to land on that single manager. These contracts are an example of what
that manager can be: one that enforces application-specific limits and then drives the account. `SCOPE_POLICY`
(`0x02`) may be combined with other scope bits (e.g. `SCOPE_POLICY | SCOPE_SELF_PAYER`) — `Keystore` does
not reject scope combinations; use-time exclusivity between policy gating and an actor's other capabilities is
protocol-side, not enforced by this contract.

## Flow

1. **Authorize + commit.** The account authorizes the session key with `scope = SCOPE_POLICY`,
   `policy_manager = PolicyManager`, and `policy_commitment = keccak256` of an account-authorized
   [`PolicyBinding`](./PolicyManager.sol). The Keystore contract exposes this via
   [`getPolicy(account, actorId)`](../../Keystore.sol). That signed actor change *is* the
   authorization — there is no separate install step on the manager.
2. **Use.** When the session key transacts, the protocol gate resolves the key's allowed target
   (`policy_manager(account, actorId)`) and reverts any call whose `call.to` isn't that address before dispatch, so
   the key's call can only arrive at `PolicyManager.execute(binding, executionData)` with `msg.sender == account`.
   The caller supplies the full [`PolicyBinding`](./PolicyManager.sol); the manager recomputes
   `commitment = keccak256(account, policy, keccak256(policyConfig), validAfter, validUntil, salt)` and requires it
   to equal the live `getPolicyCommitment(account, actorId)`. That single check authenticates config, validity
   window, and owning account — so neither the manager nor the policy stores a config hash (strictly better than
   [Account Policies](https://github.com/base/account-policies)' per-binding `_configHashByPolicyId` slot). A
   revoked key has a zero commitment and stops immediately. Actor expiry is not re-checked on this path: protocol
   authentication already rejects expired actors before dispatch. (The external `executeFor` path does enforce
   expiry.) The manager then invokes the policy, forwards a non-empty `executeBatch` plan to the account, and
   calls `onPostExecute` when applicable.

```
session key ──(8130 gate: only PolicyManager)──▶ PolicyManager.execute
                                                     │  policy enforces commitment
                                                     ▼
                                                 account.executeBatch ──▶ token / target
```

## Contracts

| Contract | Role |
|----------|------|
| `PolicyManager` | Stateless manager: `execute(binding, …)` / `executeFor(binding, …)` / `executeForMany(bindings[], …)` re-authenticate the full binding against the live signed commitment in Keystore, then run policy → account call → `onPostExecute`. |
| `Policy` | Base hook: `onExecute` → `(accountCallData, postCallData)` + `onPostExecute` (default no-op). |
| `SessionPolicy` | Unified "session key" policy: target / selector / recipient / spend limits enforced by linear scan over calldata config. Stores only spend usage. Validates config shape at execute. |
| `RecurringAllowance` | Periodic-allowance accounting library (ported from base/account-policies); used by `SessionPolicy` for spend accounting. |

A key that needs several independent bindings authorizes each separately (distinct commitments); the manager routes each by commitment.

### `SessionPolicy`: one policy, many dimensions

The manager validates exactly **one** binding per `execute` call, so authorizing several focused policies cannot
*jointly* gate the **same** call. `SessionPolicy` is the pattern for "this one call must satisfy target **and**
selector **and** recipient **and** spend-limit": each `onExecute` validates config shape then scans the
authenticated calldata config. Only mutable spend usage lives onchain.

Recipient allowlists and spend-limit accounting require decoding a call's arguments, which is only possible for
selectors whose ABI is known: `SessionPolicy` hardcodes the standard ERC-20 set (`transfer`, `transferFrom`,
`approve`). A recipient allowlist may only be attached to one of those (enforced at execute); spend limits are
consumed for those selectors on a limited token (`approve` included, so an allowance cannot exceed the remaining
budget), native-ETH limits from each call's `value`, and every other selector is governed by target/selector gating
alone. `anySelector` on a limited token is rejected at execute — pin an explicit selector allowlist instead.

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

With that authorized, the key may transfer any amount of the MyApp token, spend up to $5 of USDC per rolling month
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

`executeFor(binding, executionData)` is the external-caller entrypoint:

- **Identity is the caller:** `actorId = bytes20(msg.sender)`, and `account` is an explicit argument. The caller
  can't forge the identity because it's derived from `msg.sender`.
- **No protocol routing, so the manager re-checks itself:** it re-adds the `policy_manager(account, actorId) ==
  address(this)` check that the account-acting `execute` omits (the 8130 gate guarantees routing only on the
  dispatched path). So a provider can only pull through the exact manager the account authorized.
- **One identity, many accounts:** `executeForMany(bindings[], executionData[])` runs each binding in its own
  self-call so a single failure is **isolated and skipped** (emitting `ExecutionSkipped`) rather than reverting the
  whole batch — one delinquent subscriber doesn't block the rest.

**Opt-in (per account, once).** The account's only on-chain obligation is a single **off-chain signature** over an
actor change. Because `applySignedActorChanges` is signature-gated, the provider can submit the signed change and
then `executeFor` — so the account never needs to send a transaction. The account authorizes the provider as a
*policy-only* actor — it has no authority of its own, it only carries a binding the manager enforces:

```solidity
// actorId = bytes20(provider). The provider never signs an 8130 tx; it acts by being msg.sender.
Keystore.ActorConfig({
    authenticator: EXTERNAL_POLICY_AUTHENTICATOR, // recognized actor; NO direct executeBatch; not 8130-usable
    scope:         0x02,                          // SCOPE_POLICY — gated initiation only (MAY also OR SCOPE_SELF_PAYER
                                                  //   for self-pay; SHOULD NOT combine with SENDER — POLICY gates
                                                  //   regardless, so SENDER adds no authority the protocol will honor)
    expiry:        0
});
```

`SCOPE_NONCE` (`0x04`) is a separate, orthogonal scope bit: it permits a restricted actor to use sequenced
`nonce_key`s. This contract stores the bit verbatim and never interprets it — nonce semantics are entirely
protocol-side — so it isn't part of the policy flow above and is only mentioned here for completeness.

Critically, the provider must **not** be registered with `TRUSTED_EXECUTOR` — that sentinel grants
*direct, unrestricted* `executeBatch` and would let the provider bypass the policy entirely. `EXTERNAL_POLICY_AUTHENTICATOR`
is a no-code sentinel: the actor is recognized (non-zero authenticator) but can neither drive the account directly
nor authenticate an 8130 transaction. Give the provider its **own salt** so its commitment — and therefore its
spend budget — is isolated from any session keys on the account. End-to-end tests:
[`ExternalPolicyCaller.t.sol`](../../../test/unit/examples/ExternalPolicyCaller.t.sol).

> Out of scope for this reference: signature-based replacement and uninstall. See
> [base/account-policies](https://github.com/base/account-policies) for a fuller policy framework.
