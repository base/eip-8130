# Policies (EIP-8130 actor policies)

Self-executing policies for EIP-8130 restricted actors.

In EIP-8130, a restricted actor (e.g. a session key) is configured with optional 52-byte policy data
(`manager(20) || commitment(32)`) stored co-located with the 32-byte actor config, making an 84-byte packed
record. Length decides what gets stored; POLICY decides whether the sender is gated; OPERATOR overrides POLICY.
The protocol node gates on `scope & Scopes.POLICY != 0` and forces every call that actor makes to land on that
single `policy_manager`. In this reference the `policy_manager` **is the policy contract itself**: the policy is
its own manager. There is no separate manager contract and no per-ABI manager subclass. `Scopes.POLICY` (`0x08`)
is an optional grant. `Keystore` does not import or interpret scope bits; policy attachment is a length check
(empty vs 52).

## Flow

1. **Authorize + commit.** The account authorizes the session key with `scope = Scopes.POLICY`,
   `policy_manager = address(policy)`, and `policy_commitment = keccak256` of an account-authorized
   [`PolicyBinding`](./PolicyBinding.sol). The Keystore exposes this via
   [`getActorWithPolicy(account, actorId)`](../Keystore.sol) (or the granular `getPolicyManager` / `getPolicyCommitment`).
   That signed actor change *is* the authorization — there is no separate install step. The account also authorizes
   the policy as an execution-enabled actor so the policy may drive `executeBatch` (exactly as it would authorize any
   manager).
2. **Use.** When the session key transacts, the protocol gate resolves the key's allowed target
   (`policy_manager(account, actorId)`) and reverts any call whose `call.to` isn't that address before dispatch, so
   the key's call can only arrive at `Policy.execute(binding, executionData)` with `msg.sender == account`. The policy
   recomputes `commitment = keccak256(account, policy, keccak256(policyConfig), validAfter, validUntil, salt, transformer)`
   and requires it to equal the live `getPolicyCommitment(account, actorId)`, and requires itself to be the installed
   manager (`getActorWithPolicy(...).policyManager == address(this)`). That single commitment check authenticates
   config, validity window, owning account, and the chosen call encoder — so nothing stores a config hash (strictly
   better than [Account Policies](https://github.com/base/account-policies)' per-binding `_configHashByPolicyId` slot).
   A revoked *or expired* key reads back a zero commitment and stops immediately: `getPolicyCommitment` (like every
   Keystore read accessor) is liveness-gated. The policy then runs its rule, produces a wallet-agnostic call plan,
   encodes it into account calldata (by default `executeBatch(Call[])`; a non-zero `binding.transformer` selects an
   [`IPolicyCallEncoder`](../interfaces/IPolicyCallEncoder.sol) instead), forwards it, and runs `onPostExecute` when
   applicable.

```
session key ──(8130 gate: only the policy)──▶ Policy.execute
                                                 │  self-authenticates vs Keystore, runs rule, builds Call[]
                                                 │  encodes (default executeBatch; or binding.transformer)
                                                 ▼
                                             account.executeBatch ──▶ token / target
```

## Contracts

| Contract | Role |
|----------|------|
| `Policy` | Self-executing, manager-agnostic base: `execute` / `executeFor` / `executeForMany` resolve the acting actor, self-authenticate against the Keystore, run the policy rule (`_onExecute`), encode the call plan, forward it to the account, then `_onPostExecute`. Encoding lives in `_encodeFor` (default `executeBatch(Call[])`; a non-zero `binding.transformer` routes through an `IPolicyCallEncoder`). The policy is its own manager — one deployed instance is both the enforcement point and the account entrypoint. |
| `PolicyBinding` | Shared binding struct + `PolicyBindingLib.commitment`. The struct now carries a `transformer` field (address(0) = default encoding), bound into the commitment so the account authorizes exactly which encoder runs. |
| `IPolicy` | Use-time calling surface every self-executing policy exposes (`execute` / `executeFor` / `executeForMany` / `commitmentOf`), so external callers integrate against one interface regardless of the account's execution ABI. |
| `IPolicyCallEncoder` | Transformer interface: `encodeCalls(account, Call[]) view returns (bytes)`. Reached by STATICCALL, so it can be a shared per-ABI library contract or the account itself, but it never executes or holds authority. |
| `ERC7821Encoder` | Example `IPolicyCallEncoder` emitting ERC-7821 `execute(bytes32,bytes)` batch calldata — the template for a diverging wallet ABI. One deployed instance serves every ERC-7821 account. Replaces the old `ERC7821PolicyManager` subclass. |
| `IExecuteBatch` | The shared `Call` struct and the canonical default execution surface, in [`../interfaces/IExecuteBatch.sol`](../interfaces/IExecuteBatch.sol). |
| `SessionPolicy` | Unified "session key" policy: target / selector / recipient / spend limits enforced by linear scan over calldata config. Stores only spend usage. Validates config shape at execute. Inherits the self-executing `Policy` base unchanged. |
| `RecurringAllowance` | Periodic-allowance accounting library (ported from base/account-policies); used by `SessionPolicy` for spend accounting. |

A key that needs several independent bindings authorizes each separately (distinct commitments); the policy routes each by commitment.

### Wallet-agnostic execution: the policy decides *what*, the transformer decides *how*

Two concerns are separated so each scales independently:

- **The policy decides *what* to execute** and returns a wallet-agnostic `Call[]` (`(target, value, data)`). It never
  hardcodes wallet calldata and imports no account type.
- **The binding decides *how* to encode** for the account's execution ABI, via the committed `transformer`:

  ```solidity
  function _encodeFor(PolicyBinding calldata binding, Call[] memory calls) internal view returns (bytes memory) {
      if (binding.transformer == address(0)) return abi.encodeCall(IExecuteBatch.executeBatch, (calls));
      return IPolicyCallEncoder(binding.transformer).encodeCalls(binding.account, calls);
  }
  ```

  The default (`transformer == address(0)`) is `executeBatch(Call[])` — the surface shared by the EIP-8130
  `DefaultAccount` / `CanonicalHighRatePayerAccount` and common smart wallets (e.g. Coinbase Smart Wallet v2). A
  wallet with a different ABI names a transformer (e.g. [`ERC7821Encoder`](./ERC7821Encoder.sol)) in the binding.
  Because the transformer is folded into the commitment, the account authorizes exactly which encoder runs, and the
  encoder is a pure, staticcalled contract that can never escalate — it just formats calldata. This replaces the old
  "subclass the manager per ABI" model: one shared policy serves every wallet ABI, and supporting a new ABI means
  deploying one small stateless encoder (or having the account implement `IPolicyCallEncoder` itself).

**One shared policy, self-authenticating.** The policy does not trust a compile-time manager. On every call it
authenticates against the canonical Keystore: it requires itself to be the manager the account installed for the
acting actor (`getActorWithPolicy(account, actorId).policyManager == address(this)`), the binding to name this policy,
the binding to recompute to the actor's live signed commitment, and the validity window to be open — all before any
state mutation. Manager-style entrypoints share one `ReentrancyGuard` (the transaction-context actorId is global to
the transaction, and the policy now performs the account call itself). Implementations MUST fail closed: never
swallow a failed account forward, so a revert rolls back the policy's state mutation atomically.

### `SessionPolicy`: one policy, many dimensions

The policy validates exactly **one** binding per `execute` call, so authorizing several focused policies cannot
*jointly* gate the **same** call. `SessionPolicy` is the pattern for "this one call must satisfy target **and**
selector **and** recipient **and** spend-limit": each `_onExecute` validates config shape then scans the
authenticated calldata config. Only mutable spend usage lives onchain.

A **`TokenLimit` is the primary spend grant**: adding one for a token both caps it and, by itself, authorizes the
key to move it via the three tracked ERC-20 selectors (`transfer`, `transferFrom`, `approve`). Access resolves per
call:

- **Case 1 — `TokenLimit` alone** (no `CallScope`): the key may call only those three selectors on the token, each
  debited from the cap and gated by the limit's `recipients`. Nothing else on the token is callable.
- **Case 2 — `TokenLimit` + a `CallScope` with an empty selector list** (`anySelector`): the key may call *any*
  selector. The three tracked selectors stay debited/recipient-gated; every other selector is allowed but **not**
  debited — an explicit opt-in to untracked, value-moving methods (`increaseAllowance`, ERC-4626 `withdraw`, …).
- **Case 3 — `TokenLimit` + a `CallScope` with an explicit selector list**: exactly the listed selectors (tracked
  ones still debited/recipient-gated). An explicit list *replaces* the Case-1 default.

A `CallScope` on a target with **no** `TokenLimit` is a pure call allowlist (no spend semantics). Recipient gating
lives on the `TokenLimit`: for an ERC-20 it gates the decoded destination of the tracked selectors (`to` for
transfer/transferFrom, `spender` for approve — a deliberate merge); for native ETH (`token == address(0)`) it gates
the call `target`. Native value fails closed (a call carrying `value` reverts unless a native `TokenLimit` is set).
Recipient gating and spend accounting can only decode the hardcoded ERC-20 set, so `safeTransferFrom` and other
value-moving methods are never tracked — reachable only via the Case-2 / Case-3 opt-in.

#### Worked example

Configure one session key that (1) has full, uncapped access to one ERC-20 (the "MyApp" token), (2) may spend at
most **$5 of USDC per month**, and (3) may call the MyApp app contract as much as it wants, but only through two
chosen selectors. One spend limit + two call scopes:

```solidity
address MYAPP_TOKEN; // the "MyApp" ERC-20
address USDC;        // 6 decimals
address MYAPP;       // the MyApp app contract
bytes4  selStake = MyApp.stake.selector;
bytes4  selClaim = MyApp.claim.selector;

// Spend limits: ONLY USDC ($5/month) — a Case-1 grant. The limit alone authorizes the three tracked ERC-20
// selectors and caps every one of them, so the budget can't be sidestepped via approve/transferFrom. The MyApp
// token has no entry, so it is uncapped.
SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](1);
limits[0] = SessionPolicy.TokenLimit({token: USDC, limit: 5e6, period: 30 days, recipients: new address[](0)});

SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](2);

// (a) MyApp token: full access — empty selector list => any selector; no TokenLimit => no spend cap.
scopes[0] = SessionPolicy.CallScope({target: MYAPP_TOKEN, selectors: new bytes4[](0)});

// (b) MyApp contract: two chosen selectors, unlimited calls.
bytes4[] memory appSelectors = new bytes4[](2);
appSelectors[0] = selStake;
appSelectors[1] = selClaim;
scopes[1] = SessionPolicy.CallScope({target: MYAPP, selectors: appSelectors});

bytes memory policyConfig = abi.encode(SessionPolicy.Config({tokenLimits: limits, callScopes: scopes}));
```

With that authorized, the key may transfer any amount of the MyApp token, spend up to $5 of USDC per rolling month
(refreshing the next month), and call `stake` / `claim` on MyApp without limit — while a USDC transfer over budget
reverts `ExceededAllowance`, a third MyApp selector reverts `SelectorNotAllowed`, and any other contract reverts
`TargetNotAllowed`. End-to-end test:
[`test_workedExample_fullTokenAccess_monthlyUsdc_appSelectors`](../../../test/unit/policies/SessionPolicy.t.sol).

### External callers (subscriptions)

The flows above are *account-acting*: a session key on the account transacts, the protocol dispatches as the
account, and `execute` learns the acting actor from the transaction-context precompile. But sometimes the actor
isn't a key on the account at all — e.g. a **subscription provider** that wants to make **one** batch call pulling
from many accounts, rather than each account running its own session key. For that, identity must come from the
caller, not the protocol.

`executeFor(binding, executionData)` is the external-caller entrypoint:

- **Identity is the caller:** `actorId = ActorId.fromAddress(msg.sender)`, and `account` is a binding field. The
  caller can't forge the identity because it's derived from `msg.sender`.
- **No protocol routing, so the policy re-checks itself:** it re-adds the `policy_manager(account, actorId) ==
  address(this)` check that the account-acting `execute` shares (the 8130 gate guarantees routing only on the
  dispatched path). So a provider can only pull through the exact policy the account authorized.
- **One identity, many accounts:** `executeForMany(bindings[], executionData[])` runs each binding in its own
  self-call so a single failure is **isolated and skipped** (emitting `ExecutionSkipped`) rather than reverting the
  whole batch — one delinquent subscriber doesn't block the rest.

**Opt-in (per account, once).** The account's only onchain obligation is a single **off-chain signature** over an
actor change authorizing the provider as a *policy-only* actor — it has no authority of its own, it only carries a
binding the policy enforces:

```solidity
// actorId = ActorId.fromAddress(provider). The provider never signs an 8130 tx; it acts by being msg.sender.
Keystore.ActorConfig({
    authenticator: EXTERNAL_POLICY_AUTHENTICATOR, // recognized actor; NO direct executeBatch; not 8130-usable
    scope:         0x08,                          // Scopes.POLICY — gated initiation only
    expiry:        0
});
```

Critically, the provider must **not** be registered as an *operational* actor (admin scope `0x00` or `OPERATOR`) —
operational scope grants *direct, unrestricted* `executeBatch` and would let the provider bypass the policy
entirely. `EXTERNAL_POLICY_AUTHENTICATOR` (exported from [`Policy.sol`](./Policy.sol)) is a no-code sentinel: the
actor is recognized (non-zero authenticator) but can neither drive the account directly nor authenticate an 8130
transaction. Give the provider its **own salt** so its commitment — and therefore its spend budget — is isolated
from any session keys on the account. End-to-end tests:
[`ExternalPolicyCaller.t.sol`](../../../test/unit/policies/ExternalPolicyCaller.t.sol).

> Out of scope for this reference: signature-based replacement and uninstall. See
> [base/account-policies](https://github.com/base/account-policies) for a fuller policy framework.
