# Account-first policy execution, without selector gating

Exploration draft, not a deployment recommendation. This stacks on [#110](https://github.com/base/eip-8130/pull/110) and explores an alternative to [#111](https://github.com/base/eip-8130/pull/111): retain the address-only protocol gate and make account authorization actor-aware.

Implementation: [`NativePolicyAccount.sol`](./NativePolicyAccount.sol). Tests and an example conditional account extension: [`NativePolicyAccount.t.sol`](../../test/unit/accounts/NativePolicyAccount.t.sol).

## Proposed boundary

The protocol authenticates transaction actors and restricts policy-scoped initiation to the installed manager address. A policy-native account sets that manager address to itself. The account authenticates the actor and signed binding, calls the reusable policy, and executes its returned `Call[]` internally. No separate manager actor, wallet-ABI transformer, external execution callback, or protocol selector rule is needed.

A supplied binding includes the policy address, account, config, validity window, and salt. Its commitment authenticates the policy address before any policy code is called; a separate policy-address storage field is unnecessary. Checking only inside `Policy.onExecute` would be insufficient: an attacker-supplied contract could simply omit that check.

This does not remove the manager field. Accounts that need compatibility adapters can keep using #110's external managers, and the same shared policy contracts can serve both architectures.

## Session-key flow

```text
Keystore authorizes key with:
  expiry, POLICY scope, manager = account, commitment = hash(binding)

Key submits an 8130 transaction as the account
  Protocol constrains call.to to the account (no selector gate)

Account.execute(binding, executionData):
  require msg.sender == account
  require transaction-context sender == account
  read authenticated senderActorId
  look up the live actor and policy binding in Keystore
  require a restricted POLICY actor, manager == account, matching commitment/window

Account calls binding.policy.onExecute(binding, actorId, executionData, account)
Policy independently authenticates its binding, enforces rules, and returns calls
Account executes the calls internally through shared execution safeguards
Account calls policy.onPostExecute; failure rolls the entire invocation back
```

The policy session entrypoint deliberately accepts restricted POLICY actors, not OPERATOR | POLICY (which the existing scope rules treat as unrestricted). Operational actors use the operational entrypoints instead.

## External subscription flow

```text
Keystore authorizes runner with:
  EXTERNAL_POLICY_AUTHENTICATOR, expiry, manager = account, commitment
  No operational scope is granted; the marker is not a signing authenticator

Runner calls Account.executeFor(binding, executionData):
  derive actorId from msg.sender, not tx.origin or transaction-context actor
  require a live external-caller permission
  require manager == account and matching account/commitment/window

Account calls policy.onExecute with the authenticated runner as caller
Policy enforces the subscription and returns calls
Account executes internally, then invokes the policy post-check
```

The external path works without the 8130 context precompile. A contract runner may batch calls to many accounts itself. A separate router changes `msg.sender` and must itself be authorized; the account never accepts an unauthenticated forwarded-caller argument. There is one actor slot per runner address per account in this prototype. Independent subscriptions from one runner require composition or a separately designed permission-ID scheme; a binding salt alone does not create extra actor slots.

The account implements the single-account `execute(PolicyBinding,bytes)`, `executeFor`, and `commitmentOf` conventions from `IPolicyManager`. It intentionally does **not** claim full interface conformance or implement `executeForMany`: cross-account batching and authenticated forwarding remain separate design work.

## Operational and conditional account functions

Self-caller status alone does not authorize execution. `onlyOperationalActor` resolves a live actor and requires admin or OPERATOR scope. Missing, revoked, or expired actors resolve to an empty config; its zero scope must not be mistaken for admin. `onlyAdminActor` additionally requires scope zero. External operational callers retain DefaultAccount's k1-only authorization rule.

An operational function can perform custom account-state writes and conditional execution:

```solidity
function conditional(Call calldata primary, Call calldata recovery)
    external onlyOperationalActor nonReentrant
{
    (bool success,) = _tryExecuteCall(primary);
    if (!success) {
        ++fallbackCount;
        _executeCall(recovery);
    }
}
```

The account authorizes once on entry, not for every internal operation. Both outgoing calls originate from the account. `_tryExecuteCall` preserves transfer safeguards while returning a destination failure for recovery; account-invariant failures still revert.

A restricted key cannot directly call `execute`, `executeBatch`, or this conditional function. A policy returning a self-call to a privileged function does not elevate the actor. Every mutating execution entrypoint uses the same reentrancy guard; policy plans execute internally rather than calling the account's external executor. Extensions must apply the appropriate authorization and guard to every new privileged function.

## Execution invariants and trust

- Single calls, batches, policy plans, and conditional extension calls share `_tryExecuteCall`. It checks the current account lock before each nonzero-value call, matching the existing high-rate payer account's outbound-value restriction. This is a **native ETH outflow guard, not an asset freeze**: authorized zero-value token calls remain possible. This prototype is **not** claimed to qualify for high-rate payer admission.
- The policy hook, all approved calls, and post-check share one revert boundary. A failed call/post-check rolls back policy usage and prior calls. Empty plans keep the existing PolicyManager semantics: no execution, post-hook, or execution event (the policy's successful hook state changes remain).
- Only `CALL` plans are supported; no policy-supplied `DELEGATECALL` or temporary root-authority flag.
- Live Keystore state is read at authorization time, not a cached scope snapshot. Account authorization and shared-policy self-authentication both check installed bindings. Revocation in another transaction is effective on the next invocation. A successful post-hook also re-authenticates through the existing Policy contract.
- An installed policy is trusted to enforce its committed rules. A malicious/upgraded policy can return arbitrary calls within the executor's capabilities; use audited policy implementations and treat upgrades as authority changes.
- Transaction context is not a per-frame capability. Self-path authorization also requires the account caller and matching transaction sender. External invocations cannot borrow an unrelated transaction's root actor.
- ERC-1271 and token-receiver handling are inherited unchanged. No existing account implementation or deployment address is modified.

## Warm authorization cost

The intended baseline is warm Keystore address and calling actor config after protocol authentication. The policy benchmark explicitly warms policy metadata too; one warm slot does not implicitly warm adjacent slots.

Run:

```bash
forge test --match-contract NativePolicyAccountTest --match-test test_gas -vv
```

`test_gas_warmOperationalAuthorization` compares an operational authorization probe with a self-caller-only probe on the same ERC-1167 account. It warms both code paths and the actor config before measuring, excludes execution/reentrancy-guard work, and logs the incremental authority-check cost. The scope bit test is cheap; the context getters, Keystore call, ABI work, and liveness check account for the difference.

`test_gas_warmPolicyExecution` measures a repeat execution using the test plan policy, warm binding metadata, and dirty usage/target slots. It is not a cold first-use subscription quote or a comparison with external managers.

Both measurements use `vm.mockCall` for transaction context. They measure the Solidity paths under Foundry, **not the client's precompile body pricing**, and are not consensus gas estimates. End-to-end node measurements are still required. Exposing a validated scope in transaction context could avoid a live lookup, but that would require specifying snapshot-versus-live revocation semantics.

Local observation with Forge 1.5.1, Solidity 0.8.36, optimizer + via-IR, Osaka: the warm operational probe used 5,499 gas versus 1,074 for the self-only probe, an incremental **4,425 gas** under the mocked-context setup. The repeat policy execution measured 32,107 gas with dirty counters. These are harness-specific observations, not protocol pricing or a claim that account-first beats policy-first.

## Alternatives and launch separation

| Architecture | Benefit | Cost |
| --- | --- | --- |
| Account-first (this spike) | Identity resolution and execution stay together; ordinary EVM traces; no callback grant | Privileged self-calls must inspect actor authority; post-check is another policy call |
| Policy-first with account callback | Restricted keys do not directly enter the account; policy naturally resumes after execution | New authenticated callback carrying actor/binding; policy establishes initiating identity |
| Protocol executes policy-returned calls | No account bytecode or ABI translation on execution path | Explicit delegated execution authority/context, atomicity, tracing and external-runner semantics become protocol work |

With a future `value` field in protocol calls, ordinary unrestricted transfers could bypass the account executor entirely. Operational account code would remain useful for stateful or conditional logic. Restricted actors would need a protocol-level zero-value rule so their transfers remain policy-controlled. The gas-paying scopes are separate: SELF_PAYER can still spend account ETH on gas.

This draft does **not** add `value` to protocol calls, remove automatic default-account delegation, change Keystore storage, expose scope in transaction context, or implement protocol-driven call plans. Those remain separate decisions for a transaction-first / Keystore-later rollout. Direct protocol value would require revisiting any payer solvency invariant that depends on all ETH outflows passing through wallet code.

## Questions for the spike

- Is actor-aware account authorization preferable to #111's protocol-enforced selector gate once the warm path is measured on a client?
- Should the common use-time standard separate per-account execution from cross-account batching?
- Do we need multiple independently revocable external permissions for one caller, and what identifies them?
- How should shared policies with cross-account mutable state guard reentrancy? The per-account guard does not replace their own state-specific protections.
- What migration/adapter surface is needed for wallets that retain unconditional self-call authorization? This account must not be treated as a drop-in behavior-preserving replacement.
