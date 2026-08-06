// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {console} from "forge-std/Test.sol";

import {Keystore} from "../../../src/Keystore.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";

import {KeystoreTest} from "../../lib/KeystoreTest.sol";
import {SessionMockERC20, SessionMockTarget} from "./SessionPolicy.t.sol";

/// @notice Gas benchmarks for the {SessionPolicy} / {PolicyManager} execution flows.
///
/// @dev Numbers are logged, not asserted, so this file never fails on chain-parameter drift; run with
///      `forge test --mt test_gas -vv` to print the report. Each measurement wraps only the `manager.execute`
///      call, so it captures the full production per-call path: manager dispatch (commitment reads), the policy
///      hook (including config validation), and the forwarded account `executeBatch` (including the ERC-20/native
///      transfer).
///
///      Caveats when reading these:
///        - The EIP-8130 transaction-context precompile is `vm.mockCall`-ed, so `_actingActorId`'s STATICCALL is
///          approximated by Foundry's mock, not the real precompile cost.
///        - "cold" cools (via `vm.cool`) every address the execute path touches before measuring, mirroring
///          production where authorization ran in an earlier transaction so all contracts/slots are cold at
///          execute time. "warm" is an immediate repeat call, isolating the marginal recompute cost. Production
///          calls are effectively always cold, so the cold number is the representative one.
///        - The per-flow `test_gas_execute_*` tests are authoritative: each runs in its own transaction. The
///          `test_gas_summary` table is an at-a-glance overview and reads a few k low, because `vm.cool` resets
///          access-list warmth but not EIP-2200 original-value (dirty-slot) pricing, which is fixed per tx.
contract SessionPolicyGasTest is KeystoreTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;
    SessionMockERC20 internal token;
    SessionMockTarget internal target;

    address internal account;
    address internal bob = address(0xB0B);

    uint256 internal constant ROOT_PK = 0xA11CE;
    uint8 internal constant SCOPE_POLICY = 0x02;

    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    uint40 internal constant WEEK = 7 days;

    uint256 internal saltNonce;
    PolicyManager.PolicyBinding internal lastBinding;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(keystore));
        policy = new SessionPolicy(address(manager));
        token = new SessionMockERC20();
        target = new SessionMockTarget();

        account = _createAccountWithRootAndManager();
        token.mint(account, 1_000_000e18);
        vm.deal(account, 100 ether);
    }

    // ── Execute: gating dimensions in isolation (no spend accounting) ──

    function test_gas_execute_targetOnly_anySelector() public {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(address(target));
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        bytes memory ed = _action(address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (42)));
        emit log_named_uint("execute: target allowlist only (anySelector), cold", _measureCold(actorId, ed));
        emit log_named_uint("execute: target allowlist only (anySelector), warm", _measure(actorId, ed));
    }

    function test_gas_execute_selectorGating() public {
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] =
            SessionPolicy.SelectorRule({selector: SessionMockTarget.setValue.selector, recipients: _noRecipients()});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(target), selectorRules: rules});
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        bytes memory ed = _action(address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (7)));
        emit log_named_uint("execute: target + selector gating, cold", _measureCold(actorId, ed));
        emit log_named_uint("execute: target + selector gating, warm", _measure(actorId, ed));
    }

    function test_gas_execute_recipientGating_noLimit() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        bytes32 actorId = _install(_config(_noLimits(), _erc20Scope(address(token), recipients)));

        bytes memory ed = _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1e18)));
        emit log_named_uint("execute: target + selector + recipient gating (no limit), cold", _measureCold(actorId, ed));
        emit log_named_uint("execute: target + selector + recipient gating (no limit), warm", _measure(actorId, ed));
    }

    // ── Execute: spend-limit accounting (the only path with an SSTORE on the happy path) ──

    function test_gas_execute_spendLimitOnly() public {
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), _noRecipients())));

        // Cold: first spend allocates the period-usage slot (zero -> non-zero SSTORE).
        bytes memory ed = _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1e18)));
        emit log_named_uint("execute: spend limit only, cold (period alloc)", _measureCold(actorId, ed));
        // Warm: same period, updates the existing slot (non-zero -> non-zero SSTORE).
        emit log_named_uint("execute: spend limit only, warm (period update)", _measure(actorId, ed));
    }

    function test_gas_execute_spendLimit_plus_recipientGating() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), recipients)));

        bytes memory ed = _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1e18)));
        emit log_named_uint("execute: spend limit + recipient gating, cold", _measureCold(actorId, ed));
        emit log_named_uint("execute: spend limit + recipient gating, warm", _measure(actorId, ed));
    }

    function test_gas_execute_nativeEthLimit() public {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(bob);
        bytes32 actorId = _install(_config(_limit(address(0), 10 ether, WEEK), scopes));

        bytes memory ed = _action(bob, 0.1 ether, "");
        emit log_named_uint("execute: native-ETH limit, cold (period alloc)", _measureCold(actorId, ed));
        emit log_named_uint("execute: native-ETH limit, warm (period update)", _measure(actorId, ed));
    }

    // ── Summary table ──

    function test_gas_summary() public {
        console.log("");
        console.log("=== EIP-8130 SessionPolicy / PolicyManager Gas Benchmark ===");
        console.log("");
        console.log("  Flow                                              Cold      Warm");
        console.log("  ----------------------------------------------------------------");

        // Each row deploys its own fresh mock target/token so storage values (e.g. `target.value`, token balances)
        // never bleed across rows and change SSTORE zero/non-zero pricing — matching the standalone tests above.
        {
            SessionMockTarget t = new SessionMockTarget();
            SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
            scopes[0] = _anySelectorScope(address(t));
            bytes32 a = _install(_config(_noLimits(), scopes));
            _row(
                "target allowlist only (anySelector) ",
                a,
                _action(address(t), 0, abi.encodeCall(SessionMockTarget.setValue, (42)))
            );
        }
        {
            SessionMockTarget t = new SessionMockTarget();
            SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
            rules[0] = SessionPolicy.SelectorRule({
                selector: SessionMockTarget.setValue.selector, recipients: _noRecipients()
            });
            SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
            scopes[0] = SessionPolicy.CallScope({target: address(t), selectorRules: rules});
            bytes32 a = _install(_config(_noLimits(), scopes));
            _row(
                "target + selector gating            ",
                a,
                _action(address(t), 0, abi.encodeCall(SessionMockTarget.setValue, (7)))
            );
        }
        {
            address[] memory recipients = new address[](1);
            recipients[0] = bob;
            SessionMockERC20 tk = _freshToken();
            bytes32 a = _install(_config(_noLimits(), _erc20Scope(address(tk), recipients)));
            _row(
                "target + selector + recipient       ",
                a,
                _action(address(tk), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1e18)))
            );
        }
        {
            SessionMockERC20 tk = _freshToken();
            bytes32 a = _install(_config(_limit(address(tk), 500e18, WEEK), _erc20Scope(address(tk), _noRecipients())));
            _row(
                "spend limit only (transfer)         ",
                a,
                _action(address(tk), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1e18)))
            );
        }
        {
            address[] memory recipients = new address[](1);
            recipients[0] = bob;
            SessionMockERC20 tk = _freshToken();
            bytes32 a = _install(_config(_limit(address(tk), 500e18, WEEK), _erc20Scope(address(tk), recipients)));
            _row(
                "spend limit + recipient gating      ",
                a,
                _action(address(tk), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1e18)))
            );
        }
        {
            SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
            scopes[0] = _anySelectorScope(bob);
            bytes32 a = _install(_config(_limit(address(0), 10 ether, WEEK), scopes));
            _row("native-ETH limit                    ", a, _action(bob, 0.1 ether, ""));
        }

        console.log("  ----------------------------------------------------------------");
        console.log("");
        console.log("  Cold = execute with all touched addresses cooled (~production: authorize in a prior tx)");
        console.log("  Warm = immediate repeat call in the same tx (marginal recompute cost)");
        console.log("  Path = manager dispatch + policy hook + account executeBatch + transfer");
        console.log("  Note: overview only. The per-flow test_gas_execute_* tests each run in their own tx and are");
        console.log("        the authoritative cold numbers; this table reads a few k low because vm.cool cannot");
        console.log("        reset EIP-2200 original-value pricing mid-tx. Precompile is mocked.");
        console.log("");
    }

    /// @dev A fresh mock ERC-20 minted to the account, so each flow's spend accounting starts from clean storage.
    function _freshToken() internal returns (SessionMockERC20 tk) {
        tk = new SessionMockERC20();
        tk.mint(account, 1_000_000e18);
    }

    /// @dev Print one summary row: `label`, cold (all touched addresses cooled first, mirroring a production
    ///      execute in a separate tx from authorization) and warm (immediate repeat) `execute` cost.
    function _row(string memory label, bytes32 actorId, bytes memory ed) internal {
        uint256 cold = _measureCold(actorId, ed);
        uint256 warm = _measure(actorId, ed);
        console.log(string.concat("  ", label, _pad(cold), "    ", _pad(warm)));
    }

    function _pad(uint256 n) internal pure returns (string memory) {
        return _leftPad(vm.toString(n), 6);
    }

    function _leftPad(string memory s, uint256 width) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length >= width) return s;
        bytes memory padded = new bytes(width);
        uint256 offset = width - b.length;
        for (uint256 i; i < width; i++) {
            padded[i] = i < offset ? bytes1(" ") : b[i - offset];
        }
        return string(padded);
    }

    // ── Helpers ──

    /// @dev Mock the acting actor, then measure gas consumed by a single `manager.execute`.
    function _measure(bytes32 actorId, bytes memory executionData) internal returns (uint256 used) {
        _mockActingActor(actorId);
        vm.prank(account);
        uint256 g = gasleft();
        manager.execute(lastBinding, executionData);
        used = g - gasleft();
    }

    /// @dev Production-representative cold measurement: cool every address the execute path touches so their first
    ///      access pays the EIP-2929 cold cost, as it would when execute runs in a separate tx from authorization.
    function _measureCold(bytes32 actorId, bytes memory executionData) internal returns (uint256) {
        _coolAll(executionData);
        return _measure(actorId, executionData);
    }

    /// @dev Reset the warm/cold access state of every contract and account the execute path reads or calls. The call
    ///      target is decoded from the action so this works for the per-row fresh mocks in the summary too.
    function _coolAll(bytes memory executionData) internal {
        vm.cool(account);
        vm.cool(address(policy));
        vm.cool(address(manager));
        vm.cool(address(keystore));
        vm.cool(bob);
        SessionPolicy.Action memory action = abi.decode(executionData, (SessionPolicy.Action));
        vm.cool(action.target);
    }

    function _mockActingActor(bytes32 actorId) internal {
        vm.mockCall(
            TX_CONTEXT_ADDRESS,
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector),
            abi.encode(actorId)
        );
    }

    function _action(address t, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encode(SessionPolicy.Action({target: t, value: value, data: data}));
    }

    function _config(SessionPolicy.TokenLimit[] memory limits, SessionPolicy.CallScope[] memory scopes)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(SessionPolicy.Config({tokenLimits: limits, callScopes: scopes}));
    }

    function _noLimits() internal pure returns (SessionPolicy.TokenLimit[] memory) {
        return new SessionPolicy.TokenLimit[](0);
    }

    function _limit(address tkn, uint256 lim, uint40 period)
        internal
        pure
        returns (SessionPolicy.TokenLimit[] memory limits)
    {
        limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = SessionPolicy.TokenLimit({token: tkn, limit: lim, period: period});
    }

    function _noRecipients() internal pure returns (address[] memory) {
        return new address[](0);
    }

    function _anySelectorScope(address t) internal pure returns (SessionPolicy.CallScope memory) {
        return SessionPolicy.CallScope({target: t, selectorRules: new SessionPolicy.SelectorRule[](0)});
    }

    function _erc20Scope(address tkn, address[] memory recipients)
        internal
        pure
        returns (SessionPolicy.CallScope[] memory scopes)
    {
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] = SessionPolicy.SelectorRule({selector: TRANSFER, recipients: recipients});
        scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: tkn, selectorRules: rules});
    }

    function _createAccountWithRootAndManager() internal returns (address) {
        Keystore.InitialActor memory root = Keystore.InitialActor({
            actorId: bytes32(bytes20(vm.addr(ROOT_PK))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
        Keystore.InitialActor memory mgr = Keystore.InitialActor({
            actorId: bytes32(bytes20(address(manager))), authenticator: TRUSTED_EXECUTOR, scope: 0, policyData: ""
        });

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return keystore.createAccount(bytes32(0), bytecode, actors);
    }

    function _install(bytes memory policyConfig) internal returns (bytes32 actorId) {
        PolicyManager.PolicyBinding memory binding;
        (actorId, binding) = _prepareBinding(policyConfig);
        lastBinding = binding;
    }

    function _prepareBinding(bytes memory policyConfig)
        internal
        returns (bytes32 actorId, PolicyManager.PolicyBinding memory binding)
    {
        actorId = keccak256(abi.encode("session", saltNonce++));
        binding = PolicyManager.PolicyBinding({
            account: account,
            policy: address(policy),
            policyConfig: policyConfig,
            validAfter: 0,
            validUntil: 0,
            salt: saltNonce
        });
        bytes32 commitment = manager.commitmentOf(binding);

        Keystore.ActorConfig memory cfg =
            Keystore.ActorConfig({authenticator: address(k1Authenticator), scope: SCOPE_POLICY, expiry: 0});
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: actorId,
            changeType: Keystore.ActorChangeType.Authorize,
            data: abi.encode(cfg, abi.encodePacked(address(manager), commitment))
        });
        uint64 chainId = uint64(block.chainid);
        uint64 sequence = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        keystore.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }
}
