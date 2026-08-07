// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultAccount, Call} from "../../../src/accounts/DefaultAccount.sol";
import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @dev Minimal call target: a payable state setter plus reverters that fail with a string reason, a custom error, or
///      no returndata at all — used to exercise the success and failure legs of the low-level call inside
///      execute/executeBatch and to verify revert-reason bubbling.
contract MockTarget {
    uint256 public value;

    /// @dev Custom error used to check that non-string revert reasons bubble up verbatim.
    error Boom(uint256 code);

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external payable {
        revert("boom");
    }

    function revertingCustom(uint256 code) external pure {
        revert Boom(code);
    }

    /// @dev Reverts with empty returndata; the bubbled revert therefore carries no reason.
    function revertingSilent() external pure {
        revert();
    }
}

contract DefaultAccountTest is KeystoreTest {
    uint256 constant ACTOR_PK = 100;

    // ERC-1271 magic values returned by isValidSignature.
    bytes4 constant ERC1271_MAGIC = 0x1626ba7e;
    bytes4 constant ERC1271_FAIL = 0xFFFFFFFF;

    // Scope bits: ERC-1271 signing is operational (admin scope == 0x00, or SENDER without POLICY). SELF_PAYER and
    // SPONSOR_PAYER are non-SENDER capability scopes that are not operational on their own.
    uint16 constant SCOPE_SENDER = 0x01;
    uint16 constant SCOPE_SELF_PAYER = 0x08;
    uint16 constant SCOPE_SPONSOR_PAYER = 0x10;

    // TRUSTED_EXECUTOR sentinel: the authenticator value that marks an actor as a direct-execution caller.
    address constant TRUSTED_EXECUTOR = address(uint160(uint256(keccak256("trustedExecutor"))));

    MockTarget public target;

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    // _authorizeActor and _authorizeActorWithScope are provided by the KeystoreTest harness (re-implemented on
    // applySignedAccountChanges, granting UNBOUNDED on a sequenced local batch). TRUSTED_EXECUTOR and scoped k1
    // actors are registered through those helpers.

    // ══════════════════════════════════════════════
    //  executeBatch — reverts (source order)
    // ══════════════════════════════════════════════

    /// @notice Any caller that is neither the account itself nor a registered trusted executor reverts.
    /// @dev Exercises the false leg of `require(_isAuthorizedCaller(msg.sender))`; fuzzes caller/value/data.
    function test_executeBatch_revert_unauthorizedCaller(address caller, uint256 value, bytes calldata data) public {
        (address account,) = _createK1Account(ACTOR_PK);
        vm.assume(caller != account);
        value = bound(value, 0, type(uint128).max);

        vm.prank(caller);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        DefaultAccount(payable(account)).executeBatch(_singleCall(address(target), value, data));
    }

    /// @notice The account owner's own EOA key holder cannot drive executeBatch directly.
    /// @dev The owner is a k1 actor (authenticator == K1), not TRUSTED_EXECUTOR, so _isAuthorizedCaller is false.
    function test_executeBatch_revert_ownerEoaCallerUnauthorized(uint256 pkSeed) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1Account(pk);
        address owner = vm.addr(pk);
        vm.assume(owner != account);

        vm.prank(owner);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    /// @notice A registered actor whose authenticator is K1 (not the TRUSTED_EXECUTOR sentinel) cannot call.
    /// @dev Only the TRUSTED_EXECUTOR sentinel authorizes calls; an ordinary k1 actor does not.
    function test_executeBatch_revert_nonExecutorActorCaller(uint256 actorSeed) public {
        (address account,) = _createK1Account(ACTOR_PK);

        uint256 actorPk = _boundK1Pk(actorSeed);
        address actor = vm.addr(actorPk);
        vm.assume(actor != account && actor != vm.addr(ACTOR_PK));

        // Register `actor` as an ordinary k1 actor (authenticator == K1_AUTHENTICATOR), NOT a trusted executor.
        _authorizeActor(account, ACTOR_PK, bytes32(uint256(uint160(actor))), k1Authenticator);

        vm.prank(actor);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    /// @notice A failing inner call aborts the whole batch, bubbling the inner revert reason verbatim.
    /// @dev Exercises the failure leg of the low-level call; fuzzes the ETH value carried by the failing call.
    function test_executeBatch_revert_bubblesInnerRevert(uint256 value) public {
        (address account,) = _createK1Account(ACTOR_PK);
        value = bound(value, 0, 1e24);
        vm.deal(account, value);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "boom"));
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), value, abi.encodeCall(MockTarget.reverting, ())));
    }

    /// @notice A failing inner call with empty returndata bubbles up as a reason-less (empty) revert.
    function test_executeBatch_revert_emptyReturndataBubblesEmptyRevert() public {
        (address account,) = _createK1Account(ACTOR_PK);

        vm.prank(account);
        vm.expectRevert(bytes(""));
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.revertingSilent, ())));
    }

    /// @notice A failed call late in the batch rolls back state written by earlier successful calls.
    /// @dev The whole executeBatch reverts, so the earlier setValue is rolled back.
    function test_executeBatch_revert_failedInnerCallRollsBackPriorState(uint256 v) public {
        (address account,) = _createK1Account(ACTOR_PK);
        v = bound(v, 1, type(uint256).max); // non-zero so the rollback assertion is meaningful

        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), 0, abi.encodeCall(MockTarget.setValue, (v)));
        calls[1] = Call(address(target), 0, abi.encodeCall(MockTarget.reverting, ()));

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "boom"));
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 0);
    }

    // ══════════════════════════════════════════════
    //  executeBatch — happy paths
    // ══════════════════════════════════════════════

    /// @notice An empty calls array succeeds without entering the loop body.
    /// @dev Covers the loop-not-entered branch: authorization passes and no inner call is made.
    function test_executeBatch_success_emptyCalls() public {
        (address account,) = _createK1Account(ACTOR_PK);

        Call[] memory calls = new Call[](0);
        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 0);
    }

    /// @notice The account calling itself executes a single inner call.
    /// @dev Covers the `caller == address(this)` authorization branch and one successful loop iteration.
    function test_executeBatch_success_selfCaller(uint256 v) public {
        (address account,) = _createK1Account(ACTOR_PK);

        vm.prank(account);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (v))));

        assertEq(target.value(), v);
    }

    /// @notice Executing a call that forwards ETH transfers the value to the target.
    /// @dev Fuzzes the forwarded amount bounded to the account balance; confirms `call{value:}` wiring.
    function test_executeBatch_success_withETHValue(uint256 amount) public {
        (address account,) = _createK1Account(ACTOR_PK);
        amount = bound(amount, 0, 1e30);
        vm.deal(account, amount);

        vm.prank(account);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), amount, abi.encodeCall(MockTarget.setValue, (7))));

        assertEq(address(target).balance, amount);
        assertEq(account.balance, 0);
        assertEq(target.value(), 7);
    }

    /// @notice A batch with multiple calls executes every element in order.
    /// @dev Covers the loop iterating more than once across two distinct targets with fuzzed values.
    function test_executeBatch_success_multipleCalls(uint256 a, uint256 b) public {
        (address account,) = _createK1Account(ACTOR_PK);
        a = bound(a, 0, 1e27);
        b = bound(b, 0, 1e27);
        vm.deal(account, a + b);

        MockTarget target2 = new MockTarget();

        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), a, abi.encodeCall(MockTarget.setValue, (10)));
        calls[1] = Call(address(target2), b, abi.encodeCall(MockTarget.setValue, (20)));

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 10);
        assertEq(target2.value(), 20);
        assertEq(address(target).balance, a);
        assertEq(address(target2).balance, b);
    }

    /// @notice A registered TRUSTED_EXECUTOR actor may drive execution directly by matching msg.sender.
    /// @dev Covers the config-driven authorization branch: getActorConfig(...).authenticator == TRUSTED_EXECUTOR.
    function test_executeBatch_success_trustedExecutor(uint256 execSeed, uint256 v) public {
        (address account,) = _createK1Account(ACTOR_PK);

        address executor = address(uint160(bound(execSeed, 10, type(uint160).max)));
        vm.assume(executor != account && executor != vm.addr(ACTOR_PK));

        // The owner signs an actor change registering `executor` with the TRUSTED_EXECUTOR authenticator.
        _authorizeActor(account, ACTOR_PK, bytes32(uint256(uint160(executor))), TRUSTED_EXECUTOR);

        vm.prank(executor);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (v))));

        assertEq(target.value(), v);
    }

    /// @notice A TRUSTED_EXECUTOR actor whose scope is not operational (a capability-only scope, e.g. SELF_PAYER)
    ///         cannot drive execution: _isAuthorizedCaller returns false via the isOperator(scope) == false leg.
    function test_executeBatch_revert_trustedExecutorNonOperationalScope(uint256 execSeed) public {
        (address account,) = _createK1Account(ACTOR_PK);

        address executor = address(uint160(bound(execSeed, 10, type(uint160).max)));
        vm.assume(executor != account && executor != vm.addr(ACTOR_PK));

        // Registered as a trusted executor, but with a non-operational (capability-only) scope.
        _authorizeActorWithScope(
            account, ACTOR_PK, bytes32(uint256(uint160(executor))), TRUSTED_EXECUTOR, SCOPE_SELF_PAYER
        );

        vm.prank(executor);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    /// @notice A TRUSTED_EXECUTOR actor with an unbounded (expiry == 0) grant may drive execution.
    /// @dev Covers the `config.expiry != 0` false leg of the expiry guard (the && short-circuits before the
    ///      timestamp comparison), which the UNBOUNDED-expiry executor helper never exercises.
    function test_executeBatch_success_trustedExecutorZeroExpiry(uint256 execSeed, uint256 v) public {
        (address account,) = _createK1Account(ACTOR_PK);

        address executor = address(uint160(bound(execSeed, 10, type(uint160).max)));
        vm.assume(executor != account && executor != vm.addr(ACTOR_PK));

        // Operational admin scope, expiry == 0 (unlimited).
        _applyLocal(
            ACTOR_PK, account, _one(_authorizeChange(bytes32(uint256(uint160(executor))), TRUSTED_EXECUTOR, 0, 0, ""))
        );

        vm.prank(executor);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (v))));

        assertEq(target.value(), v);
    }

    /// @notice A TRUSTED_EXECUTOR config whose non-zero expiry has elapsed is rejected.
    /// @dev getActorConfig already zeroes expired configs, so the elapsed-expiry leg of _isAuthorizedCaller is
    ///      defense-in-depth; mock the keystore to return a stale (expired) executor config and prove it fails closed.
    function test_executeBatch_revert_trustedExecutorExpired(uint256 execSeed) public {
        (address account,) = _createK1Account(ACTOR_PK);

        address executor = address(uint160(bound(execSeed, 10, type(uint160).max)));
        vm.assume(executor != account && executor != vm.addr(ACTOR_PK));

        vm.warp(1000);
        Keystore.ActorConfig memory stale =
            Keystore.ActorConfig({authenticator: TRUSTED_EXECUTOR, expiry: 500, scope: 0}); // expiry < now
        vm.mockCall(
            address(keystore),
            abi.encodeWithSelector(Keystore.getActorConfig.selector, account, bytes32(uint256(uint160(executor)))),
            abi.encode(stale)
        );

        vm.prank(executor);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    /// @notice A call to a target with no code succeeds (the low-level call returns success).
    /// @dev executeBatch does not verify the target has code, so codeless targets return success.
    function test_executeBatch_success_callToCodelessTarget(address t) public {
        (address account,) = _createK1Account(ACTOR_PK);
        vm.assume(uint160(t) > 0xffff); // stay clear of all precompiles (which may revert on arbitrary calldata)
        vm.assume(t != account && t != address(vm) && t.code.length == 0);

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(_singleCall(t, 0, abi.encodeCall(MockTarget.setValue, (1))));

        assertEq(t.code.length, 0);
    }

    // ══════════════════════════════════════════════
    //  execute (single call)
    // ══════════════════════════════════════════════

    /// @notice An unauthorized caller cannot drive execute.
    /// @dev Exercises the false leg of `_isAuthorizedCaller(msg.sender)`; fuzzes the caller.
    function test_execute_revert_unauthorizedCaller(address caller) public {
        (address account,) = _createK1Account(ACTOR_PK);
        vm.assume(caller != account);

        vm.prank(caller);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        DefaultAccount(payable(account)).execute(address(target), 0, abi.encodeCall(MockTarget.setValue, (1)));
    }

    /// @notice A failing inner call reverts execute, bubbling the inner Error(string) reason verbatim.
    /// @dev Exercises the failure leg of the low-level call; fuzzes the value carried by the failing call.
    function test_execute_revert_bubblesInnerRevert(uint256 value) public {
        (address account,) = _createK1Account(ACTOR_PK);
        value = bound(value, 0, 1e24);
        vm.deal(account, value);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "boom"));
        DefaultAccount(payable(account)).execute(address(target), value, abi.encodeCall(MockTarget.reverting, ()));
    }

    /// @notice execute bubbles a non-string (custom error) revert reason verbatim.
    /// @dev Confirms the bubble-up helper re-throws arbitrary returndata, not just Error(string); fuzzes the code.
    function test_execute_revert_bubblesCustomError(uint256 code) public {
        (address account,) = _createK1Account(ACTOR_PK);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(MockTarget.Boom.selector, code));
        DefaultAccount(payable(account)).execute(address(target), 0, abi.encodeCall(MockTarget.revertingCustom, (code)));
    }

    /// @notice A failing inner call with empty returndata bubbles up as a reason-less (empty) revert.
    function test_execute_revert_emptyReturndataBubblesEmptyRevert() public {
        (address account,) = _createK1Account(ACTOR_PK);

        vm.prank(account);
        vm.expectRevert(bytes(""));
        DefaultAccount(payable(account)).execute(address(target), 0, abi.encodeCall(MockTarget.revertingSilent, ()));
    }

    /// @notice The account calling itself executes a single call.
    /// @dev Covers the `caller == address(this)` branch and one successful call; fuzzes the stored value.
    function test_execute_success_selfCaller(uint256 v) public {
        (address account,) = _createK1Account(ACTOR_PK);

        vm.prank(account);
        DefaultAccount(payable(account)).execute(address(target), 0, abi.encodeCall(MockTarget.setValue, (v)));

        assertEq(target.value(), v);
    }

    /// @notice execute forwards ETH value to the target.
    /// @dev Fuzzes the forwarded amount bounded to the account balance; confirms `call{value:}` wiring.
    function test_execute_success_withETHValue(uint256 amount) public {
        (address account,) = _createK1Account(ACTOR_PK);
        amount = bound(amount, 0, 1e30);
        vm.deal(account, amount);

        vm.prank(account);
        DefaultAccount(payable(account)).execute(address(target), amount, abi.encodeCall(MockTarget.setValue, (7)));

        assertEq(address(target).balance, amount);
        assertEq(target.value(), 7);
    }

    // ══════════════════════════════════════════════
    //  isValidSignature — failure returns (0xFFFFFFFF)
    // ══════════════════════════════════════════════

    /// @notice A signature from a key that is not a registered actor returns the failure magic value.
    /// @dev validateSignature reverts (AuthenticatorMismatch/DefaultEoaRevoked); isValidSignature catches it -> fail.
    function test_isValidSignature_success_returnsFailureForWrongKey(uint256 ownerSeed, uint256 wrongSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 wrongPk = _boundK1Pk(wrongSeed);
        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(wrongPk) != vm.addr(ownerPk) && vm.addr(wrongPk) != account);

        // Well-formed local envelope over the correct digest, but signed by a key that is not a registered actor.
        bytes memory authData = _wrapLocal(_buildK1Auth(wrongPk, keystore.replaySafeHash(account, block.chainid, hash)));

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, ERC1271_FAIL);
    }

    /// @notice A valid signature from a payer-only (non-SENDER, non-admin) actor returns the failure magic value.
    /// @dev isValidSignature gates on Scopes.isOperator; here SCOPE_SELF_PAYER (no SENDER, no admin) is not
    ///      operational, so an otherwise-valid signature is rejected.
    function test_isValidSignature_success_returnsFailureForNonOperationalScope(
        uint256 ownerSeed,
        uint256 actorSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(ownerPk);

        uint256 actorPk = _boundK1Pk(actorSeed);
        address actor = vm.addr(actorPk);
        vm.assume(actor != vm.addr(ownerPk) && actor != account);

        // Authorize the actor with SELF_PAYER scope only — it is not operational and cannot validate signatures.
        _authorizeActorWithScope(account, ownerPk, bytes32(uint256(uint160(actor))), k1Authenticator, SCOPE_SELF_PAYER);

        // Otherwise-valid local envelope: the sole failure reason is the non-operational scope.
        bytes memory authData = _wrapLocal(_buildK1Auth(actorPk, keystore.replaySafeHash(account, block.chainid, hash)));

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, ERC1271_FAIL);
    }

    /// @notice A valid signature from an operational SENDER-without-POLICY actor returns the ERC-1271 magic value.
    /// @dev An operational actor validates: signing encodes authority a SENDER key already holds via calls, so it
    ///      does not require the admin scope.
    function test_isValidSignature_success_operationalSenderSigns(uint256 ownerSeed, uint256 actorSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(ownerPk);

        uint256 actorPk = _boundK1Pk(actorSeed);
        address actor = vm.addr(actorPk);
        vm.assume(actor != vm.addr(ownerPk) && actor != account);

        // Authorize the actor with SENDER scope only (no POLICY) — it is operational and can validate signatures.
        _authorizeActorWithScope(account, ownerPk, bytes32(uint256(uint160(actor))), k1Authenticator, SCOPE_SENDER);

        // Chain-local envelope over the account-scoped replaySafeHash digest.
        bytes memory authData = _wrapLocal(_buildK1Auth(actorPk, keystore.replaySafeHash(account, block.chainid, hash)));

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, ERC1271_MAGIC);
    }

    /// @notice A signature envelope too short to carry a 20-byte authenticator returns the failure magic value.
    /// @dev An empty blob reverts EmptySignatureEnvelope; a Local envelope (0x01) with an under-20-byte remainder
    ///      reverts InvalidAuthLength in authenticateActor. Both are caught -> fail.
    function test_isValidSignature_success_returnsFailureForShortSignature(
        uint256 ownerSeed,
        uint8 lenSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(ownerPk);

        uint256 len = bound(lenSeed, 0, 20); // 0 = empty envelope; 1..20 = Local type byte + under-length authenticator
        bytes memory shortSig = new bytes(len);
        if (len > 0) shortSig[0] = 0x01; // SignatureType.Local; remainder (< 20 bytes) is an under-length authenticator

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, shortSig);
        assertEq(result, ERC1271_FAIL);
    }

    // ══════════════════════════════════════════════
    //  isValidSignature — success returns (0x1626ba7e)
    // ══════════════════════════════════════════════

    /// @notice A valid signature from the unrestricted owner returns the ERC-1271 magic value.
    /// @dev The owner actor has scope == 0 (unrestricted), which is operational. Fuzzes key and hash.
    function test_isValidSignature_success_validK1Owner(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1Account(pk);

        // Chain-local envelope over the account-scoped replaySafeHash digest.
        bytes memory authData = _wrapLocal(_buildK1Auth(pk, keystore.replaySafeHash(account, block.chainid, hash)));

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, ERC1271_MAGIC);
    }

    /// @notice A non-operational scoped actor never validates, even for the former SIGNER bit (0x10, now
    ///         SCOPE_SPONSOR_PAYER). Only an operational actor (admin, or SENDER-without-POLICY) returns the magic.
    /// @dev There is no SIGNER grant anymore; a sponsor-payer actor's valid signature returns the failure magic value.
    function test_isValidSignature_success_scopedActorCannotSign(uint256 ownerSeed, uint256 actorSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(ownerPk);

        uint256 actorPk = _boundK1Pk(actorSeed);
        address actor = vm.addr(actorPk);
        vm.assume(actor != vm.addr(ownerPk) && actor != account);

        _authorizeActorWithScope(
            account, ownerPk, bytes32(uint256(uint160(actor))), k1Authenticator, SCOPE_SPONSOR_PAYER
        );

        // Otherwise-valid local envelope: the sole failure reason is the non-operational scope.
        bytes memory authData = _wrapLocal(_buildK1Auth(actorPk, keystore.replaySafeHash(account, block.chainid, hash)));

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, ERC1271_FAIL);
    }

    // ══════════════════════════════════════════════
    //  isAuthorizedCaller
    // ══════════════════════════════════════════════

    /// @notice The account is always authorized to call itself.
    /// @dev Covers the hardcoded `caller == address(this)` branch. Fuzzes the owner key to vary the account.
    function test_isAuthorizedCaller_success_self(uint256 pkSeed) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1Account(pk);

        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(account));
    }

    /// @notice A registered TRUSTED_EXECUTOR actor is reported as authorized.
    /// @dev Covers the config-driven true branch: getActorConfig(...).authenticator == TRUSTED_EXECUTOR.
    function test_isAuthorizedCaller_success_trustedExecutor(uint256 execSeed) public {
        (address account,) = _createK1Account(ACTOR_PK);

        address executor = address(uint160(bound(execSeed, 10, type(uint160).max)));
        vm.assume(executor != account && executor != vm.addr(ACTOR_PK));

        _authorizeActor(account, ACTOR_PK, bytes32(uint256(uint160(executor))), TRUSTED_EXECUTOR);

        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(executor));
    }

    /// @notice A registered k1 actor (authenticator != TRUSTED_EXECUTOR) is not an authorized caller.
    /// @dev Covers the config-driven false branch: a configured actor whose authenticator is the K1 sentinel.
    function test_isAuthorizedCaller_success_k1ActorNotAuthorized(uint256 actorSeed) public {
        (address account,) = _createK1Account(ACTOR_PK);

        uint256 actorPk = _boundK1Pk(actorSeed);
        address actor = vm.addr(actorPk);
        vm.assume(actor != account && actor != vm.addr(ACTOR_PK));

        _authorizeActor(account, ACTOR_PK, bytes32(uint256(uint160(actor))), k1Authenticator);

        assertFalse(DefaultAccount(payable(account)).isAuthorizedCaller(actor));
    }

    /// @notice An arbitrary unregistered caller is not authorized.
    /// @dev Covers the config-driven false branch for an empty config (authenticator == address(0)). Fuzzes caller.
    function test_isAuthorizedCaller_success_randomCallerNotAuthorized(address caller) public {
        (address account,) = _createK1Account(ACTOR_PK);
        vm.assume(caller != account);

        assertFalse(DefaultAccount(payable(account)).isAuthorizedCaller(caller));
    }
}
