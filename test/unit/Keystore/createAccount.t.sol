// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @dev Fully fuzzed, branch-complete suite for Keystore.createAccount and the pure/view
///      machinery it drives: computeAddress, _buildDeploymentCode, _computeEffectiveSalt / _computeActorsCommitment,
///      and _initializeAccount. Reverts are ordered to mirror createAccount's source control flow; happy paths and
///      the computeAddress determinism/sensitivity checks follow.
contract CreateAccountTest is KeystoreTest {
    // ── local builders ──

    function _initialActor(bytes32 actorId, address authenticator)
        internal
        pure
        returns (Keystore.InitialActor memory)
    {
        return Keystore.InitialActor({actorId: actorId, authenticator: authenticator, scope: 0, policyData: ""});
    }

    /// @dev A one-element k1 actor set with a caller-chosen actorId. actorId must be strictly > 0 (the sort guard
    ///      seeds previousActorId at 0 and rejects the first id if it is <= 0).
    function _oneK1Actor(bytes32 actorId) internal view returns (Keystore.InitialActor[] memory actors) {
        actors = new Keystore.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(k1Authenticator));
    }

    /// @dev Deterministically materialize a strictly-ascending k1 actor set of `count` address-shaped actorIds
    ///      (high 12 bytes zero, mirroring a real k1 actorId = bytes32(uint256(uint160(signer)))). Ascending uint160 base+i
    ///      maps to ascending bytes32, so no in-Solidity sort is needed. base >= 1 keeps the first id > 0.
    function _ascendingK1Actors(uint256 count, uint256 base)
        internal
        view
        returns (Keystore.InitialActor[] memory actors)
    {
        actors = new Keystore.InitialActor[](count);
        for (uint256 i; i < count; i++) {
            bytes32 actorId = bytes32(uint256(uint160(address(uint160(base + i)))));
            actors[i] = _initialActor(actorId, address(k1Authenticator));
        }
    }

    /// @dev Arbitrary valid runtime bytecode of a fuzzed length/content. The deployment header only CODECOPY+RETURNs
    ///      these bytes as runtime code (never executes them), so any content deploys as long as it is under the
    ///      EIP-170 runtime cap and does not lead with 0xEF (EIP-3541).
    function _validBytecode(uint256 lenSeed, bytes32 contentSeed) internal pure returns (bytes memory bc) {
        uint256 len = bound(lenSeed, 1, 2048);
        bc = new bytes(len);
        for (uint256 i; i < len; i++) {
            bc[i] = bytes1(uint8(uint256(keccak256(abi.encodePacked(contentSeed, i)))));
        }
        if (bc[0] == 0xEF) bc[0] = 0x00; // EIP-3541: leading 0xEF is rejected as runtime code
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // REVERTS (source-execution order)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Verifies createAccount reverts when deployment bytecode is empty
    /// @dev Empty runtime code would break the 8130 isEOA invariant: (7702-delegated) || (no code).
    function test_createAccount_revert_emptyBytecode(bytes32 salt) public {
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(1)))));

        vm.expectRevert(Keystore.EmptyBytecode.selector);
        keystore.createAccount(salt, "", actors);
    }

    /// @notice Verifies createAccount reverts when bytecode length exceeds the 0xFFFF encodable maximum
    /// @dev _buildDeploymentCode (reached first, via computeAddress) reverts BytecodeTooLarge for n > 0xFFFF
    function test_createAccount_revert_bytecodeTooLarge(uint256 lenSeed, bytes1 fill, bytes32 salt) public {
        uint256 len = bound(lenSeed, 0x10000, 0x10000 + 64);
        bytes memory bytecode = new bytes(len);
        bytecode[0] = fill;

        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(1)))));

        vm.expectRevert(Keystore.BytecodeTooLarge.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice Verifies re-creating an account at an address that already holds 8130 state reverts
    /// @dev localSequence is set to 1 on first create and doubles as the initialized flag; the guard trips on retry
    function test_createAccount_revert_alreadyInitialized(uint256 pk, bytes32 salt, uint256 lenSeed, bytes32 content)
        public
    {
        pk = _boundK1Pk(pk);
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(pk)))));
        bytes memory bytecode = _validBytecode(lenSeed, content);

        keystore.createAccount(salt, bytecode, actors);

        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice Verifies createAccount reverts when the initial actor set is empty
    /// @dev _initializeAccount rejects a zero-length initialActors with NoInitialActors before any actor is written
    function test_createAccount_revert_noInitialActors(bytes32 salt, uint256 lenSeed, bytes32 content) public {
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](0);
        bytes memory bytecode = _validBytecode(lenSeed, content);

        vm.expectRevert(Keystore.NoInitialActors.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice Verifies createAccount reverts when initial actors are not in strictly ascending actorId order
    /// @dev Exercises the `<` side of the `actorId <= previousActorId` guard: a larger id precedes a smaller one
    function test_createAccount_revert_actorsNotSorted(bytes32 idA, bytes32 idB, bytes32 salt) public {
        vm.assume(idA != 0 && idB != 0);
        vm.assume(idA != idB);
        bytes32 smaller = idA < idB ? idA : idB;
        bytes32 larger = idA < idB ? idB : idA;

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        actors[0] = _initialActor(larger, address(k1Authenticator));
        actors[1] = _initialActor(smaller, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert(Keystore.ActorsNotSortedOrDuplicate.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice Verifies createAccount reverts when the initial actor set contains a duplicate actorId
    /// @dev Exercises the `==` side of the `actorId <= previousActorId` guard: two equal ids in one set
    function test_createAccount_revert_actorsDuplicate(bytes32 id, bytes32 salt) public {
        vm.assume(id != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        actors[0] = _initialActor(id, address(k1Authenticator));
        actors[1] = _initialActor(id, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert(Keystore.ActorsNotSortedOrDuplicate.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice Verifies createAccount reverts when an initial actor names an authenticator below the K1 sentinel
    /// @dev _authorizeActor rejects authenticator < K1_AUTHENTICATOR; the only such value is address(0)
    function test_createAccount_revert_invalidAuthenticator(bytes32 actorId, bytes32 salt) public {
        vm.assume(actorId != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(0));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert(Keystore.InvalidAuthenticator.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice Verifies createAccount reverts when CREATE2 rejects the runtime code for a leading 0xEF byte
    /// @dev EIP-3541: a 0xEF-prefixed runtime code makes CREATE2 return address(0), tripping AccountDeploymentFailed
    function test_createAccount_revert_deploymentFailedLeadingEF(uint256 lenSeed, bytes32 content, bytes32 salt)
        public
    {
        uint256 len = bound(lenSeed, 1, 512);
        bytes memory bytecode = new bytes(len);
        bytecode[0] = 0xEF;
        for (uint256 i = 1; i < len; i++) {
            bytecode[i] = bytes1(uint8(uint256(keccak256(abi.encodePacked(content, i)))));
        }

        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(1)))));

        vm.expectRevert(Keystore.AccountDeploymentFailed.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice A failed CREATE2 unwinds every state write, leaving no initialized-but-codeless account
    /// @dev Leading-0xEF runtime code makes CREATE2 return address(0), which must revert the whole call. Verifies no
    ///      code, no local sequence, and no actor persist, and that a retry re-attempts the deploy (and fails again)
    ///      rather than reverting AlreadyInitialized.
    function test_createAccount_revert_deploymentFailedNoOrphanedState(uint256 pk, bytes32 salt) public {
        pk = _boundK1Pk(pk);
        bytes32 actorId = bytes32(uint256(uint160(vm.addr(pk))));

        Keystore.InitialActor[] memory actors = _oneK1Actor(actorId);
        bytes memory bytecode = hex"EF";

        address predicted = keystore.computeAddress(salt, bytecode, actors);

        vm.expectRevert(Keystore.AccountDeploymentFailed.selector);
        keystore.createAccount(salt, bytecode, actors);

        assertEq(predicted.code.length, 0);
        assertEq(keystore.getChangeSequences(predicted).localSequence, 0);
        assertEq(keystore.getChangeSequences(predicted).multichain, 0);
        assertFalse(_isActor(predicted, actorId));

        // The writes were unwound, so the re-init guard is not tripped: the retry re-attempts the deploy and fails
        // again on the same invalid bytecode rather than reverting AlreadyInitialized.
        vm.expectRevert(Keystore.AccountDeploymentFailed.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // HAPPY PATHS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Verifies a single-K1-actor account deploys with code and registers the actor as live
    /// @dev Canonical clone bytecode; fuzzed key and salt confirm the property holds across the actor/salt space
    function test_createAccount_success_singleK1Actor(uint256 pk, bytes32 salt) public {
        pk = _boundK1Pk(pk);
        bytes32 actorId = bytes32(uint256(uint160(vm.addr(pk))));

        Keystore.InitialActor[] memory actors = _oneK1Actor(actorId);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        address account = keystore.createAccount(salt, bytecode, actors);

        assertTrue(account != address(0));
        assertGt(account.code.length, 0);
        assertTrue(_isActor(account, actorId));
    }

    /// @notice Verifies an account with many sorted initial actors deploys and registers every actor as live
    /// @dev Fuzzes the actor count and the ascending id base, exercising the _initializeAccount authorization loop
    ///      and _computeActorsCommitment over a multi-element set
    function test_createAccount_success_multipleActors(uint256 count, uint256 base, bytes32 salt) public {
        count = bound(count, 2, 8);
        base = bound(base, 1, type(uint160).max - count);

        Keystore.InitialActor[] memory actors = _ascendingK1Actors(count, base);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        address account = keystore.createAccount(salt, bytecode, actors);

        assertGt(account.code.length, 0);
        for (uint256 i; i < count; i++) {
            assertTrue(_isActor(account, actors[i].actorId));
        }
    }

    /// @notice Verifies any non-zero authenticator address is accepted and stored verbatim on the initial actor
    /// @dev Fuzzes the authenticator address (the `authenticator >= K1_AUTHENTICATOR` accept side) and asserts
    ///      getActorConfig round-trips it as an unrestricted owner
    function test_createAccount_success_fuzzedAuthenticatorAddress(address authenticator, bytes32 actorId, bytes32 salt)
        public
    {
        vm.assume(authenticator != address(0));
        // Keep actorId away from the self-actorId shape (a right-aligned address has its high 12 bytes zero) so it
        // routes to the generic actor home rather than the inline-self path, which would report the K1 sentinel
        // instead of the fuzzed address.
        vm.assume((uint256(actorId) >> 160) != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = _initialActor(actorId, authenticator);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        address account = keystore.createAccount(salt, bytecode, actors);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, authenticator);
        assertEq(cfg.scope, 0x00);
        assertEq(cfg.expiry, 0);
        assertTrue(_isActor(account, actorId));
    }

    /// @notice Verifies initial actors are unrestricted owners and the account is initialized with safe lock defaults
    /// @dev Initial actors are structurally scope 0 / no expiry / no policy; localSequence is 1 and the account is
    ///      unlocked with a zeroed unlock schedule
    function test_createAccount_success_unrestrictedInitialActor(uint256 pk, bytes32 salt) public {
        pk = _boundK1Pk(pk);
        bytes32 actorId = bytes32(uint256(uint160(vm.addr(pk))));

        Keystore.InitialActor[] memory actors = _oneK1Actor(actorId);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        address account = keystore.createAccount(salt, bytecode, actors);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, 0x00);
        assertEq(cfg.expiry, 0);

        assertEq(keystore.getChangeSequences(account).localSequence, 1);
        assertEq(keystore.getChangeSequences(account).multichain, 0);

        (bool locked, bool hasInitiatedUnlock, uint48 unlocksAt, uint16 unlockDelay) = keystore.getLockStatus(account);
        assertFalse(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, 0);
        assertEq(unlockDelay, 0);
    }

    /// @notice Verifies createAccount marks the account's implicit secp256k1 self key revoked by default
    /// @dev FLAG_REVOKE_DEFAULT_EOA is set on create (quantum-safe default), so the self-actorId is not a live actor
    ///      absent an explicit self initial actor
    function test_createAccount_success_defaultEoaRevokedByDefault(uint256 pk, bytes32 salt) public {
        pk = _boundK1Pk(pk);
        bytes32 actorId = bytes32(uint256(uint160(vm.addr(pk))));

        Keystore.InitialActor[] memory actors = _oneK1Actor(actorId);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        address account = keystore.createAccount(salt, bytecode, actors);

        // The account's own self-actorId is not the seeded actor, so the inline k1 self stays disabled.
        vm.assume(bytes32(uint256(uint160(account))) != actorId);
        assertFalse(_isActor(account, bytes32(uint256(uint160(account)))));
    }

    /// @notice Verifies arbitrary valid runtime bytecode of a fuzzed length/content deploys successfully
    /// @dev The deployment header CODECOPY+RETURNs the bytes as runtime code without executing them, so any EIP-170-
    ///      sized, non-0xEF-leading payload deploys; the deployed code length matches the requested bytecode length
    function test_createAccount_success_arbitraryBytecode(uint256 lenSeed, bytes32 content, uint256 pk, bytes32 salt)
        public
    {
        pk = _boundK1Pk(pk);
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(pk)))));
        bytes memory bytecode = _validBytecode(lenSeed, content);

        address account = keystore.createAccount(salt, bytecode, actors);

        assertEq(account.code.length, bytecode.length);
    }

    /// @notice Verifies bytecode of exactly 0xFFFF bytes is accepted (the encodable maximum is inclusive)
    /// @dev Lower side of the BytecodeTooLarge boundary: _buildDeploymentCode rejects only `n > 0xFFFF`, so 0xFFFF
    ///      passes the size check and deploys. Foundry disables the EIP-170 runtime code-size limit in tests, so the
    ///      65535-byte runtime code deploys rather than failing — the assertion here is purely that BytecodeTooLarge
    ///      is NOT reached at the boundary, complementing the n == 0x10000 revert test above.
    function test_createAccount_success_bytecodeAtEncodableMax(bytes32 salt) public {
        bytes memory bytecode = new bytes(0xFFFF); // zero-filled: EIP-3541-clean (no leading 0xEF)

        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(1)))));

        address account = keystore.createAccount(salt, bytecode, actors);
        assertEq(account.code.length, 0xFFFF);
    }

    /// @notice Verifies createAccount emits AccountCreated once with the account, user salt, and bytecode hash
    /// @dev Sole assertion of this event; the codeHash argument is keccak256 of the raw user bytecode, not the header
    function test_createAccount_success_emitsAccountCreated(uint256 pk, bytes32 salt, uint256 lenSeed, bytes32 content)
        public
    {
        pk = _boundK1Pk(pk);
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(pk)))));
        bytes memory bytecode = _validBytecode(lenSeed, content);

        address predicted = keystore.computeAddress(salt, bytecode, actors);

        vm.expectEmit(true, false, false, true, address(keystore));
        emit Keystore.AccountCreated(predicted, salt, keccak256(bytecode));
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice Verifies the deployed account address equals the counterfactual computeAddress for fuzzed inputs
    /// @dev CREATE2 determinism across salt, bytecode, and actor set; the predicted address holds code post-deploy
    function test_createAccount_success_deterministicAddress(uint256 pk, bytes32 salt, uint256 lenSeed, bytes32 content)
        public
    {
        pk = _boundK1Pk(pk);
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(pk)))));
        bytes memory bytecode = _validBytecode(lenSeed, content);

        address predicted = keystore.computeAddress(salt, bytecode, actors);
        address actual = keystore.createAccount(salt, bytecode, actors);

        assertEq(actual, predicted);
        assertGt(predicted.code.length, 0);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // computeAddress (pure/view: _buildDeploymentCode + _computeEffectiveSalt + _computeActorsCommitment)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Verifies computeAddress reverts when deployment bytecode is empty
    function test_computeAddress_revert_emptyBytecode(bytes32 salt) public {
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(1)))));

        vm.expectRevert(Keystore.EmptyBytecode.selector);
        keystore.computeAddress(salt, "", actors);
    }

    /// @notice Verifies computeAddress reverts for bytecode larger than the 0xFFFF encodable maximum
    /// @dev computeAddress -> _buildDeploymentCode reverts BytecodeTooLarge for n > 0xFFFF, independent of create
    function test_computeAddress_revert_bytecodeTooLarge(uint256 lenSeed, bytes1 fill, bytes32 salt) public {
        uint256 len = bound(lenSeed, 0x10000, 0x10000 + 64);
        bytes memory bytecode = new bytes(len);
        bytecode[0] = fill;

        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(1)))));

        vm.expectRevert(Keystore.BytecodeTooLarge.selector);
        keystore.computeAddress(salt, bytecode, actors);
    }

    /// @notice Verifies computeAddress rejects an empty actor set, matching createAccount (M-02 parity)
    /// @dev _prepareDeployment runs _validateInitialActors before deriving the address, so no address is predicted
    ///      for a set createAccount would reject.
    function test_computeAddress_revert_noInitialActors(bytes32 salt) public {
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](0);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        vm.expectRevert(Keystore.NoInitialActors.selector);
        keystore.computeAddress(salt, bytecode, actors);
    }

    /// @notice Verifies computeAddress rejects an unsorted actor set, matching createAccount (M-02 parity)
    function test_computeAddress_revert_actorsNotSorted(bytes32 idA, bytes32 idB, bytes32 salt) public {
        vm.assume(idA != 0 && idB != 0 && idA != idB);
        bytes32 smaller = idA < idB ? idA : idB;
        bytes32 larger = idA < idB ? idB : idA;

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        actors[0] = _initialActor(larger, address(k1Authenticator));
        actors[1] = _initialActor(smaller, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert(Keystore.ActorsNotSortedOrDuplicate.selector);
        keystore.computeAddress(salt, bytecode, actors);
    }

    /// @notice Verifies computeAddress rejects a duplicate actorId, matching createAccount (M-02 parity)
    function test_computeAddress_revert_actorsDuplicate(bytes32 id, bytes32 salt) public {
        vm.assume(id != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        actors[0] = _initialActor(id, address(k1Authenticator));
        actors[1] = _initialActor(id, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert(Keystore.ActorsNotSortedOrDuplicate.selector);
        keystore.computeAddress(salt, bytecode, actors);
    }

    /// @notice Verifies computeAddress rejects a sub-K1 authenticator, matching createAccount (M-02 parity)
    function test_computeAddress_revert_invalidAuthenticator(bytes32 actorId, bytes32 salt) public {
        vm.assume(actorId != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(0));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert(Keystore.InvalidAuthenticator.selector);
        keystore.computeAddress(salt, bytecode, actors);
    }

    /// @notice Verifies computeAddress rejects malformed policyData, matching createAccount (M-02 parity)
    /// @dev Scope carries Scopes.POLICY (0x02) but policyData is not the required 52 bytes, so _validateInitialActors
    ///      reverts InvalidPolicyData before an address is predicted.
    function test_computeAddress_revert_invalidPolicyData(bytes32 actorId, bytes32 salt) public {
        vm.assume(actorId != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0x02, policyData: hex"deadbeef"
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        keystore.computeAddress(salt, bytecode, actors);
    }

    /// @notice Verifies createAccount rejects malformed policyData up front via the shared validator
    /// @dev Complements the existing sorted/duplicate/authenticator revert tests: scope has Scopes.POLICY set but
    ///      policyData is not 52 bytes, so _prepareDeployment -> _validateInitialActors reverts InvalidPolicyData.
    function test_createAccount_revert_invalidPolicyData(bytes32 actorId, bytes32 salt) public {
        vm.assume(actorId != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0x02, policyData: hex"deadbeef"
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        keystore.createAccount(salt, bytecode, actors);
    }

    /// @notice Verifies computeAddress accepts bytecode of exactly 0xFFFF bytes without reverting
    /// @dev Config-independent proof that the BytecodeTooLarge boundary is exclusive: computeAddress runs
    ///      _buildDeploymentCode but never deploys, so 0xFFFF returns an address while n == 0x10000 reverts (above)
    function test_computeAddress_success_bytecodeAtEncodableMax(bytes32 salt) public view {
        bytes memory bytecode = new bytes(0xFFFF);
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(1)))));

        address predicted = keystore.computeAddress(salt, bytecode, actors);
        assertTrue(predicted != address(0));
    }

    /// @notice Verifies distinct user salts produce distinct counterfactual addresses for the same actors/bytecode
    /// @dev _computeEffectiveSalt folds userSalt into the CREATE2 salt, so salt is address-determining
    function test_computeAddress_success_differentSalts(uint256 pk, bytes32 saltA, bytes32 saltB) public view {
        vm.assume(saltA != saltB);
        pk = _boundK1Pk(pk);
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(pk)))));
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        address addrA = keystore.computeAddress(saltA, bytecode, actors);
        address addrB = keystore.computeAddress(saltB, bytecode, actors);

        assertTrue(addrA != addrB);
    }

    /// @notice Verifies a different initial actor set yields a different address for the same salt and bytecode
    /// @dev _computeActorsCommitment binds the packed actor set into the effective salt, so the actor set is
    ///      address-determining
    function test_computeAddress_success_actorSetSensitivity(bytes32 salt, bytes32 idA, bytes32 idB) public view {
        vm.assume(idA != 0 && idB != 0 && idA != idB);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        address addrA = keystore.computeAddress(salt, bytecode, _oneK1Actor(idA));
        address addrB = keystore.computeAddress(salt, bytecode, _oneK1Actor(idB));

        assertTrue(addrA != addrB);
    }

    /// @notice Verifies different bytecode yields a different address for the same salt and actor set
    /// @dev computeAddress hashes _buildDeploymentCode(bytecode); a distinct codeHash moves the CREATE2 address
    function test_computeAddress_success_bytecodeSensitivity(uint256 pk, bytes32 salt, uint256 lenSeed, bytes32 content)
        public
        view
    {
        pk = _boundK1Pk(pk);
        Keystore.InitialActor[] memory actors = _oneK1Actor(bytes32(uint256(uint160(vm.addr(pk)))));

        bytes memory bytecodeA = _validBytecode(lenSeed, content);
        bytes memory bytecodeB = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.assume(keccak256(bytecodeA) != keccak256(bytecodeB));

        address addrA = keystore.computeAddress(salt, bytecodeA, actors);
        address addrB = keystore.computeAddress(salt, bytecodeB, actors);

        assertTrue(addrA != addrB);
    }
}
