// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice SLOAD-count guards for the hot read paths after policy co-location. Measured with vm.record /
///         vm.accesses against the keystore address, so a future layout change that splits the packed config or
///         spreads policy across extra slots fails loudly:
///           - keystore-side authentication ({_resolveExplicitActor}) is a single SLOAD (the packed 32-byte config)
///           - each policy getter is exactly two SLOADs: one liveness read of the co-located config, one for the
///             policy value (manager or commitment)
contract KeystoreSloadCountTest is KeystoreTest {
    /// @dev Total keystore SLOADs recorded since the preceding vm.record() (duplicates included, so a slot read
    ///      twice counts twice — this is the true SLOAD opcode count, not a distinct-slot count).
    function _keystoreSloads() internal returns (uint256) {
        (bytes32[] memory reads,) = vm.accesses(address(keystore));
        return reads.length;
    }

    /// @dev Authenticating an explicit k1 actor resolves it from the single packed config slot: one SLOAD.
    function test_sload_authExplicitK1Actor_isSingleSload(uint256 ownerSeed, bytes32 hash) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(ownerPk);
        // The owner is an explicit actor (its address != the account clone), so this exercises _resolveExplicitActor
        // rather than the inline-self path.
        vm.assume(vm.addr(ownerPk) != account);

        bytes memory auth = _buildK1Auth(ownerPk, hash);

        vm.record();
        keystore.authenticateActor(account, hash, auth);
        assertEq(_keystoreSloads(), 1, "auth must be a single SLOAD");
    }

    /// @dev getPolicyCommitment is one liveness SLOAD (config) plus one for the commitment: two total.
    function test_sload_getPolicyCommitment_isTwoSloads(uint256 ownerSeed, uint256 actorSeed) public {
        (address account, bytes32 actorId) = _accountWithPolicyActor(ownerSeed, actorSeed);

        vm.record();
        keystore.getPolicyCommitment(account, actorId);
        assertEq(_keystoreSloads(), 2, "getPolicyCommitment must be two SLOADs");
    }

    /// @dev getPolicyManager mirrors getPolicyCommitment: one liveness SLOAD (config) plus one for the manager.
    function test_sload_getPolicyManager_isTwoSloads(uint256 ownerSeed, uint256 actorSeed) public {
        (address account, bytes32 actorId) = _accountWithPolicyActor(ownerSeed, actorSeed);

        vm.record();
        keystore.getPolicyManager(account, actorId);
        assertEq(_keystoreSloads(), 2, "getPolicyManager must be two SLOADs");
    }

    /// @dev Creates an account and authorizes a distinct k1 actor carrying 52-byte co-located policy data.
    function _accountWithPolicyActor(uint256 ownerSeed, uint256 actorSeed)
        internal
        returns (address account, bytes32 actorId)
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));

        (account,) = _createK1Account(ownerPk);
        address actor = vm.addr(actorPk);
        vm.assume(actor != account);
        actorId = bytes32(uint256(uint160(actor)));

        bytes memory policyData = abi.encodePacked(address(0xCAFE), keccak256("commitment")); // 20 + 32 = 52 bytes
        _applyLocal(
            ownerPk,
            account,
            _one(_authorizeChange(actorId, address(k1Authenticator), Scopes.POLICY, UNBOUNDED, policyData))
        );
    }
}
