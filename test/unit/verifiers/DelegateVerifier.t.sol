// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract DelegateVerifierTest is AccountConfigurationTest {
    uint256 constant DELEGATE_PK = 42;
    uint256 constant DELEGATOR_PK = 43;

    function test_verify_validDelegation() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        address delegateSigner = vm.addr(DELEGATOR_PK);
        bytes32 delegatorActorId = bytes32(bytes20(delegateSigner));
        bytes32 delegateRefActorId = bytes32(bytes20(delegateAccount));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](2);
        if (delegatorActorId < delegateRefActorId) {
            actors[0] = IAccountConfiguration.InitialActor({actorId: delegatorActorId, verifier: address(k1Verifier)});
            actors[1] =
                IAccountConfiguration.InitialActor({actorId: delegateRefActorId, verifier: address(delegateVerifier)});
        } else {
            actors[0] =
                IAccountConfiguration.InitialActor({actorId: delegateRefActorId, verifier: address(delegateVerifier)});
            actors[1] = IAccountConfiguration.InitialActor({actorId: delegatorActorId, verifier: address(k1Verifier)});
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        accountConfiguration.createAccount(bytes32(uint256(1)), bytecode, actors);

        bytes32 hash = keccak256("delegate test");
        bytes memory delegateSig = _signDigest(DELEGATE_PK, hash);

        // Nested auth: k1Verifier(20) || sig
        bytes memory nestedAuth = abi.encodePacked(address(k1Verifier), delegateSig);
        // delegate data: delegate_address(20) || nestedAuth
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        bytes32 actorId = delegateVerifier.verify(hash, data);
        assertEq(actorId, delegateRefActorId);
    }

    function test_verify_revertsOnTooShortData() public {
        bytes32 hash = keccak256("test");

        vm.expectRevert();
        delegateVerifier.verify(hash, hex"");
    }

    function test_verify_revertsOnUnauthorizedNestedActor() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        bytes32 hash = keccak256("test");

        bytes memory fakeSig = _signDigest(999, hash);
        // Nested auth with wrong signer — verifier recovers wrong address
        bytes memory nestedAuth = abi.encodePacked(address(k1Verifier), fakeSig);
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert();
        delegateVerifier.verify(hash, data);
    }

    function test_verify_revertsOnDoubleDelegate() public {
        (address accountA,) = _createK1Account(DELEGATE_PK);

        bytes32 delegateRefA = bytes32(bytes20(accountA));
        IAccountConfiguration.InitialActor[] memory actorsB = new IAccountConfiguration.InitialActor[](1);
        actorsB[0] = IAccountConfiguration.InitialActor({actorId: delegateRefA, verifier: address(delegateVerifier)});
        bytes memory bytecodeB = _computeERC1167Bytecode(defaultAccountImplementation);
        address accountB = accountConfiguration.createAccount(bytes32(uint256(10)), bytecodeB, actorsB);

        bytes32 hash = keccak256("double delegate test");
        bytes memory k1Sig = _signDigest(DELEGATE_PK, hash);

        // Single-hop B → A: should work
        bytes memory nestedAuth = abi.encodePacked(address(k1Verifier), k1Sig);
        bytes memory singleHopData = abi.encodePacked(accountA, nestedAuth);
        bytes32 actorId = delegateVerifier.verify(hash, singleHopData);
        assertEq(actorId, delegateRefA);

        // Double-hop: try to use accountB as delegate — 1-hop limit triggers
        bytes memory doubleHopData = abi.encodePacked(accountB, nestedAuth);
        vm.expectRevert();
        delegateVerifier.verify(hash, doubleHopData);
    }
}
