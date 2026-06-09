// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract DelegateAuthenticatorTest is AccountConfigurationTest {
    uint256 constant DELEGATE_PK = 42;
    uint256 constant DELEGATOR_PK = 43;

    function test_authenticate_validDelegation() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        address delegateSigner = vm.addr(DELEGATOR_PK);
        bytes32 delegatorActorId = bytes32(bytes20(delegateSigner));
        bytes32 delegateRefActorId = bytes32(bytes20(delegateAccount));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](2);
        if (delegatorActorId < delegateRefActorId) {
            actors[0] = IAccountConfiguration.InitialActor({
                actorId: delegatorActorId, authenticator: address(k1Authenticator)
            });
            actors[1] = IAccountConfiguration.InitialActor({
                actorId: delegateRefActorId, authenticator: address(delegateAuthenticator)
            });
        } else {
            actors[0] = IAccountConfiguration.InitialActor({
                actorId: delegateRefActorId, authenticator: address(delegateAuthenticator)
            });
            actors[1] = IAccountConfiguration.InitialActor({
                actorId: delegatorActorId, authenticator: address(k1Authenticator)
            });
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        accountConfiguration.createAccount(bytes32(uint256(1)), bytecode, actors);

        bytes32 hash = keccak256("delegate test");
        bytes memory delegateSig = _signDigest(DELEGATE_PK, hash);

        // Nested auth: k1Authenticator(20) || sig
        bytes memory nestedAuth = abi.encodePacked(address(k1Authenticator), delegateSig);
        // delegate data: delegate_address(20) || nestedAuth
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        bytes32 actorId = delegateAuthenticator.authenticate(hash, data);
        assertEq(actorId, delegateRefActorId);
    }

    function test_authenticate_revertsOnTooShortData() public {
        bytes32 hash = keccak256("test");

        vm.expectRevert();
        delegateAuthenticator.authenticate(hash, hex"");
    }

    function test_authenticate_revertsOnUnauthorizedNestedActor() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        bytes32 hash = keccak256("test");

        bytes memory fakeSig = _signDigest(999, hash);
        // Nested auth with wrong signer — authenticator recovers wrong address
        bytes memory nestedAuth = abi.encodePacked(address(k1Authenticator), fakeSig);
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert();
        delegateAuthenticator.authenticate(hash, data);
    }

    function test_authenticate_revertsOnDoubleDelegate() public {
        (address accountA,) = _createK1Account(DELEGATE_PK);

        bytes32 delegateRefA = bytes32(bytes20(accountA));
        IAccountConfiguration.InitialActor[] memory actorsB = new IAccountConfiguration.InitialActor[](1);
        actorsB[0] =
            IAccountConfiguration.InitialActor({actorId: delegateRefA, authenticator: address(delegateAuthenticator)});
        bytes memory bytecodeB = _computeERC1167Bytecode(defaultAccountImplementation);
        address accountB = accountConfiguration.createAccount(bytes32(uint256(10)), bytecodeB, actorsB);

        bytes32 hash = keccak256("double delegate test");
        bytes memory k1Sig = _signDigest(DELEGATE_PK, hash);

        // Single-hop B → A: should work
        bytes memory nestedAuth = abi.encodePacked(address(k1Authenticator), k1Sig);
        bytes memory singleHopData = abi.encodePacked(accountA, nestedAuth);
        bytes32 actorId = delegateAuthenticator.authenticate(hash, singleHopData);
        assertEq(actorId, delegateRefA);

        // Double-hop: try to use accountB as delegate — 1-hop limit triggers
        bytes memory doubleHopData = abi.encodePacked(accountB, nestedAuth);
        vm.expectRevert();
        delegateAuthenticator.authenticate(hash, doubleHopData);
    }
}
