// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {InitialOwner} from "../../../src/AccountDeployer.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract DelegateVerifierTest is AccountConfigurationTest {
    uint256 constant DELEGATE_PK = 42;
    uint256 constant DELEGATOR_PK = 43;

    function test_verify_validDelegation() public {
        (address delegateAccount, bytes32 delegateOwnerId) = _createK1Account(DELEGATE_PK);

        address delegateSigner = vm.addr(DELEGATOR_PK);
        bytes32 delegatorOwnerId = bytes32(bytes20(delegateSigner));
        bytes32 delegateRefOwnerId = bytes32(bytes20(delegateAccount));

        InitialOwner[] memory owners = new InitialOwner[](2);
        if (delegatorOwnerId < delegateRefOwnerId) {
            owners[0] = InitialOwner({verifier: address(k1Verifier), ownerId: delegatorOwnerId});
            owners[1] = InitialOwner({verifier: address(delegateVerifier), ownerId: delegateRefOwnerId});
        } else {
            owners[0] = InitialOwner({verifier: address(delegateVerifier), ownerId: delegateRefOwnerId});
            owners[1] = InitialOwner({verifier: address(k1Verifier), ownerId: delegatorOwnerId});
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address delegatorAccount = accountConfiguration.createAccount(bytes32(uint256(1)), bytecode, owners);

        bytes32 hash = keccak256("delegate test");
        bytes memory delegateSig = _signDigest(DELEGATE_PK, hash);

        // delegate data: delegate_address (20) || nested_verifier_type (1) || nested_data
        bytes memory data = abi.encodePacked(delegateAccount, uint8(0x01), delegateSig);

        bytes32 ownerId = delegateVerifier.verify(hash, data);
        assertEq(ownerId, delegateRefOwnerId);
    }

    function test_verify_revertsOnTooShortData() public {
        bytes32 hash = keccak256("test");

        vm.expectRevert();
        delegateVerifier.verify(hash, hex"");
    }

    function test_verify_revertsOnUnauthorizedNestedOwner() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        bytes32 hash = keccak256("test");

        bytes memory fakeSig = _signDigest(999, hash);
        bytes memory data = abi.encodePacked(delegateAccount, uint8(0x01), fakeSig);

        vm.expectRevert();
        delegateVerifier.verify(hash, data);
    }

    function test_verify_revertsOnDoubleDelegate() public {
        (address accountA,) = _createK1Account(DELEGATE_PK);

        bytes32 delegateRefA = bytes32(bytes20(accountA));
        InitialOwner[] memory ownersB = new InitialOwner[](1);
        ownersB[0] = InitialOwner({verifier: address(delegateVerifier), ownerId: delegateRefA});
        bytes memory bytecodeB = _computeERC1167Bytecode(defaultAccountImplementation);
        address accountB = accountConfiguration.createAccount(bytes32(uint256(10)), bytecodeB, ownersB);

        bytes32 delegateRefB = bytes32(bytes20(accountB));
        InitialOwner[] memory ownersC = new InitialOwner[](1);
        ownersC[0] = InitialOwner({verifier: address(delegateVerifier), ownerId: delegateRefB});
        bytes memory bytecodeC = _computeERC1167Bytecode(defaultAccountImplementation);
        accountConfiguration.createAccount(bytes32(uint256(20)), bytecodeC, ownersC);

        bytes32 hash = keccak256("double delegate test");
        bytes memory k1Sig = _signDigest(DELEGATE_PK, hash);

        // Single-hop B → A: should work
        bytes memory singleHopData = abi.encodePacked(accountA, uint8(0x01), k1Sig);
        bytes32 ownerId = delegateVerifier.verify(hash, singleHopData);
        assertEq(ownerId, delegateRefA);

        // Double-hop C → B → A: nested_verifier is DELEGATE (0x04) → triggers 1-hop limit
        bytes memory doubleHopData = abi.encodePacked(accountB, uint8(0x04), singleHopData);
        vm.expectRevert();
        delegateVerifier.verify(hash, doubleHopData);
    }
}
