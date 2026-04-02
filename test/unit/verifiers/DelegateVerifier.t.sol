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
        bytes32 delegatorOwnerId = bytes32(bytes20(delegateSigner));
        bytes32 delegateRefOwnerId = bytes32(bytes20(delegateAccount));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](2);
        if (delegatorOwnerId < delegateRefOwnerId) {
            owners[0] = IAccountConfiguration.Owner({
                ownerId: delegatorOwnerId,
                config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
            });
            owners[1] = IAccountConfiguration.Owner({
                ownerId: delegateRefOwnerId,
                config: IAccountConfiguration.OwnerConfig({verifier: address(delegateVerifier), scopes: 0x00})
            });
        } else {
            owners[0] = IAccountConfiguration.Owner({
                ownerId: delegateRefOwnerId,
                config: IAccountConfiguration.OwnerConfig({verifier: address(delegateVerifier), scopes: 0x00})
            });
            owners[1] = IAccountConfiguration.Owner({
                ownerId: delegatorOwnerId,
                config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
            });
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        accountConfiguration.createAccount(bytes32(uint256(1)), bytecode, owners);

        bytes32 hash = keccak256("delegate test");
        bytes memory delegateSig = _signDigest(DELEGATE_PK, hash);

        // Nested auth: k1Verifier(20) || sig
        bytes memory nestedAuth = abi.encodePacked(address(k1Verifier), delegateSig);
        // delegate data: delegate_address(20) || nestedAuth
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

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
        // Nested auth with wrong signer — verifier recovers wrong address
        bytes memory nestedAuth = abi.encodePacked(address(k1Verifier), fakeSig);
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert();
        delegateVerifier.verify(hash, data);
    }

    function test_verify_revertsOnDoubleDelegate() public {
        (address accountA,) = _createK1Account(DELEGATE_PK);

        bytes32 delegateRefA = bytes32(bytes20(accountA));
        IAccountConfiguration.Owner[] memory ownersB = new IAccountConfiguration.Owner[](1);
        ownersB[0] = IAccountConfiguration.Owner({
            ownerId: delegateRefA,
            config: IAccountConfiguration.OwnerConfig({verifier: address(delegateVerifier), scopes: 0x00})
        });
        bytes memory bytecodeB = _computeERC1167Bytecode(defaultAccountImplementation);
        address accountB = accountConfiguration.createAccount(bytes32(uint256(10)), bytecodeB, ownersB);

        bytes32 hash = keccak256("double delegate test");
        bytes memory k1Sig = _signDigest(DELEGATE_PK, hash);

        // Single-hop B → A: should work
        bytes memory nestedAuth = abi.encodePacked(address(k1Verifier), k1Sig);
        bytes memory singleHopData = abi.encodePacked(accountA, nestedAuth);
        bytes32 ownerId = delegateVerifier.verify(hash, singleHopData);
        assertEq(ownerId, delegateRefA);

        // Double-hop: try to use accountB as delegate — 1-hop limit triggers
        bytes memory doubleHopData = abi.encodePacked(accountB, nestedAuth);
        vm.expectRevert();
        delegateVerifier.verify(hash, doubleHopData);
    }
}
