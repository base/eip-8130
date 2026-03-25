// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract DelegateVerifierTest is AccountConfigurationTest {
    uint256 constant DELEGATE_PK = 42;
    uint256 constant DELEGATOR_PK = 43;

    function test_verify_validDelegation() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        address delegateSigner = vm.addr(DELEGATOR_PK);
        bytes32 delegatorOwnerId = bytes32(bytes20(delegateSigner));
        bytes32 delegateRefOwnerId = bytes32(bytes20(delegateAccount));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](2);
        if (delegatorOwnerId < delegateRefOwnerId) {
            owners[0] = AccountConfiguration.InitializeOwner({
                ownerId: delegatorOwnerId,
                config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
            });
            owners[1] = AccountConfiguration.InitializeOwner({
                ownerId: delegateRefOwnerId,
                config: AccountConfiguration.OwnerConfig({verifier: address(delegateVerifier), scopes: 0x00})
            });
        } else {
            owners[0] = AccountConfiguration.InitializeOwner({
                ownerId: delegateRefOwnerId,
                config: AccountConfiguration.OwnerConfig({verifier: address(delegateVerifier), scopes: 0x00})
            });
            owners[1] = AccountConfiguration.InitializeOwner({
                ownerId: delegatorOwnerId,
                config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
            });
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        accountConfiguration.createAccount(bytes32(uint256(1)), bytecode, owners);

        bytes32 hash = keccak256("delegate test");
        bytes memory delegateSig = _signDigest(DELEGATE_PK, hash);

        // delegate data: delegate_address (20) || abi.encode(Verification)
        AccountConfiguration.Verification memory nestedVerif = AccountConfiguration.Verification({
            ownerId: bytes32(bytes20(vm.addr(DELEGATE_PK))), verifierData: delegateSig
        });
        bytes memory data = abi.encodePacked(delegateAccount, abi.encode(nestedVerif));

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
        // Claim DELEGATE_PK's ownerId but supply a wrong sig — verifier returns wrong ownerId
        AccountConfiguration.Verification memory nestedVerif =
            AccountConfiguration.Verification({ownerId: bytes32(bytes20(vm.addr(DELEGATE_PK))), verifierData: fakeSig});
        bytes memory data = abi.encodePacked(delegateAccount, abi.encode(nestedVerif));

        vm.expectRevert();
        delegateVerifier.verify(hash, data);
    }

    function test_verify_revertsOnDoubleDelegate() public {
        (address accountA,) = _createK1Account(DELEGATE_PK);

        bytes32 delegateRefA = bytes32(bytes20(accountA));
        AccountConfiguration.InitializeOwner[] memory ownersB = new AccountConfiguration.InitializeOwner[](1);
        ownersB[0] = AccountConfiguration.InitializeOwner({
            ownerId: delegateRefA,
            config: AccountConfiguration.OwnerConfig({verifier: address(delegateVerifier), scopes: 0x00})
        });
        bytes memory bytecodeB = _computeERC1167Bytecode(defaultAccountImplementation);
        address accountB = accountConfiguration.createAccount(bytes32(uint256(10)), bytecodeB, ownersB);

        bytes32 hash = keccak256("double delegate test");
        bytes memory k1Sig = _signDigest(DELEGATE_PK, hash);

        // Single-hop B → A: should work (accountB's verifier for delegateRefA is k1Verifier... wait)
        // Actually accountB has delegateVerifier for delegateRefA, so this single hop tries
        // to verify with accountA as delegate. accountA has k1Verifier for DELEGATE_PK.
        AccountConfiguration.Verification memory singleVerif =
            AccountConfiguration.Verification({ownerId: bytes32(bytes20(vm.addr(DELEGATE_PK))), verifierData: k1Sig});
        bytes memory singleHopData = abi.encodePacked(accountA, abi.encode(singleVerif));
        bytes32 ownerId = delegateVerifier.verify(hash, singleHopData);
        assertEq(ownerId, delegateRefA);

        // Double-hop: try to use accountB as delegate, claiming delegateRefA as ownerId
        // accountB's verifier for delegateRefA = delegateVerifier = address(this) → 1-hop limit triggers
        bytes memory doubleHopData = abi.encodePacked(accountB, abi.encode(singleVerif));
        vm.expectRevert();
        delegateVerifier.verify(hash, doubleHopData);
    }
}
