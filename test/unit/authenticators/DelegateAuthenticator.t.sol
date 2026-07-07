// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract DelegateAuthenticatorTest is AccountConfigurationTest {
    uint256 constant DELEGATE_PK = 42;
    uint256 constant DELEGATOR_PK = 43;

    function test_authenticate_validDelegation() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        address delegateSigner = vm.addr(DELEGATOR_PK);
        bytes32 delegatorActorId = bytes32(bytes20(delegateSigner));
        bytes32 delegateRefActorId = bytes32(bytes20(delegateAccount));

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](2);
        if (delegatorActorId < delegateRefActorId) {
            actors[0] =
                AccountConfiguration.InitialActor({actorId: delegatorActorId, authenticator: address(k1Authenticator)});
            actors[1] = AccountConfiguration.InitialActor({
                actorId: delegateRefActorId, authenticator: address(delegateAuthenticator)
            });
        } else {
            actors[0] = AccountConfiguration.InitialActor({
                actorId: delegateRefActorId, authenticator: address(delegateAuthenticator)
            });
            actors[1] =
                AccountConfiguration.InitialActor({actorId: delegatorActorId, authenticator: address(k1Authenticator)});
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
        AccountConfiguration.InitialActor[] memory actorsB = new AccountConfiguration.InitialActor[](1);
        actorsB[0] =
            AccountConfiguration.InitialActor({actorId: delegateRefA, authenticator: address(delegateAuthenticator)});
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

    function test_authenticate_revertsWhenNestedSignerLacksSignatureScope() public {
        // Account B: unrestricted owner (DELEGATE_PK) plus a second key scoped to PAYER only.
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);
        _authorizeScopedK1Actor(delegateAccount, DELEGATE_PK, DELEGATOR_PK, SCOPE_PAYER);

        bytes32 hash = keccak256("scoped delegate test");
        // The PAYER-only key is a valid, bound actor on B, but lacks SIGNATURE scope.
        bytes memory nestedAuth = abi.encodePacked(address(k1Authenticator), _signDigest(DELEGATOR_PK, hash));
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        // Delegation now gates SCOPE_SIGNER (verifySignature), so a non-SIGNATURE key must revert.
        vm.expectRevert();
        delegateAuthenticator.authenticate(hash, data);
    }

    function test_authenticate_succeedsWhenNestedSignerHasSignatureScope() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);
        _authorizeScopedK1Actor(delegateAccount, DELEGATE_PK, DELEGATOR_PK, SCOPE_SIGNER);

        bytes32 hash = keccak256("scoped delegate test");
        bytes memory nestedAuth = abi.encodePacked(address(k1Authenticator), _signDigest(DELEGATOR_PK, hash));
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        bytes32 actorId = delegateAuthenticator.authenticate(hash, data);
        assertEq(actorId, bytes32(bytes20(delegateAccount)));
    }

    uint8 constant SCOPE_SIGNER = 0x01;
    uint8 constant SCOPE_PAYER = 0x04;
    uint8 constant AUTHORIZE_ACTOR = 0x01;

    /// @dev Authorizes a new K1 actor (`newPk`) with `scope` on `account`, signed by the
    ///      unrestricted owner (`ownerPk`) via applySignedActorChanges on the local chain.
    function _authorizeScopedK1Actor(address account, uint256 ownerPk, uint256 newPk, uint8 scope) internal {
        AccountConfiguration.ActorConfig memory config = AccountConfiguration.ActorConfig({
            authenticator: address(k1Authenticator), scope: scope, expiry: 0, policyType: 0
        });

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            changeType: AUTHORIZE_ACTOR, actorId: bytes32(bytes20(vm.addr(newPk))), data: abi.encode(config, bytes(""))
        });

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ownerPk, digest));
    }
}
