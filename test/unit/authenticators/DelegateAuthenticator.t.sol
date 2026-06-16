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

    /// @dev EIP-8130 depth-1 constraint: the nested authenticator MUST NOT be the delegate authenticator.
    ///      Exercises the explicit `nestedAuthenticator != address(this)` check, independent of any
    ///      downstream actor-config lookup (no inner actor is registered).
    function test_authenticate_revertsOnNestedAuthenticatorIsDelegate() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        bytes32 hash = keccak256("nested delegate test");

        // Wire format: delegate_address(20) || nested_authenticator(=this)(20) || arbitrary bytes
        bytes memory nestedAuth = abi.encodePacked(address(delegateAuthenticator), hex"00");
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert();
        delegateAuthenticator.authenticate(hash, data);
    }

    /// @dev EIP-8130 requires the nested check to run in B's SIGNATURE context. A nested actor on B
    ///      whose scope lacks the SIGNATURE bit (e.g. PAYER-only) must not be usable to vouch for A.
    function test_authenticate_revertsOnNestedActorWithoutSignerScope() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        // Authorize a PAYER-only second key on the delegate account; the owner key signs the change.
        uint256 payerOnlyPk = 44;
        bytes32 payerOnlyActorId = bytes32(bytes20(vm.addr(payerOnlyPk)));
        _authorizeActorOnAccount(
            delegateAccount, DELEGATE_PK, payerOnlyActorId, address(k1Authenticator), accountConfiguration.SCOPE_PAYER()
        );

        bytes32 hash = keccak256("payer-scope rejection test");
        bytes memory payerSig = _signDigest(payerOnlyPk, hash);

        bytes memory nestedAuth = abi.encodePacked(address(k1Authenticator), payerSig);
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert();
        delegateAuthenticator.authenticate(hash, data);
    }

    /// @dev Positive control: a nested actor explicitly authorized with SIGNATURE-only scope authenticates.
    function test_authenticate_succeedsWithNestedActorSignerScope() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);

        uint256 signerOnlyPk = 45;
        bytes32 signerOnlyActorId = bytes32(bytes20(vm.addr(signerOnlyPk)));
        _authorizeActorOnAccount(
            delegateAccount,
            DELEGATE_PK,
            signerOnlyActorId,
            address(k1Authenticator),
            accountConfiguration.SCOPE_SIGNER()
        );

        bytes32 hash = keccak256("signer-scope success test");
        bytes memory signerSig = _signDigest(signerOnlyPk, hash);

        bytes memory nestedAuth = abi.encodePacked(address(k1Authenticator), signerSig);
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        bytes32 actorId = delegateAuthenticator.authenticate(hash, data);
        assertEq(actorId, bytes32(bytes20(delegateAccount)));
    }

    function _authorizeActorOnAccount(
        address account,
        uint256 ownerPk,
        bytes32 newActorId,
        address authenticator,
        uint8 scope
    ) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    authenticator: authenticator, scope: scope, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }
}
