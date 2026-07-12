// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {UpgradeableAccount} from "../../../src/accounts/UpgradeableAccount.sol";
import {UpgradeableProxy} from "../../../src/accounts/UpgradeableProxy.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Call, DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract MockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external pure {
        revert("boom");
    }
}

/// @dev A second implementation for testing upgrades.
contract UpgradeableAccountV2 is UpgradeableAccount {
    constructor(address accountConfiguration) UpgradeableAccount(accountConfiguration) {}

    function isValidSignature(bytes32, bytes calldata) external pure override returns (bytes4) {
        return bytes4(0xdeadbeef);
    }

    function version() external pure returns (uint256) {
        return 2;
    }
}

contract UpgradeableAccountTest is AccountConfigurationTest {
    uint256 constant ACTOR_PK = 100;
    uint256 constant SCOPED_PK = 101;
    MockTarget public target;
    address public upgradeableImpl;

    bytes32 constant SIGNED_UPGRADE_TYPEHASH = keccak256(
        "SignedUpgrade(address account,address fromImplementation,address toImplementation,bytes32 dataHash)"
    );

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
        upgradeableImpl = address(new UpgradeableAccount(address(accountConfiguration)));
    }

    function _createUpgradeableAccount(uint256 pk) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(bytes20(signer));

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({actorId: actorId, authenticator: address(k1Authenticator)});

        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        account = accountConfiguration.createAccount(bytes32(0), proxyBytecode, actors);
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    // ── Proxy basics ──

    function test_proxyDelegatesToDefault() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);

        bytes32 hash = keccak256("test");
        bytes memory authData = _buildK1Auth(ACTOR_PK, hash);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_proxyBytecodeLength() public view {
        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        assertEq(proxyBytecode.length, 93);
    }

    function test_deterministicAddress() public {
        address signer = vm.addr(ACTOR_PK);
        bytes32 actorId = bytes32(bytes20(signer));

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({actorId: actorId, authenticator: address(k1Authenticator)});

        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        address predicted = accountConfiguration.computeAddress(bytes32(0), proxyBytecode, actors);

        (address actual,) = _createUpgradeableAccount(ACTOR_PK);
        assertEq(actual, predicted);
    }

    // ── Caller authorization ──

    function test_selfIsAlwaysAuthorized() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        assertTrue(UpgradeableAccount(payable(account)).isAuthorizedCaller(account));
    }

    // ── executeBatch ──

    function test_executeBatch_success() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);

        vm.prank(account);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (42))));

        assertEq(target.value(), 42);
    }

    function test_executeBatch_withETHValue() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0.5 ether, abi.encodeCall(MockTarget.setValue, (1))));

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_executeBatch_revertsFromUnauthorizedCaller() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);

        vm.prank(address(0xdead));
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    function test_executeBatch_revertsOnFailedCall() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);

        vm.prank(account);
        vm.expectRevert(DefaultAccount.CallFailed.selector);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.reverting, ())));
    }

    // ── UUPS upgrade ──

    /// @dev A plain self-call to upgradeToAndCall must revert: {_authorizeUpgrade} is gated on the one-shot
    ///      `_upgradeAuthorized` flag, not on `msg.sender == address(this)`, so upgrading always requires going
    ///      through {upgradeBySignature}'s CONFIG-scoped signature check.
    function test_upgrade_revertsFromDirectSelfCall() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        vm.prank(account);
        vm.expectRevert(UpgradeableAccount.UpgradeNotInitiated.selector);
        UpgradeableAccount(payable(account)).upgradeToAndCall(address(v2Impl), "");
    }

    function test_upgrade_revertsFromNonSelf() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        vm.prank(address(0xdead));
        vm.expectRevert(UpgradeableAccount.UpgradeNotInitiated.selector);
        UpgradeableAccount(payable(account)).upgradeToAndCall(address(v2Impl), "");
    }

    function test_upgrade_executeBatchStillWorks() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        _signedUpgrade(account, ACTOR_PK, address(0), address(v2Impl), "");

        vm.prank(account);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (999))));

        assertEq(target.value(), 999);
    }

    /// @dev Closes the gap the plain self-call check would otherwise leave open: batching a call to
    ///      `upgradeToAndCall` targeting `address(this)` makes that inner call's `msg.sender == address(this)`
    ///      too, but `executeBatch` never checks CONFIG scope specifically (only that the caller is authorized to
    ///      drive calls at all, e.g. any SENDER-scoped actor) — so this must revert regardless of who can call
    ///      `executeBatch`.
    function test_upgrade_viaExecuteBatch_reverts() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        Call[] memory calls = new Call[](1);
        calls[0] = Call(account, 0, abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(v2Impl), "")));

        vm.prank(account);
        vm.expectRevert(DefaultAccount.CallFailed.selector);
        UpgradeableAccount(payable(account)).executeBatch(calls);
    }

    // ── isValidSignature ──

    function test_isValidSignature_validK1() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory authData = _buildK1Auth(ACTOR_PK, hash);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory authData = _buildK1Auth(999, hash);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }

    // ── upgradeBySignature (owner-signed, compare-and-swap) ──

    function _upgradeDigest(address account, address from, address to, bytes memory data)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(SIGNED_UPGRADE_TYPEHASH, account, from, to, keccak256(data)));
    }

    /// @dev Submits upgradeBySignature as an arbitrary relayer (no prank): the signature is what authorizes it.
    function _signedUpgrade(address account, uint256 pk, address from, address to, bytes memory data) internal {
        bytes32 digest = _upgradeDigest(account, from, to, data);
        bytes memory auth = _buildK1Auth(pk, digest);
        UpgradeableAccount(payable(account)).upgradeBySignature(from, to, data, auth);
    }

    function _addScopedActor(address account, uint256 ownerPk, uint256 newPk, uint8 scope) internal {
        bytes32 newActorId = bytes32(bytes20(vm.addr(newPk)));
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: scope, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(ownerPk, digest)
        );
    }

    function test_upgradeBySignature_fromZero_success() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        // Fresh account: ERC-1967 slot is unset, so the compare-and-swap `from` is address(0).
        _signedUpgrade(account, ACTOR_PK, address(0), address(v2Impl), "");

        assertEq(UpgradeableAccountV2(payable(account)).version(), 2);
    }

    function test_upgradeBySignature_withInitData() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        // `data` is delegatecalled on the new implementation post-upgrade, so the selector must exist there.
        bytes memory initData = abi.encodeCall(UpgradeableAccountV2.version, ());
        _signedUpgrade(account, ACTOR_PK, address(0), address(v2Impl), initData);

        assertEq(UpgradeableAccountV2(payable(account)).version(), 2);
    }

    function test_upgradeBySignature_chained() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2a = new UpgradeableAccountV2(address(accountConfiguration));
        UpgradeableAccountV2 v2b = new UpgradeableAccountV2(address(accountConfiguration));

        _signedUpgrade(account, ACTOR_PK, address(0), address(v2a), "");
        // Second hop: `from` is now the previously installed implementation.
        _signedUpgrade(account, ACTOR_PK, address(v2a), address(v2b), "");

        assertEq(UpgradeableAccountV2(payable(account)).version(), 2);
    }

    function test_upgradeBySignature_anyRelayerCanSubmit() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        bytes32 digest = _upgradeDigest(account, address(0), address(v2Impl), "");
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        vm.prank(address(0xBEEF)); // unrelated relayer
        UpgradeableAccount(payable(account)).upgradeBySignature(address(0), address(v2Impl), "", auth);

        assertEq(UpgradeableAccountV2(payable(account)).version(), 2);
    }

    function test_upgradeBySignature_revertsStaleFrom() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        // Current slot is address(0), but the signature claims `from = upgradeableImpl`.
        bytes32 digest = _upgradeDigest(account, upgradeableImpl, address(v2Impl), "");
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        vm.expectRevert(UpgradeableAccount.UpgradeFromMismatch.selector);
        UpgradeableAccount(payable(account)).upgradeBySignature(upgradeableImpl, address(v2Impl), "", auth);
    }

    function test_upgradeBySignature_revertsReplay() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        bytes32 digest = _upgradeDigest(account, address(0), address(v2Impl), "");
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        UpgradeableAccount(payable(account)).upgradeBySignature(address(0), address(v2Impl), "", auth);

        // Slot now holds v2Impl, so the same signature (from == address(0)) no longer matches: replay fails.
        vm.expectRevert(UpgradeableAccount.UpgradeFromMismatch.selector);
        UpgradeableAccount(payable(account)).upgradeBySignature(address(0), address(v2Impl), "", auth);
    }

    function test_upgradeBySignature_revertsNonConfigScope() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        // Authorize a SIGNER-scoped key (lacks CONFIG), then have it sign an upgrade.
        _addScopedActor(account, ACTOR_PK, SCOPED_PK, accountConfiguration.SCOPE_SIGNER());

        bytes32 digest = _upgradeDigest(account, address(0), address(v2Impl), "");
        bytes memory auth = _buildK1Auth(SCOPED_PK, digest);

        vm.expectRevert(UpgradeableAccount.UpgradeUnauthorized.selector);
        UpgradeableAccount(payable(account)).upgradeBySignature(address(0), address(v2Impl), "", auth);
    }

    function test_upgradeBySignature_configKeySucceeds() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        // A CONFIG key (SCOPE_CONFIG) is authorized to upgrade, even though it is not an unrestricted owner.
        _addScopedActor(account, ACTOR_PK, SCOPED_PK, accountConfiguration.SCOPE_CONFIG());

        _signedUpgrade(account, SCOPED_PK, address(0), address(v2Impl), "");

        assertEq(UpgradeableAccountV2(payable(account)).version(), 2);
    }

    function test_upgradeBySignature_revertsInvalidSignature() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        bytes32 digest = _upgradeDigest(account, address(0), address(v2Impl), "");
        bytes memory badAuth = _buildK1Auth(999, digest); // not an authorized actor

        vm.expectRevert();
        UpgradeableAccount(payable(account)).upgradeBySignature(address(0), address(v2Impl), "", badAuth);
    }

    /// @dev Documents the accepted compare-and-swap ABA caveat (deferred for audit/discussion): if the
    ///      implementation is upgraded away from and later restored to a prior value, a previously-used signature
    ///      for that transition becomes replayable again. There is no deadline; this is the accepted trade-off for
    ///      coordination-free, nonce-less multichain upgrades, on the assumption that downgrades are rare.
    function test_upgradeBySignature_abaReplayIsPossible() public {
        (address account,) = _createUpgradeableAccount(ACTOR_PK);
        UpgradeableAccountV2 v2a = new UpgradeableAccountV2(address(accountConfiguration));
        UpgradeableAccountV2 v2b = new UpgradeableAccountV2(address(accountConfiguration));

        // 0 -> v2a, then cycle v2a -> v2b -> v2a (a downgrade restores the v2a state).
        _signedUpgrade(account, ACTOR_PK, address(0), address(v2a), "");
        _signedUpgrade(account, ACTOR_PK, address(v2a), address(v2b), "");
        _signedUpgrade(account, ACTOR_PK, address(v2b), address(v2a), "");

        // Slot is back at v2a, so a v2a -> v2b signature is honored again (state, not nonce, gates it).
        bytes32 digestAtoB = _upgradeDigest(account, address(v2a), address(v2b), "");
        bytes memory authAtoB = _buildK1Auth(ACTOR_PK, digestAtoB);
        UpgradeableAccount(payable(account)).upgradeBySignature(address(v2a), address(v2b), "", authAtoB);
        assertEq(UpgradeableAccountV2(payable(account)).version(), 2);
    }
}
