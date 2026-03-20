// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {UpgradeableAccount} from "../../../src/accounts/UpgradeableAccount.sol";
import {UpgradeableProxy} from "../../../src/accounts/UpgradeableProxy.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Call, EXTERNAL_CALLER_VERIFIER} from "../../../src/accounts/DefaultAccount.sol";
import {InitialOwner} from "../../../src/AccountDeployer.sol";
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

/// @dev A second implementation for testing upgrades. Identical interface,
///      but returns a different magic value from isValidSignature to prove
///      the upgrade took effect.
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
    uint256 constant OWNER_PK = 100;
    MockTarget public target;
    address public upgradeableImpl;

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
        upgradeableImpl = address(new UpgradeableAccount(address(accountConfiguration)));
    }

    function _createUpgradeableAccount(uint256 pk) internal returns (address account, bytes32 ownerId) {
        address signer = vm.addr(pk);
        ownerId = bytes32(bytes20(signer));

        InitialOwner[] memory owners = new InitialOwner[](1);
        owners[0] = InitialOwner({verifier: address(k1Verifier), ownerId: ownerId, scope: 0x00});

        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        account = accountConfiguration.createAccount(bytes32(0), proxyBytecode, owners);
    }

    function _createUpgradeableAccountWithExternalCaller(uint256 pk, address caller)
        internal
        returns (address account, bytes32 ownerId)
    {
        address signer = vm.addr(pk);
        ownerId = bytes32(bytes20(signer));
        bytes32 callerOwnerId = bytes32(bytes20(caller));
        address ecv = EXTERNAL_CALLER_VERIFIER;

        InitialOwner[] memory owners = new InitialOwner[](2);

        if (ownerId < callerOwnerId) {
            owners[0] = InitialOwner({verifier: address(k1Verifier), ownerId: ownerId, scope: 0x00});
            owners[1] = InitialOwner({verifier: ecv, ownerId: callerOwnerId, scope: 0x00});
        } else {
            owners[0] = InitialOwner({verifier: ecv, ownerId: callerOwnerId, scope: 0x00});
            owners[1] = InitialOwner({verifier: address(k1Verifier), ownerId: ownerId, scope: 0x00});
        }

        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        account = accountConfiguration.createAccount(bytes32(uint256(0xcc)), proxyBytecode, owners);
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    // ── Proxy basics ──

    function test_proxyDelegatesToDefault() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);

        bytes32 hash = keccak256("test");
        bytes memory sig = _signDigest(OWNER_PK, hash);
        bytes memory authData = abi.encodePacked(uint8(0x01), sig);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_proxyBytecodeLength() public {
        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        assertEq(proxyBytecode.length, 93);
    }

    function test_deterministicAddress() public {
        address signer = vm.addr(OWNER_PK);
        bytes32 ownerId = bytes32(bytes20(signer));

        InitialOwner[] memory owners = new InitialOwner[](1);
        owners[0] = InitialOwner({verifier: address(k1Verifier), ownerId: ownerId, scope: 0x00});

        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        address predicted = accountConfiguration.getAddress(bytes32(0), proxyBytecode, owners);

        (address actual,) = _createUpgradeableAccount(OWNER_PK);
        assertEq(actual, predicted);
    }

    // ── Caller authorization ──

    function test_selfIsAlwaysAuthorized() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);
        assertTrue(UpgradeableAccount(payable(account)).isAuthorizedCaller(account));
    }

    function test_externalCallerAuthorized() public {
        address policyManager = address(0xBBBB);
        (address account,) = _createUpgradeableAccountWithExternalCaller(OWNER_PK, policyManager);
        assertTrue(UpgradeableAccount(payable(account)).isAuthorizedCaller(policyManager));
    }

    function test_unregisteredCallerNotAuthorized() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);
        assertFalse(UpgradeableAccount(payable(account)).isAuthorizedCaller(address(0xdead)));
    }

    // ── executeBatch ──

    function test_executeBatch_success() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);

        vm.prank(account);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (42))));

        assertEq(target.value(), 42);
    }

    function test_executeBatch_withETHValue() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0.5 ether, abi.encodeCall(MockTarget.setValue, (1))));

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_executeBatch_fromExternalCaller() public {
        address policyManager = address(0xBBBB);
        (address account,) = _createUpgradeableAccountWithExternalCaller(OWNER_PK, policyManager);

        vm.prank(policyManager);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (77))));

        assertEq(target.value(), 77);
    }

    function test_executeBatch_revertsFromUnauthorizedCaller() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);

        vm.prank(address(0xdead));
        vm.expectRevert();
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    function test_executeBatch_revertsOnFailedCall() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);

        vm.prank(account);
        vm.expectRevert();
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.reverting, ())));
    }

    // ── UUPS upgrade ──

    function test_upgrade_success() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        vm.prank(account);
        UpgradeableAccount(payable(account)).upgradeToAndCall(address(v2Impl), "");

        assertEq(UpgradeableAccountV2(payable(account)).version(), 2);
        assertEq(UpgradeableAccountV2(payable(account)).isValidSignature(bytes32(0), ""), bytes4(0xdeadbeef));
    }

    function test_upgrade_preservesCallerAuth() public {
        address policyManager = address(0xBBBB);
        (address account,) = _createUpgradeableAccountWithExternalCaller(OWNER_PK, policyManager);

        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        vm.prank(account);
        UpgradeableAccount(payable(account)).upgradeToAndCall(address(v2Impl), "");

        assertTrue(UpgradeableAccount(payable(account)).isAuthorizedCaller(policyManager));
    }

    function test_upgrade_revertsFromNonSelf() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        vm.prank(address(0xdead));
        vm.expectRevert();
        UpgradeableAccount(payable(account)).upgradeToAndCall(address(v2Impl), "");
    }

    function test_upgrade_executeBatchStillWorks() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        vm.prank(account);
        UpgradeableAccount(payable(account)).upgradeToAndCall(address(v2Impl), "");

        vm.prank(account);
        UpgradeableAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (999))));

        assertEq(target.value(), 999);
    }

    function test_upgrade_viaExecuteBatch() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);
        UpgradeableAccountV2 v2Impl = new UpgradeableAccountV2(address(accountConfiguration));

        Call[] memory calls = new Call[](1);
        calls[0] = Call(account, 0, abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(v2Impl), "")));

        vm.prank(account);
        UpgradeableAccount(payable(account)).executeBatch(calls);

        assertEq(UpgradeableAccountV2(payable(account)).version(), 2);
    }

    // ── isValidSignature ──

    function test_isValidSignature_validK1() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory sig = _signDigest(OWNER_PK, hash);
        bytes memory authData = abi.encodePacked(uint8(0x01), sig);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory wrongSig = _signDigest(999, hash);
        bytes memory authData = abi.encodePacked(uint8(0x01), wrongSig);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }
}
