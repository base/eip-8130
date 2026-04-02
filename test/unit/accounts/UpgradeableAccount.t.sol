// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {UpgradeableAccount} from "../../../src/accounts/UpgradeableAccount.sol";
import {UpgradeableProxy} from "../../../src/accounts/UpgradeableProxy.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Call} from "../../../src/accounts/DefaultAccount.sol";
import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
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

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });

        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        account = accountConfiguration.createAccount(bytes32(0), proxyBytecode, owners);
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    // ── Proxy basics ──

    function test_proxyDelegatesToDefault() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);

        bytes32 hash = keccak256("test");
        bytes memory authData = _buildK1Auth(OWNER_PK, hash);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_proxyBytecodeLength() public view {
        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        assertEq(proxyBytecode.length, 93);
    }

    function test_deterministicAddress() public {
        address signer = vm.addr(OWNER_PK);
        bytes32 ownerId = bytes32(bytes20(signer));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });

        bytes memory proxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        address predicted = accountConfiguration.computeAddress(bytes32(0), proxyBytecode, owners);

        (address actual,) = _createUpgradeableAccount(OWNER_PK);
        assertEq(actual, predicted);
    }

    // ── Caller authorization ──

    function test_selfIsAlwaysAuthorized() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);
        assertTrue(UpgradeableAccount(payable(account)).isAuthorizedCaller(account));
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
        bytes memory authData = _buildK1Auth(OWNER_PK, hash);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account,) = _createUpgradeableAccount(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory authData = _buildK1Auth(999, hash);

        bytes4 result = UpgradeableAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }
}
