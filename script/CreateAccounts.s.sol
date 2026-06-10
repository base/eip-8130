// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../src/interfaces/IAccountConfiguration.sol";
import {ERC4337Account} from "../src/accounts/BackwardCompatibleERC4337Account.sol";

/// @dev Nick's deterministic deployment proxy — same address on every EVM chain.
address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

bytes32 constant SALT = bytes32(0);

/// @notice Creates a DefaultAccount and a backward-compatible ERC-4337 account on top of the
///         canonical EIP-8130 system already deployed on Base Sepolia.
///
/// @dev Reuses the canonical AccountConfiguration / DefaultAccount impl / K1Authenticator from
///      Deploy.s.sol (CREATE2 via Nick's factory). The backward-compatible ERC-4337 implementation
///      is not part of Deploy.s.sol, so it is deployed here (also deterministically) before creating
///      an account proxy pointing at it.
contract CreateAccounts is Script {
    // ── Canonical addresses already deployed on Base Sepolia (see Deploy.s.sol) ──
    address constant ACCOUNT_CONFIG = 0xe6BB4A62034c4F7494A411E28d0a18B1BB55DEE6;
    address constant DEFAULT_IMPL = 0xE69fca5270f01c40E9884E503a9961195438E6fD;
    address constant K1 = 0x39221FB37Df105B22316328e88632C9684861466;

    // Canonical ERC-4337 v0.7 EntryPoint (same address on every chain).
    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function _addr(bytes memory initCode) internal pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), CREATE2_FACTORY, SALT, keccak256(initCode)))))
        );
    }

    function _create2(bytes memory initCode) internal returns (address addr) {
        addr = _addr(initCode);
        if (addr.code.length > 0) return addr;
        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(SALT, initCode));
        require(ok && addr.code.length > 0, "create2 deployment failed");
    }

    /// @dev ERC-1167 minimal proxy (45 bytes) pointing at `impl`.
    function _erc1167(address impl) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3");
    }

    function run() public {
        vm.startBroadcast();

        AccountConfiguration config = AccountConfiguration(ACCOUNT_CONFIG);

        // The deployer EOA is the initial owner actor, authenticated via the canonical K1Authenticator.
        bytes32 actorId = bytes32(bytes20(msg.sender));
        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = IAccountConfiguration.InitialActor({actorId: actorId, authenticator: K1});

        // ── DefaultAccount (ERC-1167 proxy -> canonical DefaultAccount impl) ──
        address defaultAccount = config.createAccount(bytes32(uint256(0x8130)), _erc1167(DEFAULT_IMPL), actors);

        // ── Backward-compatible ERC-4337 account ──
        // Deploy the ERC4337Account implementation deterministically, then an ERC-1167 proxy to it.
        bytes memory erc4337Init =
            abi.encodePacked(type(ERC4337Account).creationCode, abi.encode(ACCOUNT_CONFIG, ENTRY_POINT));
        address erc4337Impl = _create2(erc4337Init);
        address erc4337Account = config.createAccount(bytes32(uint256(0x4337)), _erc1167(erc4337Impl), actors);

        console.log("Owner actor (deployer):     ", msg.sender);
        console.log("EntryPoint (v0.7):          ", ENTRY_POINT);
        console.log("");
        console.log("ERC4337Account impl:        ", erc4337Impl);
        console.log("DefaultAccount:             ", defaultAccount);
        console.log("ERC4337 BackwardCompat acct:", erc4337Account);

        vm.stopBroadcast();
    }
}
