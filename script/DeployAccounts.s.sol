// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {InitialOwner} from "../src/AccountDeployer.sol";

import {DefaultAccount, Call} from "../src/accounts/DefaultAccount.sol";
import {DefaultHighRateAccount} from "../src/accounts/DefaultHighRateAccount.sol";
import {UpgradeableAccount} from "../src/accounts/UpgradeableAccount.sol";
import {UpgradeableProxy} from "../src/accounts/UpgradeableProxy.sol";

import {K1Verifier} from "../src/verifiers/K1Verifier.sol";

/// @notice Demonstrates deploying all three wallet types via AccountConfiguration.createAccount.
///
///         All wallets share the same owner setup and AccountConfiguration system —
///         they differ only in the proxy bytecode placed at the account address.
///
///         Wallet types:
///           1. DefaultAccount        — ERC-1167 proxy (45 bytes), not upgradeable
///           2. DefaultHighRateAccount — ERC-1167 proxy (45 bytes), not upgradeable, blocks ETH when locked
///           3. UpgradeableAccount     — ERC-1967 proxy (93 bytes), UUPS upgradeable
contract DeployAccounts is Script {
    function run() public {
        vm.startBroadcast();

        // ── Step 1: Deploy system infrastructure (once per chain) ──

        address k1 = address(new K1Verifier{salt: 0}());
        AccountConfiguration accountConfig = new AccountConfiguration{salt: 0}(k1, address(0), address(0), address(0));

        console.log("AccountConfiguration:", address(accountConfig));
        console.log("K1Verifier:          ", k1);

        // ── Step 2: Deploy wallet implementations (once per chain) ──
        //
        //     These are singleton contracts. Every account delegates to one of them.

        address defaultImpl = address(new DefaultAccount{salt: 0}(address(accountConfig)));
        address highRateImpl = address(new DefaultHighRateAccount{salt: 0}(address(accountConfig)));
        address upgradeableImpl = address(new UpgradeableAccount{salt: 0}(address(accountConfig)));

        console.log("");
        console.log("=== Implementations (singletons) ===");
        console.log("DefaultAccount impl:        ", defaultImpl);
        console.log("DefaultHighRateAccount impl:", highRateImpl);
        console.log("UpgradeableAccount impl:    ", upgradeableImpl);

        // ── Step 3: Create accounts ──
        //
        //     Each account gets its own address with its own owner set.
        //     The "bytecode" passed to createAccount is the PROXY — a tiny
        //     delegatecall forwarder that points to the implementation above.
        //     The proxy is what lives permanently at the account address.

        address owner = msg.sender;
        bytes32 ownerId = bytes32(bytes20(owner));

        InitialOwner[] memory owners = new InitialOwner[](1);
        owners[0] = InitialOwner({verifier: k1, ownerId: ownerId, scope: 0x00});

        // ── 3a: DefaultAccount (ERC-1167 proxy, 45 bytes) ──
        //
        //     Non-upgradeable. Smallest proxy. Best for 8130-native chains
        //     where 7702 re-delegation handles "upgrades" for EOAs.

        bytes memory erc1167Bytecode = accountConfig.computeERC1167Bytecode(defaultImpl);
        address defaultAccount = accountConfig.createAccount(bytes32(uint256(1)), erc1167Bytecode, owners);

        console.log("");
        console.log("=== Accounts (proxies at these addresses) ===");
        console.log("DefaultAccount:         ", defaultAccount);
        console.log("  proxy size:            45 bytes (ERC-1167)");
        console.log("  upgradeable:           no");

        // ── 3b: DefaultHighRateAccount (ERC-1167 proxy, 45 bytes) ──
        //
        //     Same proxy pattern, different implementation.
        //     Blocks ETH transfers when locked for mempool rate limit benefits.

        bytes memory highRateBytecode = accountConfig.computeERC1167Bytecode(highRateImpl);
        address highRateAccount = accountConfig.createAccount(bytes32(uint256(2)), highRateBytecode, owners);

        console.log("DefaultHighRateAccount: ", highRateAccount);
        console.log("  proxy size:            45 bytes (ERC-1167)");
        console.log("  upgradeable:           no");

        // ── 3c: UpgradeableAccount (ERC-1967 proxy, 93 bytes) ──
        //
        //     Uses the UpgradeableProxy library to generate a proxy that:
        //       - SLOADs the ERC-1967 implementation slot
        //       - If empty (fresh deploy): delegates to hardcoded default (upgradeableImpl)
        //       - If set (post-upgrade): delegates to stored implementation
        //
        //     The 48-byte overhead vs ERC-1167 buys UUPS upgradeability.
        //     To upgrade later: account calls upgradeToAndCall(newImpl, "").

        bytes memory upgradeableProxyBytecode = UpgradeableProxy.bytecode(upgradeableImpl);
        address upgradeableAccount = accountConfig.createAccount(bytes32(uint256(3)), upgradeableProxyBytecode, owners);

        console.log("UpgradeableAccount:     ", upgradeableAccount);
        console.log("  proxy size:            93 bytes (ERC-1967 + default)");
        console.log("  upgradeable:           yes (UUPS)");

        // ── Step 4: Verify accounts work ──

        console.log("");
        console.log("=== Verification ===");

        (address verifier, uint8 scope) = accountConfig.getOwner(defaultAccount, ownerId);
        console.log("DefaultAccount owner verifier:", verifier);
        console.log("DefaultAccount owner scope:   ", scope);

        (verifier, scope) = accountConfig.getOwner(upgradeableAccount, ownerId);
        console.log("UpgradeableAccount owner verifier:", verifier);
        console.log("UpgradeableAccount owner scope:   ", scope);

        vm.stopBroadcast();
    }
}
