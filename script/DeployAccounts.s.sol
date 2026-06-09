// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../src/interfaces/IAccountConfiguration.sol";
import {DefaultAccount, Call} from "../src/accounts/DefaultAccount.sol";
import {DefaultHighRateAccount} from "../src/accounts/DefaultHighRateAccount.sol";
import {UpgradeableAccount} from "../src/accounts/UpgradeableAccount.sol";
import {UpgradeableProxy} from "../src/accounts/UpgradeableProxy.sol";

import {K1Authenticator} from "../src/authenticators/K1Authenticator.sol";

/// @notice Demonstrates deploying all three wallet types via AccountConfiguration.createAccount.
///
///         All wallets share the same actor setup and AccountConfiguration system —
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

        address k1 = address(new K1Authenticator{salt: 0}());
        AccountConfiguration accountConfig = new AccountConfiguration{salt: 0}();

        console.log("AccountConfiguration:", address(accountConfig));
        console.log("K1Authenticator:          ", k1);

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
        //     Each account gets its own address with its own actor set.
        //     The "bytecode" passed to createAccount is the PROXY — a tiny
        //     delegatecall forwarder that points to the implementation above.
        //     The proxy is what lives permanently at the account address.

        address actor = msg.sender;
        bytes32 actorId = bytes32(bytes20(actor));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = IAccountConfiguration.InitialActor({actorId: actorId, authenticator: k1});

        // ── 3a: DefaultAccount (ERC-1167 proxy, 45 bytes) ──
        //
        //     Non-upgradeable. Smallest proxy. Best for 8130-native chains
        //     where 7702 re-delegation handles "upgrades" for EOAs.

        bytes memory erc1167Bytecode =
            abi.encodePacked(hex"363d3d373d3d3d363d73", defaultImpl, hex"5af43d82803e903d91602b57fd5bf3");
        address defaultAccount = accountConfig.createAccount(bytes32(uint256(1)), erc1167Bytecode, actors);

        console.log("");
        console.log("=== Accounts (proxies at these addresses) ===");
        console.log("DefaultAccount:         ", defaultAccount);
        console.log("  proxy size:            45 bytes (ERC-1167)");
        console.log("  upgradeable:           no");

        // ── 3b: DefaultHighRateAccount (ERC-1167 proxy, 45 bytes) ──
        //
        //     Same proxy pattern, different implementation.
        //     Blocks ETH transfers when locked for mempool rate limit benefits.

        bytes memory highRateBytecode =
            abi.encodePacked(hex"363d3d373d3d3d363d73", highRateImpl, hex"5af43d82803e903d91602b57fd5bf3");
        address highRateAccount = accountConfig.createAccount(bytes32(uint256(2)), highRateBytecode, actors);

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
        address upgradeableAccount = accountConfig.createAccount(bytes32(uint256(3)), upgradeableProxyBytecode, actors);

        console.log("UpgradeableAccount:     ", upgradeableAccount);
        console.log("  proxy size:            93 bytes (ERC-1967 + default)");
        console.log("  upgradeable:           yes (UUPS)");

        // ── Step 4: Authenticate accounts work ──

        console.log("");
        console.log("=== Authentication ===");

        IAccountConfiguration.ActorConfig memory actorCfg = accountConfig.getActorConfig(defaultAccount, actorId);
        console.log("DefaultAccount actor authenticator:", actorCfg.authenticator);
        console.log("DefaultAccount actor scope:  ", actorCfg.scope);

        actorCfg = accountConfig.getActorConfig(upgradeableAccount, actorId);
        console.log("UpgradeableAccount actor authenticator:", actorCfg.authenticator);
        console.log("UpgradeableAccount actor scope:  ", actorCfg.scope);

        vm.stopBroadcast();
    }
}
