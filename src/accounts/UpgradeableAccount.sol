// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

import {DefaultAccount} from "./DefaultAccount.sol";

/// @notice UUPS-upgradeable variant of DefaultAccount.
///
///         Adds upgradeToAndCall from Solady's UUPSUpgradeable. Everything else
///         (executeBatch, isValidSignature, caller authorization) is inherited.
///
///         Deploy behind an UpgradeableProxy instead of ERC-1167.
///         7702 accounts don't need this — they can re-delegate anytime.
contract UpgradeableAccount is DefaultAccount, UUPSUpgradeable {
    constructor(address accountConfiguration) DefaultAccount(accountConfiguration) {}

    function _authorizeUpgrade(address) internal view override {
        require(msg.sender == address(this));
    }
}
