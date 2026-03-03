// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {IInitialized} from "./IInitialized.sol";

contract Account is IInitialized, UUPSUpgradeable {
    struct Call {
        address target;
        bytes data;
        uint256 value;
    }

    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    function initialized() external pure virtual returns (bool) {
        // TODO: weird to have this implicitly true?
        return true;
    }

    modifier onlyAdmin() {
        require(
            msg.sender == address(this) || ACCOUNT_CONFIGURATION.isOwner(address(this), bytes32(bytes20(msg.sender)))
        );
        _;
    }

    function executeBatch(Call[] calldata calls) external onlyAdmin {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory data) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success);
        }
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}
}
