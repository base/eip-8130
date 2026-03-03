// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {UUPSUpgradeable} from "openzeppelin/proxy/utils/UUPSUpgradeable.sol";
import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {IInitialized} from "./IInitialized.sol";

contract DefaultAccount is IInitialized, UUPSUpgradeable, Receiver {
    struct Call {
        address target;
        bytes data;
        uint256 value;
    }

    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
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

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bool) {
        (bytes32 ownerId, bytes memory data) = abi.decode(signature, (bytes32, bytes));
        return ACCOUNT_CONFIGURATION.verifyIntent(address(this), ownerId, hash, data);
    }

    /// @dev Only initialization required are owner additions handled by AccountConfiguration
    function initialized() external pure virtual returns (bool) {
        return true;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}
}
