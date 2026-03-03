// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract AccountProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory data) ERC1967Proxy(implementation, data) {}

    /// @notice Allow the proxy to accept empty bytecode on deployment
    /// @dev Owner configuration done by AccountConfiguration contract at creation time
    function _unsafeAllowUninitialized() internal pure override returns (bool) {
        return true;
    }
}
