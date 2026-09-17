// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Call, ICallTransformer} from "../../src/interfaces/ICallTransformer.sol";

/// @notice Test transformer that returns empty calldata, exercising the manager's {EmptyTransformerOutput} guard.
contract EmptyOutputTransformer is ICallTransformer {
    function transform(address, Call[] calldata) external pure returns (bytes memory) {
        return "";
    }
}
