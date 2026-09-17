// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";
import {Call, ICallTransformer} from "../../src/interfaces/ICallTransformer.sol";

/// @notice Test transformer that encodes the first call as a single {DefaultAccount.execute}, proving the manager can
///         drive an account through a non-default execution entrypoint the binding selects.
contract ExecuteTransformer is ICallTransformer {
    function transform(address, Call[] calldata calls) external pure returns (bytes memory) {
        return abi.encodeCall(DefaultAccount.execute, (calls[0].target, calls[0].value, calls[0].data));
    }
}
