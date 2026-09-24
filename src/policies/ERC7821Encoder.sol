// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC7821} from "../interfaces/IERC7821.sol";
import {Call} from "../interfaces/IExecuteBatch.sol";
import {IPolicyCallEncoder} from "../interfaces/IPolicyCallEncoder.sol";

/// @title ERC7821Encoder
///
/// @notice Shared, stateless {IPolicyCallEncoder} for accounts exposing the ERC-7821 `execute(bytes32,bytes)` batch
///         entrypoint instead of the default `executeBatch(Call[])`. A binding selects it by setting
///         `PolicyBinding.transformer = address(thisEncoder)`.
///
/// @dev Replaces the old per-ABI `PolicyManager` subclass model: one deployed encoder instance serves every
///      ERC-7821 account, and because it is pure and reached only by STATICCALL, it holds no authority and never
///      executes. Supporting 7579 / Safe / ZeroDev would be another encoder of the same shape.
///
/// @author Coinbase
contract ERC7821Encoder is IPolicyCallEncoder {
    /// @dev ERC-7821 batch execution mode (single batch, no `opData`).
    bytes32 internal constant MODE_BATCH = 0x0100000000000000000000000000000000000000000000000000000000000000;

    /// @dev Encodes `execute(MODE_BATCH, abi.encode(calls))`. The ERC-7821 batch element (address, uint256, bytes) is
    ///      ABI-identical to {Call}, so the plan encodes directly.
    function encodeCalls(address account, Call[] calldata calls) external pure override returns (bytes memory) {
        account;
        return abi.encodeCall(IERC7821.execute, (MODE_BATCH, abi.encode(calls)));
    }
}
