// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC7821} from "../interfaces/IERC7821.sol";
import {Call} from "../interfaces/IExecuteBatch.sol";
import {PolicyManager} from "./PolicyManager.sol";

/// @title ERC7821PolicyManager
///
/// @notice {PolicyManager} variant for accounts exposing the ERC-7821 `execute(bytes32,bytes)` batch entrypoint
///         instead of the default `executeBatch(Call[])`.
///
/// @dev Illustrates the "override the encoding, deploy an instance" model for supporting diverging wallet ABIs. An
///      account opts into this encoding by gating its policy actor to an instance of this manager (via
///      `policy_manager`), exactly as it would the default manager. Because policies self-authenticate against the
///      Keystore, the SAME shared policy instances work under this manager and the default one — no per-manager
///      policy redeployment. 7579 / Safe / ZeroDev support would follow the same shape.
///
/// @author Coinbase
contract ERC7821PolicyManager is PolicyManager {
    /// @dev ERC-7821 batch execution mode (single batch, no `opData`).
    bytes32 internal constant MODE_BATCH = 0x0100000000000000000000000000000000000000000000000000000000000000;

    constructor(address keystore) PolicyManager(keystore) {}

    /// @dev Encodes `execute(MODE_BATCH, abi.encode(calls))`. The ERC-7821 batch element (address, uint256, bytes) is
    ///      ABI-identical to {Call}, so the plan encodes directly.
    function _encodeCalls(address account, Call[] memory calls) internal pure override returns (bytes memory) {
        account;
        return abi.encodeCall(IERC7821.execute, (MODE_BATCH, abi.encode(calls)));
    }
}
