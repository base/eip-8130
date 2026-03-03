// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IInitialized {
    function initialized() external pure returns (bool);
}
