// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Nonces {
    mapping(address account => mapping(uint192 key => uint64 sequence)) public getNonce;
}
