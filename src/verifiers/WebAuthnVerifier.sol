// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {WebAuthn} from "openzeppelin/utils/cryptography/WebAuthn.sol";

import {IVerifier} from "./IVerifier.sol";

contract WebAuthnVerifier is IVerifier {
    function verifyIntent(address account, bytes32 ownerId, bytes32 hash, bytes calldata data)
        external
        view
        returns (bool)
    {
        (WebAuthn.WebAuthnAuth memory auth, bytes32 x, bytes32 y) =
            abi.decode(data, (WebAuthn.WebAuthnAuth, bytes32, bytes32));
        require(keccak256(abi.encode(x, y)) == ownerId);
        return WebAuthn.verify({challenge: abi.encode(hash), auth: auth, qx: x, qy: y, requireUV: false});
    }
}
