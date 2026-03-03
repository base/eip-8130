// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IVerifier} from "./IVerifier.sol";

contract K1Verifier is IVerifier {
    function verifyIntent(address account, bytes32 ownerId, bytes32 hash, bytes calldata data)
        external
        pure
        returns (bool)
    {
        // Commitment must be a valid address
        address owner = address(bytes20(ownerId));
        require(bytes32(bytes20(owner)) == ownerId);

        // Signature must not be malleable
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(data, (uint8, bytes32, bytes32));
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0); // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol#L176-L184

        // Recover address from signature
        address recovered = ecrecover(hash, v, r, s);

        // Verify recovered address matches ownerId
        return recovered == owner;
    }
}
