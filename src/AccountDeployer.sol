// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

struct InitialOwner {
    address verifier;
    bytes32 ownerId;
    uint8 scope;
}

/// @notice Pure deployment utilities for EIP-8130 account creation.
///         Handles CREATE2 address derivation, deployment header construction, and ERC-1167 bytecode.
abstract contract AccountDeployer {
    /// @notice Compute the counterfactual address for an account.
    function getAddress(bytes32 userSalt, bytes calldata bytecode, InitialOwner[] calldata initialOwners)
        public
        view
        returns (address)
    {
        bytes32 effectiveSalt = _computeEffectiveSalt(userSalt, initialOwners);
        bytes32 codeHash = keccak256(_buildDeploymentCode(bytecode));
        return
            address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xFF), address(this), effectiveSalt, codeHash)))));
    }

    /// @notice Compute ERC-1167 minimal proxy bytecode for a given implementation.
    function computeERC1167Bytecode(address implementation) external pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    function _deploy(bytes calldata bytecode, InitialOwner[] calldata initialOwners, bytes32 userSalt) internal {
        bytes memory deploymentCode = _buildDeploymentCode(bytecode);
        bytes32 effectiveSalt = _computeEffectiveSalt(userSalt, initialOwners);
        assembly {
            pop(create2(0, add(deploymentCode, 0x20), mload(deploymentCode), effectiveSalt))
        }
    }

    function _computeOwnersCommitment(InitialOwner[] calldata owners) internal pure returns (bytes32) {
        bytes memory data;
        for (uint256 i; i < owners.length; i++) {
            data = abi.encodePacked(data, owners[i].ownerId, owners[i].verifier, owners[i].scope);
        }
        return keccak256(data);
    }

    function _computeEffectiveSalt(bytes32 userSalt, InitialOwner[] calldata initialOwners)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(userSalt, _computeOwnersCommitment(initialOwners)));
    }

    /// @dev Constructs DEPLOYMENT_HEADER(n) || bytecode. The 14-byte EVM loader
    ///      copies trailing bytecode into memory and returns it.
    function _buildDeploymentCode(bytes calldata bytecode) internal pure returns (bytes memory) {
        uint256 n = bytecode.length;
        require(n <= 0xFFFF);

        bytes memory code = new bytes(14 + n);

        code[0] = 0x61; //  PUSH2
        code[1] = bytes1(uint8(n >> 8));
        code[2] = bytes1(uint8(n));
        code[3] = 0x60; //  PUSH1
        code[4] = 0x0E; //  14 (offset)
        code[5] = 0x60; //  PUSH1
        code[6] = 0x00; //  0 (mem dest)
        code[7] = 0x39; //  CODECOPY
        code[8] = 0x61; //  PUSH2
        code[9] = bytes1(uint8(n >> 8));
        code[10] = bytes1(uint8(n));
        code[11] = 0x60; // PUSH1
        code[12] = 0x00; // 0 (mem offset)
        code[13] = 0xF3; // RETURN

        for (uint256 i; i < n; i++) {
            code[14 + i] = bytecode[i];
        }
        return code;
    }
}
