// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @dev ERC-1271 wallet that accepts any signature. Stands in for a contract account under test; the import path
///      only checks for the canonical magic return, so an empty signature suffices.
contract AlwaysValidWallet {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @notice Coverage for FLAG_CONTRACT_ESTABLISHED / isContractEstablished: the marker set on every keystore-established
///         account (createAccount and importAccount alike, regardless of code shape) that keeps it from being mistaken
///         for a key-backed EOA after its code becomes empty (e.g. an EIP-6780 same-transaction SELFDESTRUCT).
contract ContractEstablishedTest is KeystoreTest {
    function _singleUnrestrictedActor(bytes32 actorId) internal view returns (Keystore.InitialActor[] memory actors) {
        actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });
    }

    /// @notice createAccount marks the account contract-established (a CREATE2 address has no private key).
    function test_createAccount_setsContractEstablished(uint256 pkSeed, bytes32 salt) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1AccountWithSalt(pk, salt);

        assertTrue(keystore.isContractEstablished(account));
    }

    /// @notice Importing a plain (non-7702) contract wallet marks it contract-established.
    function test_importAccount_plainContract_setsContractEstablished(bytes32 actorId) public {
        vm.assume(actorId != 0);
        AlwaysValidWallet wallet = new AlwaysValidWallet();

        keystore.importAccount(address(wallet), block.chainid, _singleUnrestrictedActor(actorId), "");

        assertTrue(keystore.isContractEstablished(address(wallet)));
    }

    /// @notice Importing an EIP-7702/7819 delegate is allowed (the 7819 factory relies on it) and, like every other
    ///         import, marks the account contract-established: the keystore does not infer an address-bound key from the
    ///         delegation code shape.
    function test_importAccount_delegate_setsContractEstablished(uint256 eoaSeed, bytes32 actorId) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        vm.assume(actorId != 0);
        address eoa = vm.addr(eoaPk);
        vm.assume(eoa != address(keystore));

        AlwaysValidWallet impl = new AlwaysValidWallet();
        // Delegate the EOA to the ERC-1271 implementation (code = 0xef0100 || delegate), the 23-byte 7702 indicator.
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(impl)));

        keystore.importAccount(eoa, block.chainid, _singleUnrestrictedActor(actorId), "");

        assertTrue(keystore.isContractEstablished(eoa));
    }

    /// @notice EIP-6780 ephemeral importer: a contract wallet imported then SELFDESTRUCTed leaves empty code while its
    ///         EIP-8130 state persists. The account must stay flagged contract-established so empty code alone is never
    ///         read as a known EOA. The post-SELFDESTRUCT empty-code state is modelled with vm.etch, since a real
    ///         same-transaction deletion only settles at transaction end (unobservable within one test call).
    function test_importAccount_emptyCodeAfterSelfDestruct_staysFlagged(bytes32 actorId) public {
        vm.assume(actorId != 0);
        AlwaysValidWallet wallet = new AlwaysValidWallet();
        address account = address(wallet);

        keystore.importAccount(account, block.chainid, _singleUnrestrictedActor(actorId), "");
        assertTrue(keystore.isContractEstablished(account));

        // Model the EIP-6780 same-transaction SELFDESTRUCT: runtime code is gone, Keystore storage is not.
        vm.etch(account, "");

        assertEq(account.code.length, 0);
        assertEq(keystore.getChangeSequences(account).localSequence, 1);
        assertTrue(_isActor(account, actorId));
        // Empty code, but still not key-backed.
        assertTrue(keystore.isContractEstablished(account));
    }

    /// @notice A never-initialized account reports not contract-established.
    function test_uninitialized_isNotContractEstablished(address account) public view {
        assertFalse(keystore.isContractEstablished(account));
    }
}
