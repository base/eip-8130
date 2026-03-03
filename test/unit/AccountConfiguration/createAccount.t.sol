// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountProxy} from "../../../src/accounts/AccountProxy.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract CreateAccountTest is AccountConfigurationTest {
    function test_createAccount_success(uint256 pk) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address owner = vm.addr(pk);
        bytes32 ownerId = bytes32(bytes20(owner));

        AccountConfiguration.Owner[] memory owners = new AccountConfiguration.Owner[](1);
        owners[0] = AccountConfiguration.Owner({
            id: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier)})
        });

        bytes memory bytecode =
            abi.encodePacked(type(AccountProxy).creationCode, abi.encode(defaultAccountImplementation, new bytes(0)));
        address account = accountConfiguration.createAccount(owners, 0, bytecode, new bytes(0));
        assert(account != address(0));
    }
}
