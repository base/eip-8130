// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "./IVerifier.sol";
import {ITxContext} from "../interfaces/ITxContext.sol";

interface IERC20Info {
    function balanceOf(address account) external view returns (uint256);
}

interface IAeroRouterGeneric {
    struct Route {
        address from;
        address to;
        bool stable;
        address factory;
    }

    function getAmountsOut(uint256 amountIn, Route[] memory routes) external view returns (uint256[] memory amounts);
}

/// @notice Generic ERC-20 payer verifier for gas sponsorship — any token with Aerodrome liquidity.
///
///         The only untrusted input is the token address (20 bytes). Price is read on-chain
///         from Aerodrome's WETH/TOKEN pool — if no pool exists or liquidity is zero, the
///         verification fails (token is not accepted).
///
///         Validation flow:
///           1. Read token address from data, derive ownerId as the right-aligned address
///           2. Check gas limit is sufficient to execute the token transfer
///           3. Compute ETH cost: TX_CONTEXT.getMaxCost() + verifier gas overhead
///           4. Quote Aerodrome: WETH → TOKEN at current pool price → required tokens
///           5. Check sender's token balance ≥ required amount
///           6. Validate first call phase: exactly 1 call, transfer(payer, amount ≥ required)
///
///         Data layout: token (20 bytes)
///
///         ownerId = bytes32(uint256(uint160(token))) — the token address, right-aligned.
///         Naturally collision-free with K1/DELEGATE's left-aligned bytes32(bytes20(address)).
///         The payer registers this ownerId in owner_config to declare which tokens they accept.
///         No blocklist checks — use USDCPayerVerifier for blocklist-enabled stablecoins.
///
///         Uses volatile pool routing by default. Deploy a separate instance or use
///         USDCPayerVerifier for tokens requiring stable-curve pools.
contract AeroPayerVerifier is IVerifier {
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb; // transfer(address,uint256)

    address public immutable AERO_ROUTER;
    address public immutable WETH;
    address public immutable POOL_FACTORY;
    address public immutable TX_CONTEXT;
    uint256 public immutable VERIFIER_GAS_OVERHEAD;
    uint256 public immutable MIN_GAS_LIMIT;

    /// @param aeroRouter Aerodrome Router address
    /// @param weth WETH address on the target chain
    /// @param poolFactory Aerodrome default pool factory
    /// @param txContext Transaction Context precompile address (TX_CONTEXT_ADDRESS)
    /// @param verifierGasOverhead Extra gas to account for the verifier's own metered execution
    /// @param minGasLimit Minimum gas_limit required to ensure the token transfer succeeds
    constructor(
        address aeroRouter,
        address weth,
        address poolFactory,
        address txContext,
        uint256 verifierGasOverhead,
        uint256 minGasLimit
    ) {
        AERO_ROUTER = aeroRouter;
        WETH = weth;
        POOL_FACTORY = poolFactory;
        TX_CONTEXT = txContext;
        VERIFIER_GAS_OVERHEAD = verifierGasOverhead;
        MIN_GAS_LIMIT = minGasLimit;
    }

    /// @dev Data: token (20 bytes)
    function verify(bytes32, bytes calldata data) external view returns (bytes32 ownerId) {
        require(data.length >= 20);
        address token = address(bytes20(data[:20]));
        ownerId = bytes32(uint256(uint160(token)));

        ITxContext ctx = ITxContext(TX_CONTEXT);
        require(ctx.getGasLimit() >= MIN_GAS_LIMIT, "gas limit too low for transfer");

        uint256 maxEthCost = ctx.getMaxCost() + VERIFIER_GAS_OVERHEAD * tx.gasprice;
        uint256 requiredTokens = _quoteTokensForEth(token, maxEthCost);

        _checkSenderBalance(ctx, token, requiredTokens);
        _checkPaymentPhase(ctx, token, requiredTokens);
    }

    function _quoteTokensForEth(address token, uint256 ethAmount) internal view returns (uint256) {
        IAeroRouterGeneric.Route[] memory routes = new IAeroRouterGeneric.Route[](1);
        routes[0] = IAeroRouterGeneric.Route({from: WETH, to: token, stable: false, factory: POOL_FACTORY});

        uint256[] memory amounts = IAeroRouterGeneric(AERO_ROUTER).getAmountsOut(ethAmount, routes);
        return amounts[1];
    }

    function _checkSenderBalance(ITxContext ctx, address token, uint256 requiredTokens) internal view {
        address sender = ctx.getSender();
        require(IERC20Info(token).balanceOf(sender) >= requiredTokens, "insufficient token balance");
    }

    function _checkPaymentPhase(ITxContext ctx, address token, uint256 requiredTokens) internal view {
        address payer = ctx.getPayer();

        ITxContext.Call[][] memory phases = ctx.getCalls();
        require(phases.length > 0, "no call phases");
        require(phases[0].length == 1, "first phase must have exactly 1 call");
        require(phases[0][0].to == token, "first call must target token");

        _checkTransferCalldata(phases[0][0].data, payer, requiredTokens);
    }

    function _checkTransferCalldata(bytes memory cd, address payer, uint256 requiredTokens) internal pure {
        require(cd.length >= 68, "invalid transfer calldata");

        bytes4 sel;
        address recipient;
        uint256 amt;
        assembly {
            sel := mload(add(cd, 0x20))
            recipient := mload(add(cd, 0x24))
            amt := mload(add(cd, 0x44))
        }

        require(sel == TRANSFER_SELECTOR, "must be transfer call");
        require(recipient == payer, "transfer recipient must be payer");
        require(amt >= requiredTokens, "transfer amount insufficient");
    }
}
