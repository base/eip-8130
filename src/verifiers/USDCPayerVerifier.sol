// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "./IVerifier.sol";
import {ITxContext} from "../interfaces/ITxContext.sol";

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
}

interface IBlocklistable {
    function isBlacklisted(address account) external view returns (bool);
}

interface IAeroRouter {
    struct Route {
        address from;
        address to;
        bool stable;
        address factory;
    }

    function getAmountsOut(uint256 amountIn, Route[] memory routes) external view returns (uint256[] memory amounts);
}

/// @notice USDC-specific payer verifier for gas sponsorship with blocklist enforcement.
///
///         Zero untrusted input — `data` is ignored entirely. Everything is derived on-chain:
///           - Token address, pool config, and blocklist are immutables
///           - Price is read from Aerodrome (on-chain DEX liquidity)
///           - Gas limit and gas price come from the EVM / TX_CONTEXT precompile
///
///         Validation flow:
///           1. Derive ownerId from the immutable TOKEN address
///           2. Compute gas cost: tx.gasprice × TX_CONTEXT.getGasLimit() → ETH
///           3. Quote Aerodrome: WETH → TOKEN at current pool price → required USDC
///           4. Check sender and payer are not on the USDC blocklist
///           5. Check sender's USDC balance ≥ required amount
///           6. Validate first call phase: exactly 1 call, transfer(payer, amount ≥ required)
///
///         ownerId = bytes32(uint256(uint160(TOKEN))) — the token address, right-aligned.
///         Naturally collision-free with K1/DELEGATE's left-aligned bytes32(bytes20(address)).
///
///         Price oracle note: uses Aerodrome spot price which cannot be flash-loan manipulated
///         during validation (validation runs before execution in EIP-8130).
contract USDCPayerVerifier is IVerifier {
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb; // transfer(address,uint256)

    address public immutable TOKEN;
    address public immutable AERO_ROUTER;
    address public immutable WETH;
    address public immutable POOL_FACTORY;
    bool public immutable USE_STABLE_POOL;
    address public immutable TX_CONTEXT;
    bytes32 public immutable OWNER_ID;

    /// @param token ERC-20 token address (e.g., USDC on Base)
    /// @param aeroRouter Aerodrome Router address
    /// @param weth WETH address on the target chain
    /// @param poolFactory Aerodrome pool factory for the TOKEN/WETH pair
    /// @param useStablePool True for stable-curve pool, false for volatile (typically false for USDC/WETH)
    /// @param txContext Transaction Context precompile address (TX_CONTEXT_ADDRESS)
    constructor(
        address token,
        address aeroRouter,
        address weth,
        address poolFactory,
        bool useStablePool,
        address txContext
    ) {
        TOKEN = token;
        AERO_ROUTER = aeroRouter;
        WETH = weth;
        POOL_FACTORY = poolFactory;
        USE_STABLE_POOL = useStablePool;
        TX_CONTEXT = txContext;
        OWNER_ID = bytes32(uint256(uint160(token)));
    }

    function verify(bytes32, bytes calldata) external view returns (bytes32) {
        ITxContext ctx = ITxContext(TX_CONTEXT);
        uint256 requiredTokens = _quoteTokensForEth(tx.gasprice * ctx.getGasLimit());

        _checkSender(ctx, requiredTokens);
        _checkPaymentPhase(ctx, requiredTokens);

        return OWNER_ID;
    }

    function _quoteTokensForEth(uint256 ethAmount) internal view returns (uint256) {
        IAeroRouter.Route[] memory routes = new IAeroRouter.Route[](1);
        routes[0] = IAeroRouter.Route({from: WETH, to: TOKEN, stable: USE_STABLE_POOL, factory: POOL_FACTORY});

        uint256[] memory amounts = IAeroRouter(AERO_ROUTER).getAmountsOut(ethAmount, routes);
        return amounts[1];
    }

    function _checkSender(ITxContext ctx, uint256 requiredTokens) internal view {
        address sender = ctx.getSender();
        require(!IBlocklistable(TOKEN).isBlacklisted(sender), "sender blocklisted");
        require(IERC20Minimal(TOKEN).balanceOf(sender) >= requiredTokens, "insufficient token balance");
    }

    function _checkPaymentPhase(ITxContext ctx, uint256 requiredTokens) internal view {
        address payer = ctx.getPayer();
        require(!IBlocklistable(TOKEN).isBlacklisted(payer), "payer blocklisted");

        ITxContext.Call[][] memory phases = ctx.getCalls();
        require(phases.length > 0, "no call phases");
        require(phases[0].length == 1, "first phase must have exactly 1 call");
        require(phases[0][0].to == TOKEN, "first call must target token");

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
