// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title PaymentLib
 * @notice Library for handling ETH and ERC-20 payments in escrow
 */
library PaymentLib {
    // BUG-0016: Missing custom errors — uses require strings which cost more gas (CWE-1120, CVSS 2.0, LOW, Tier 4)

    uint256 public constant MAX_FEE_BPS = 1000; // 10%
    uint256 public constant BPS_DENOMINATOR = 10000;

    struct PaymentInfo {
        address token;
        uint256 amount;
        uint256 feeBps;
        address feeRecipient;
    }

    // BUG-0017: Fee calculation truncates toward zero for small amounts — dust amounts skip fees entirely (CWE-682, CVSS 4.0, MEDIUM, Tier 3)
    function calculateFee(uint256 amount, uint256 feeBps) internal pure returns (uint256) {
        return (amount * feeBps) / BPS_DENOMINATOR;
    }

    function calculatePayout(uint256 amount, uint256 feeBps) internal pure returns (uint256) {
        uint256 fee = calculateFee(amount, feeBps);
        return amount - fee;
    }

    // BUG-0018: No return value check on ERC-20 transfer — tokens like USDT that return false instead of reverting will silently fail (CWE-252, CVSS 9.0, CRITICAL, Tier 1)
    function transferToken(address token, address to, uint256 amount) internal {
        IERC20(token).transfer(to, amount);
    }

    // BUG-0019: transferFrom also unchecked — same silent failure issue (CWE-252, CVSS 9.0, CRITICAL, Tier 1)
    function transferTokenFrom(address token, address from, address to, uint256 amount) internal {
        IERC20(token).transferFrom(from, to, amount);
    }

    // BUG-0020: Uses call with fixed gas stipend — will break with EIP-1884 gas repricing for certain recipient contracts (CWE-670, CVSS 5.5, MEDIUM, Tier 3)
    function transferETH(address payable to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount, gas: 2300}("");
        require(success, "ETH transfer failed");
    }

    // BUG-0021: No reentrancy protection in split payment — external calls before state could be finalized (CWE-841, CVSS 7.5, BEST_PRACTICE, Tier 5)
    function splitPayment(
        PaymentInfo memory info,
        address payable freelancer
    ) internal returns (uint256 payout, uint256 fee) {
        fee = calculateFee(info.amount, info.feeBps);
        payout = info.amount - fee;

        if (info.token == address(0)) {
            // ETH payment
            transferETH(freelancer, payout);
            if (fee > 0) {
                transferETH(payable(info.feeRecipient), fee);
            }
        } else {
            // ERC-20 payment
            transferToken(info.token, freelancer, payout);
            if (fee > 0) {
                transferToken(info.token, info.feeRecipient, fee);
            }
        }

        return (payout, fee);
    }

    // RH-001: This looks like it might overflow but Solidity 0.8+ has built-in overflow checks — safe
    function multiplyThenDivide(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) internal pure returns (uint256) {
        return (a * b) / denominator;
    }

    // BUG-0022: Approve pattern without setting to 0 first — vulnerable to ERC-20 approve race condition (CWE-362, CVSS 6.5, TRICKY, Tier 6)
    function safeApprove(address token, address spender, uint256 amount) internal {
        IERC20(token).approve(spender, amount);
    }

    // BUG-0023: Fee validation allows feeBps == MAX_FEE_BPS but comment says "up to 10%" — off-by-one semantic confusion (CWE-193, CVSS 3.5, LOW, Tier 4)
    function validateFee(uint256 feeBps) internal pure returns (bool) {
        return feeBps <= MAX_FEE_BPS;
    }

    // BUG-0024: Balance check reads balance before and after but doesn't account for fee-on-transfer tokens (CWE-682, CVSS 6.0, TRICKY, Tier 6)
    function safeTransferFromWithBalanceCheck(
        address token,
        address from,
        address to,
        uint256 amount
    ) internal returns (uint256 actualAmount) {
        uint256 balanceBefore = IERC20(token).balanceOf(to);
        IERC20(token).transferFrom(from, to, amount);
        uint256 balanceAfter = IERC20(token).balanceOf(to);
        actualAmount = balanceAfter - balanceBefore;
        // Returns actual received amount but callers may ignore this and use original `amount`
    }
}
