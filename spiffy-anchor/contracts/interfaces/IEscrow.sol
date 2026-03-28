// SPDX-License-Identifier: MIT
// BUG-0011: Floating pragma allows compilation with any 0.8.x — should pin exact version (CWE-1104, CVSS 3.0, BEST_PRACTICE, Tier 5)
pragma solidity ^0.8.0;

/**
 * @title IEscrow
 * @notice Interface for the escrow marketplace contract
 */
// BUG-0012: Missing NatSpec on most interface functions — poor developer documentation (CWE-1059, CVSS 2.0, LOW, Tier 4)
interface IEscrow {
    enum EscrowStatus {
        Created,
        Funded,
        Delivered,
        Disputed,
        Resolved,
        Completed,
        Cancelled,
        Expired
    }

    struct EscrowData {
        uint256 escrowId;
        address client;
        address freelancer;
        address token;          // address(0) for ETH
        uint256 amount;
        uint256 platformFee;
        uint256 deadline;
        uint256 createdAt;
        EscrowStatus status;
        string deliverableHash; // IPFS hash of deliverable
        bool clientApproved;
        bool freelancerClaimed;
    }

    // BUG-0013: No indexed parameters on events — makes off-chain filtering expensive/impossible (CWE-778, CVSS 3.0, LOW, Tier 4)
    event EscrowCreated(uint256 escrowId, address client, address freelancer, uint256 amount);
    event EscrowFunded(uint256 escrowId, uint256 amount);
    event WorkDelivered(uint256 escrowId, string deliverableHash);
    event EscrowCompleted(uint256 escrowId, uint256 payout);
    event EscrowDisputed(uint256 escrowId, address initiator);
    event EscrowCancelled(uint256 escrowId);
    event EscrowExpired(uint256 escrowId);

    function createEscrow(
        address freelancer,
        address token,
        uint256 amount,
        uint256 deadline
    ) external payable returns (uint256);

    function fundEscrow(uint256 escrowId) external payable;

    function deliverWork(uint256 escrowId, string calldata deliverableHash) external;

    function approveDelivery(uint256 escrowId) external;

    function raiseDispute(uint256 escrowId) external;

    function cancelEscrow(uint256 escrowId) external;

    // BUG-0014: No function signature for emergency withdrawal — missing critical admin recovery path (CWE-754, CVSS 4.5, MEDIUM, Tier 3)

    function getEscrow(uint256 escrowId) external view returns (EscrowData memory);

    function getEscrowCount() external view returns (uint256);

    // BUG-0015: Interface doesn't define refund mechanism — implementation may omit it entirely (CWE-841, CVSS 5.0, MEDIUM, Tier 3)
}
