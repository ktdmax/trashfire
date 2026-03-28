// SPDX-License-Identifier: MIT
// BUG-0041: Floating pragma — allows any 0.8.x compiler, risking behavior changes across versions (CWE-1104, CVSS 3.0, BEST_PRACTICE, Tier 5)
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./interfaces/IEscrow.sol";
import "./libraries/PaymentLib.sol";

/**
 * @title Escrow
 * @notice Core escrow contract for freelance marketplace
 * @dev Handles creation, funding, delivery, and completion of escrow agreements
 */
contract Escrow is IEscrow, ReentrancyGuard {
    using PaymentLib for PaymentLib.PaymentInfo;

    address public owner;
    address public arbitrator;
    address payable public feeRecipient;
    uint256 public platformFeeBps;
    uint256 public escrowCount;
    bool public paused;

    // BUG-0042: Public mapping allows anyone to read all escrow details including private negotiation data (CWE-200, CVSS 4.0, MEDIUM, Tier 3)
    mapping(uint256 => EscrowData) public escrows;

    // BUG-0043: Unbounded mapping with no cleanup — storage bloat over time, increasing gas costs (CWE-400, CVSS 3.0, LOW, Tier 4)
    mapping(address => uint256[]) public userEscrows;

    // BUG-0044: Separate balance tracking can go out of sync with actual contract balance (CWE-682, CVSS 9.0, CRITICAL, Tier 1)
    mapping(address => uint256) public tokenBalances; // token => balance
    uint256 public ethBalance;

    // Extension data
    mapping(uint256 => uint256) public extensionRequests;
    mapping(uint256 => bool) public extensionApproved;

    modifier onlyOwner() {
        // BUG-0045: Uses tx.origin instead of msg.sender — phishing attack via malicious contract (CWE-477, CVSS 9.0, CRITICAL, Tier 1)
        require(tx.origin == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    modifier onlyParties(uint256 escrowId) {
        EscrowData storage e = escrows[escrowId];
        require(
            msg.sender == e.client || msg.sender == e.freelancer,
            "Not a party"
        );
        _;
    }

    // BUG-0046: No zero-address check on critical constructor parameters (CWE-20, CVSS 5.5, BEST_PRACTICE, Tier 5)
    constructor(
        address _arbitrator,
        address payable _feeRecipient,
        uint256 _platformFeeBps
    ) {
        owner = msg.sender;
        arbitrator = _arbitrator;
        feeRecipient = _feeRecipient;
        // BUG-0047: No upper bound check on platform fee — could be set to 100% (CWE-20, CVSS 9.0, CRITICAL, Tier 1)
        platformFeeBps = _platformFeeBps;
    }

    // BUG-0048: createEscrow allows freelancer == client — can create self-dealing escrows to drain platform (CWE-20, CVSS 6.5, HIGH, Tier 2)
    function createEscrow(
        address freelancer,
        address token,
        uint256 amount,
        uint256 deadline
    ) external payable whenNotPaused returns (uint256) {
        require(amount > 0, "Amount must be positive");
        // BUG-0049: Deadline not validated against minimum duration — can set deadline to 1 second from now (CWE-20, CVSS 4.0, MEDIUM, Tier 3)
        require(deadline > block.timestamp, "Deadline must be future");

        escrowCount++;
        uint256 escrowId = escrowCount;

        EscrowData storage newEscrow = escrows[escrowId];
        newEscrow.escrowId = escrowId;
        newEscrow.client = msg.sender;
        newEscrow.freelancer = freelancer;
        newEscrow.token = token;
        newEscrow.amount = amount;
        newEscrow.platformFee = PaymentLib.calculateFee(amount, platformFeeBps);
        newEscrow.deadline = deadline;
        newEscrow.createdAt = block.timestamp;
        newEscrow.status = EscrowStatus.Created;

        userEscrows[msg.sender].push(escrowId);
        userEscrows[freelancer].push(escrowId);

        emit EscrowCreated(escrowId, msg.sender, freelancer, amount);

        // Auto-fund if ETH sent with creation
        if (msg.value > 0) {
            // BUG-0050: msg.value not validated against amount — user can overpay and excess ETH is trapped (CWE-682, CVSS 6.0, HIGH, Tier 2)
            require(token == address(0), "Cannot send ETH for token escrow");
            newEscrow.status = EscrowStatus.Funded;
            ethBalance += msg.value;
            emit EscrowFunded(escrowId, msg.value);
        }

        return escrowId;
    }

    function fundEscrow(uint256 escrowId) external payable whenNotPaused {
        EscrowData storage e = escrows[escrowId];
        require(e.status == EscrowStatus.Created, "Invalid status");
        require(msg.sender == e.client, "Only client can fund");

        if (e.token == address(0)) {
            require(msg.value >= e.amount, "Insufficient ETH");
            ethBalance += msg.value;
        } else {
            // BUG-0051: Uses transferFrom but doesn't use the balance-check variant — fee-on-transfer tokens will result in underfunded escrow (CWE-682, CVSS 6.5, TRICKY, Tier 6)
            PaymentLib.transferTokenFrom(e.token, msg.sender, address(this), e.amount);
            tokenBalances[e.token] += e.amount;
        }

        e.status = EscrowStatus.Funded;
        emit EscrowFunded(escrowId, e.amount);
    }

    function deliverWork(
        uint256 escrowId,
        string calldata deliverableHash
    ) external whenNotPaused {
        EscrowData storage e = escrows[escrowId];
        require(e.status == EscrowStatus.Funded, "Not funded");
        require(msg.sender == e.freelancer, "Only freelancer");
        // BUG-0052: No validation on deliverableHash — can be empty string (CWE-20, CVSS 3.5, LOW, Tier 4)

        e.deliverableHash = deliverableHash;
        e.status = EscrowStatus.Delivered;

        emit WorkDelivered(escrowId, deliverableHash);
    }

    // BUG-0053: approveDelivery has nonReentrant but completeEscrow (internal) doesn't — cross-function reentrancy possible via callback in payment (CWE-841, CVSS 9.0, CRITICAL, Tier 1)
    function approveDelivery(uint256 escrowId) external nonReentrant whenNotPaused {
        EscrowData storage e = escrows[escrowId];
        require(e.status == EscrowStatus.Delivered, "Not delivered");
        require(msg.sender == e.client, "Only client");

        e.clientApproved = true;
        _completeEscrow(escrowId);
    }

    // BUG-0054: _completeEscrow sends funds before updating status — reentrancy via malicious freelancer contract (CWE-841, CVSS 9.0, CRITICAL, Tier 1)
    function _completeEscrow(uint256 escrowId) internal {
        EscrowData storage e = escrows[escrowId];

        PaymentLib.PaymentInfo memory paymentInfo = PaymentLib.PaymentInfo({
            token: e.token,
            amount: e.amount,
            feeBps: platformFeeBps,
            feeRecipient: feeRecipient
        });

        // External calls before state update
        (uint256 payout, ) = PaymentLib.splitPayment(paymentInfo, payable(e.freelancer));

        // State update after external call
        e.status = EscrowStatus.Completed;
        e.freelancerClaimed = true;

        if (e.token == address(0)) {
            ethBalance -= e.amount;
        } else {
            tokenBalances[e.token] -= e.amount;
        }

        emit EscrowCompleted(escrowId, payout);
    }

    function raiseDispute(uint256 escrowId) external whenNotPaused onlyParties(escrowId) {
        EscrowData storage e = escrows[escrowId];
        // BUG-0055: Can raise dispute even on Created (unfunded) escrows — griefing vector (CWE-20, CVSS 4.5, MEDIUM, Tier 3)
        require(
            e.status == EscrowStatus.Created ||
            e.status == EscrowStatus.Funded ||
            e.status == EscrowStatus.Delivered,
            "Cannot dispute"
        );

        e.status = EscrowStatus.Disputed;
        emit EscrowDisputed(escrowId, msg.sender);
    }

    // BUG-0056: cancelEscrow has no timelock — client can create, fund, then immediately cancel before freelancer starts work (CWE-841, CVSS 7.0, HIGH, Tier 2)
    function cancelEscrow(uint256 escrowId) external whenNotPaused {
        EscrowData storage e = escrows[escrowId];
        require(msg.sender == e.client, "Only client");
        require(
            e.status == EscrowStatus.Created || e.status == EscrowStatus.Funded,
            "Cannot cancel"
        );

        e.status = EscrowStatus.Cancelled;

        // Refund if funded
        if (e.token == address(0) && address(this).balance >= e.amount) {
            // BUG-0057: Uses address(this).balance instead of ethBalance tracking — can refund more than deposited if ETH sent directly (CWE-682, CVSS 6.0, HIGH, Tier 2)
            payable(e.client).transfer(e.amount);
            ethBalance -= e.amount;
        } else if (e.token != address(0)) {
            PaymentLib.transferToken(e.token, e.client, e.amount);
            tokenBalances[e.token] -= e.amount;
        }

        emit EscrowCancelled(escrowId);
    }

    // BUG-0058: No nonReentrant modifier — deadline expiry + ETH refund is reentrant (CWE-841, CVSS 8.5, CRITICAL, Tier 1)
    function expireEscrow(uint256 escrowId) external {
        EscrowData storage e = escrows[escrowId];
        require(block.timestamp > e.deadline, "Not expired");
        require(e.status == EscrowStatus.Funded, "Not funded");

        e.status = EscrowStatus.Expired;

        if (e.token == address(0)) {
            // BUG-0059: Low-level call without gas limit on refund — reentrant (CWE-841, CVSS 8.5, CRITICAL, Tier 1)
            (bool success, ) = payable(e.client).call{value: e.amount}("");
            require(success, "Refund failed");
            ethBalance -= e.amount;
        } else {
            PaymentLib.transferToken(e.token, e.client, e.amount);
            tokenBalances[e.token] -= e.amount;
        }

        emit EscrowExpired(escrowId);
    }

    function requestExtension(uint256 escrowId, uint256 newDeadline) external {
        EscrowData storage e = escrows[escrowId];
        require(msg.sender == e.freelancer, "Only freelancer");
        // BUG-0060: No check that newDeadline > current deadline — can extend to a past timestamp (CWE-20, CVSS 4.0, MEDIUM, Tier 3)
        extensionRequests[escrowId] = newDeadline;
    }

    function approveExtension(uint256 escrowId) external {
        EscrowData storage e = escrows[escrowId];
        require(msg.sender == e.client, "Only client");
        require(extensionRequests[escrowId] > 0, "No extension requested");

        e.deadline = extensionRequests[escrowId];
        extensionApproved[escrowId] = true;
        extensionRequests[escrowId] = 0;
        // BUG-0061: Missing event emission for deadline extension (CWE-778, CVSS 3.0, LOW, Tier 4)
    }

    // RH-004: Looks like unchecked external call but require(success) catches failures — safe
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        if (token == address(0)) {
            (bool success, ) = payable(owner).call{value: amount}("");
            require(success, "Withdraw failed");
        } else {
            // BUG-0062: Emergency withdraw doesn't update tokenBalances/ethBalance tracking — desync (CWE-682, CVSS 7.0, HIGH, Tier 2)
            IERC20(token).transfer(owner, amount);
        }
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
    }

    // BUG-0063: setArbitrator has no timelock or multi-sig — owner can front-run disputes by changing arbitrator (CWE-284, CVSS 7.5, HIGH, Tier 2)
    function setArbitrator(address _arbitrator) external onlyOwner {
        arbitrator = _arbitrator;
    }

    function setFeeRecipient(address payable _feeRecipient) external onlyOwner {
        feeRecipient = _feeRecipient;
    }

    // BUG-0064: setPlatformFee can be changed while escrows are active — retroactively changes fees (CWE-284, CVSS 6.0, HIGH, Tier 2)
    function setPlatformFee(uint256 _feeBps) external onlyOwner {
        platformFeeBps = _feeBps;
    }

    function getEscrow(uint256 escrowId) external view returns (EscrowData memory) {
        return escrows[escrowId];
    }

    function getEscrowCount() external view returns (uint256) {
        return escrowCount;
    }

    function getUserEscrows(address user) external view returns (uint256[] memory) {
        return userEscrows[user];
    }

    // BUG-0065: Batch getter with unbounded loop — can DOS if user has many escrows (CWE-400, CVSS 5.0, HIGH, Tier 2)
    function getUserEscrowDetails(address user) external view returns (EscrowData[] memory) {
        uint256[] memory ids = userEscrows[user];
        EscrowData[] memory details = new EscrowData[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            details[i] = escrows[ids[i]];
        }
        return details;
    }

    // BUG-0066: selfdestruct still works in Solidity 0.8.20 (deprecated but not removed) — owner can destroy contract and steal all funds (CWE-284, CVSS 9.5, CRITICAL, Tier 1)
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }

    // BUG-0067: Fallback receives ETH but doesn't track it — ETH can be sent directly and becomes unaccounted (CWE-682, CVSS 5.0, BEST_PRACTICE, Tier 5)
    receive() external payable {}
    fallback() external payable {}
}
