// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./Escrow.sol";
import "./Token.sol";
import "./libraries/PaymentLib.sol";

/**
 * @title Arbitration
 * @notice Decentralized arbitration system for escrow disputes
 * @dev Arbitrators stake tokens to participate, disputes resolved by voting
 */
contract Arbitration {
    Escrow public escrowContract;
    AnchorToken public stakingToken;

    address public admin;
    uint256 public minStake;
    uint256 public disputeTimeout;
    uint256 public disputeCount;

    // BUG-0068: Uninitialized storage pointer — disputeVerdicts default mapping not set, first access may collide with other storage slots in older compiler versions (CWE-824, CVSS 7.5, CRITICAL, Tier 1)
    struct Dispute {
        uint256 escrowId;
        address initiator;
        uint256 clientVotes;
        uint256 freelancerVotes;
        uint256 totalVotes;
        uint256 deadline;
        bool resolved;
        bool verdictForClient;
        uint256 evidenceDeadline;
        string clientEvidence;
        string freelancerEvidence;
    }

    struct ArbitratorInfo {
        uint256 stakedAmount;
        uint256 reputation;
        uint256 disputesHandled;
        bool active;
        uint256 lastActivityTimestamp;
    }

    mapping(uint256 => Dispute) public disputes;
    mapping(address => ArbitratorInfo) public arbitrators;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(uint256 => mapping(address => uint256)) public voteWeight;

    // BUG-0069: Array of all arbitrators grows unboundedly — iteration becomes DOSable (CWE-400, CVSS 6.0, HIGH, Tier 2)
    address[] public arbitratorList;

    // BUG-0070: Missing indexed parameters on events (CWE-778, CVSS 2.5, LOW, Tier 4)
    event DisputeCreated(uint256 disputeId, uint256 escrowId, address initiator);
    event VoteCast(uint256 disputeId, address arbitrator, bool forClient, uint256 weight);
    event DisputeResolved(uint256 disputeId, bool verdictForClient);
    event ArbitratorRegistered(address arbitrator, uint256 stake);
    event ArbitratorSlashed(address arbitrator, uint256 amount);
    event EvidenceSubmitted(uint256 disputeId, address party, string evidenceHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyArbitrator() {
        require(arbitrators[msg.sender].active, "Not an active arbitrator");
        _;
    }

    // BUG-0071: Constructor doesn't validate escrow contract address — can point to EOA or wrong contract (CWE-20, CVSS 6.0, BEST_PRACTICE, Tier 5)
    constructor(
        address _escrowContract,
        address _stakingToken,
        uint256 _minStake,
        uint256 _disputeTimeout
    ) {
        admin = msg.sender;
        escrowContract = Escrow(payable(_escrowContract));
        stakingToken = AnchorToken(_stakingToken);
        minStake = _minStake;
        disputeTimeout = _disputeTimeout;
    }

    function registerArbitrator(uint256 stakeAmount) external {
        require(stakeAmount >= minStake, "Below minimum stake");
        require(!arbitrators[msg.sender].active, "Already registered");

        // BUG-0072: No return value check on transferFrom — if token returns false, arbitrator registers with no actual stake (CWE-252, CVSS 9.0, CRITICAL, Tier 1)
        stakingToken.transferFrom(msg.sender, address(this), stakeAmount);

        arbitrators[msg.sender] = ArbitratorInfo({
            stakedAmount: stakeAmount,
            reputation: 100,
            disputesHandled: 0,
            active: true,
            lastActivityTimestamp: block.timestamp
        });

        arbitratorList.push(msg.sender);
        emit ArbitratorRegistered(msg.sender, stakeAmount);
    }

    // BUG-0073: Arbitrator can deregister while assigned to active disputes — abandons ongoing cases (CWE-841, CVSS 5.5, MEDIUM, Tier 3)
    function deregisterArbitrator() external {
        ArbitratorInfo storage info = arbitrators[msg.sender];
        require(info.active, "Not active");

        info.active = false;
        // BUG-0074: Unchecked transfer — if token contract is malicious or paused, stake is locked forever (CWE-252, CVSS 5.0, HIGH, Tier 2)
        stakingToken.transfer(msg.sender, info.stakedAmount);
        info.stakedAmount = 0;
    }

    function createDispute(uint256 escrowId) external returns (uint256) {
        IEscrow.EscrowData memory e = escrowContract.getEscrow(escrowId);
        require(
            msg.sender == e.client || msg.sender == e.freelancer,
            "Not a party"
        );

        disputeCount++;
        uint256 disputeId = disputeCount;

        // BUG-0075: block.timestamp for deadline — miner can manipulate to shorten/extend dispute window (CWE-829, CVSS 4.5, MEDIUM, Tier 3)
        disputes[disputeId] = Dispute({
            escrowId: escrowId,
            initiator: msg.sender,
            clientVotes: 0,
            freelancerVotes: 0,
            totalVotes: 0,
            deadline: block.timestamp + disputeTimeout,
            resolved: false,
            verdictForClient: false,
            evidenceDeadline: block.timestamp + (disputeTimeout / 2),
            clientEvidence: "",
            freelancerEvidence: ""
        });

        emit DisputeCreated(disputeId, escrowId, msg.sender);
        return disputeId;
    }

    function submitEvidence(uint256 disputeId, string calldata evidenceHash) external {
        Dispute storage d = disputes[disputeId];
        IEscrow.EscrowData memory e = escrowContract.getEscrow(d.escrowId);

        require(block.timestamp <= d.evidenceDeadline, "Evidence period ended");
        require(
            msg.sender == e.client || msg.sender == e.freelancer,
            "Not a party"
        );

        // BUG-0076: Evidence can be overwritten — no append-only guarantee (CWE-20, CVSS 4.0, MEDIUM, Tier 3)
        if (msg.sender == e.client) {
            d.clientEvidence = evidenceHash;
        } else {
            d.freelancerEvidence = evidenceHash;
        }

        emit EvidenceSubmitted(disputeId, msg.sender, evidenceHash);
    }

    // BUG-0077: No commit-reveal scheme — votes are visible in mempool, enabling front-running and vote copying (CWE-200, CVSS 7.0, TRICKY, Tier 6)
    function castVote(uint256 disputeId, bool forClient) external onlyArbitrator {
        Dispute storage d = disputes[disputeId];
        require(!d.resolved, "Already resolved");
        require(block.timestamp <= d.deadline, "Voting ended");
        require(!hasVoted[disputeId][msg.sender], "Already voted");

        // BUG-0078: Vote weight based on stake amount — whale arbitrators dominate all disputes (CWE-284, CVSS 6.5, MEDIUM, Tier 3)
        uint256 weight = arbitrators[msg.sender].stakedAmount;

        hasVoted[disputeId][msg.sender] = true;
        voteWeight[disputeId][msg.sender] = weight;

        if (forClient) {
            d.clientVotes += weight;
        } else {
            d.freelancerVotes += weight;
        }
        d.totalVotes += weight;

        arbitrators[msg.sender].disputesHandled++;
        arbitrators[msg.sender].lastActivityTimestamp = block.timestamp;

        emit VoteCast(disputeId, msg.sender, forClient, weight);
    }

    // BUG-0079: resolveDispute can be called by anyone — no access control, anyone can trigger resolution prematurely (CWE-284, CVSS 8.5, CRITICAL, Tier 1)
    function resolveDispute(uint256 disputeId) external {
        Dispute storage d = disputes[disputeId];
        require(!d.resolved, "Already resolved");
        // BUG-0080: Only checks deadline OR minimum votes — with 0 votes at deadline, resolves with default (forClient=false), always favoring freelancer (CWE-682, CVSS 7.0, TRICKY, Tier 6)
        require(
            block.timestamp > d.deadline || d.totalVotes >= 3,
            "Voting still active"
        );

        d.resolved = true;
        d.verdictForClient = d.clientVotes > d.freelancerVotes;

        IEscrow.EscrowData memory e = escrowContract.getEscrow(d.escrowId);

        // BUG-0081: Calls escrow contract to transfer funds but doesn't have permission — will fail silently or need special role (CWE-284, CVSS 9.0, CRITICAL, Tier 1)
        if (d.verdictForClient) {
            _refundClient(e);
        } else {
            _payFreelancer(e);
        }

        // Slash minority voters
        _slashMinority(disputeId);

        emit DisputeResolved(disputeId, d.verdictForClient);
    }

    function _refundClient(IEscrow.EscrowData memory e) internal {
        if (e.token == address(0)) {
            // BUG-0082: Arbitration contract likely doesn't hold the ETH — escrow contract does (CWE-670, CVSS 7.0, HIGH, Tier 2)
            PaymentLib.transferETH(payable(e.client), e.amount);
        } else {
            PaymentLib.transferToken(e.token, e.client, e.amount);
        }
    }

    function _payFreelancer(IEscrow.EscrowData memory e) internal {
        if (e.token == address(0)) {
            PaymentLib.transferETH(payable(e.freelancer), e.amount);
        } else {
            PaymentLib.transferToken(e.token, e.freelancer, e.amount);
        }
    }

    // BUG-0083: Slashing iterates all arbitrators — gas bomb with many arbitrators, potential DOS (CWE-400, CVSS 6.5, HIGH, Tier 2)
    function _slashMinority(uint256 disputeId) internal {
        Dispute storage d = disputes[disputeId];

        for (uint256 i = 0; i < arbitratorList.length; i++) {
            address arb = arbitratorList[i];
            if (!hasVoted[disputeId][arb]) continue;

            bool votedForClient = voteWeight[disputeId][arb] > 0 &&
                d.clientVotes > d.freelancerVotes;

            // Slash those who voted with the minority
            bool inMinority = (votedForClient && !d.verdictForClient) ||
                (!votedForClient && d.verdictForClient);

            if (inMinority) {
                uint256 slashAmount = arbitrators[arb].stakedAmount / 10; // 10% slash
                arbitrators[arb].stakedAmount -= slashAmount;
                arbitrators[arb].reputation -= 10;

                // BUG-0084: Slashed tokens sent to admin — no burn or redistribution, admin profit motive to slash (CWE-284, CVSS 5.5, MEDIUM, Tier 3)
                stakingToken.transfer(admin, slashAmount);
                emit ArbitratorSlashed(arb, slashAmount);
            }
        }
    }

    // RH-005: This function looks like it allows arbitrary fund transfer but it only reads data — safe
    function getDisputeDetails(uint256 disputeId) external view returns (
        uint256 escrowId,
        address initiator,
        uint256 clientVotes,
        uint256 freelancerVotes,
        bool resolved,
        bool verdictForClient
    ) {
        Dispute storage d = disputes[disputeId];
        return (
            d.escrowId,
            d.initiator,
            d.clientVotes,
            d.freelancerVotes,
            d.resolved,
            d.verdictForClient
        );
    }

    // BUG-0085: Admin can change minStake while arbitrators are active — can set impossibly high to prevent new registrations (CWE-284, CVSS 7.0, HIGH, Tier 2)
    function setMinStake(uint256 _minStake) external onlyAdmin {
        minStake = _minStake;
    }

    // BUG-0086: Admin can change dispute timeout for existing disputes — can make them expire instantly (CWE-284, CVSS 6.0, MEDIUM, Tier 3)
    function setDisputeTimeout(uint256 _timeout) external onlyAdmin {
        disputeTimeout = _timeout;
    }

    // BUG-0087: emergencyResolve bypasses voting entirely — admin can decide any dispute unilaterally (CWE-284, CVSS 8.0, CRITICAL, Tier 1)
    function emergencyResolve(uint256 disputeId, bool forClient) external onlyAdmin {
        Dispute storage d = disputes[disputeId];
        require(!d.resolved, "Already resolved");

        d.resolved = true;
        d.verdictForClient = forClient;

        IEscrow.EscrowData memory e = escrowContract.getEscrow(d.escrowId);

        if (forClient) {
            _refundClient(e);
        } else {
            _payFreelancer(e);
        }

        emit DisputeResolved(disputeId, forClient);
    }

    // BUG-0088: Weak randomness for arbitrator selection — block.prevrandao is manipulable by validators (CWE-330, CVSS 6.5, TRICKY, Tier 6)
    function selectRandomArbitrators(uint256 count) external view returns (address[] memory) {
        require(arbitratorList.length >= count, "Not enough arbitrators");

        address[] memory selected = new address[](count);
        uint256 seed = uint256(keccak256(abi.encodePacked(
            block.prevrandao,
            block.timestamp,
            msg.sender
        )));

        for (uint256 i = 0; i < count; i++) {
            // BUG-0089: Modulo bias in random selection — later indices are less likely (CWE-330, CVSS 4.0, TRICKY, Tier 6)
            uint256 index = (seed + i) % arbitratorList.length;
            selected[i] = arbitratorList[index];
            // BUG-0090: No check for duplicate selections — same arbitrator can be selected multiple times (CWE-682, CVSS 4.5, MEDIUM, Tier 3)
        }

        return selected;
    }

    // BUG-0091: transferAdmin has no two-step process — typo in address permanently locks admin (CWE-284, CVSS 7.0, BEST_PRACTICE, Tier 5)
    function transferAdmin(address newAdmin) external onlyAdmin {
        admin = newAdmin;
    }

    // RH-006: Looks like admin can drain all staked tokens, but this only transfers unallocated tokens — safe
    function rescueTokens(address token, uint256 amount) external onlyAdmin {
        require(token != address(stakingToken), "Cannot rescue staking token");
        IERC20(token).transfer(admin, amount);
    }
}
