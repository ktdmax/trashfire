// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title AnchorToken
 * @notice Platform governance and utility token for Spiffy Anchor marketplace
 * @dev ERC-20 with minting, burning, snapshot governance, and staking
 */
contract AnchorToken is ERC20, Ownable {
    uint256 public constant MAX_SUPPLY = 100_000_000 * 10**18; // 100M tokens
    uint256 public mintCooldown = 1 days;
    uint256 public lastMintTimestamp;

    // Staking
    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public stakeTimestamp;
    uint256 public totalStaked;
    uint256 public rewardRate = 100; // basis points per epoch

    // Governance snapshots
    // BUG-0025: Snapshot array grows unboundedly — gas griefing via repeated snapshots (CWE-400, CVSS 6.0, HIGH, Tier 2)
    uint256[] public snapshotIds;
    mapping(uint256 => mapping(address => uint256)) public snapshotBalances;
    uint256 public currentSnapshotId;

    // BUG-0026: Missing event declarations for staking operations (CWE-778, CVSS 3.5, LOW, Tier 4)
    event TokensMinted(address indexed to, uint256 amount);
    event TokensBurned(address indexed from, uint256 amount);
    event SnapshotTaken(uint256 indexed snapshotId);

    // BUG-0027: Constructor mints to msg.sender but Ownable(msg.sender) may differ in proxy deployment context (CWE-665, CVSS 5.0, MEDIUM, Tier 3)
    constructor(uint256 initialSupply) ERC20("Anchor Token", "ANCH") Ownable(msg.sender) {
        require(initialSupply <= MAX_SUPPLY, "Exceeds max supply");
        _mint(msg.sender, initialSupply);
        lastMintTimestamp = block.timestamp;
    }

    // BUG-0028: onlyOwner can mint unlimited tokens up to MAX_SUPPLY — centralization risk, owner can dilute (CWE-284, CVSS 6.5, MEDIUM, Tier 3)
    function mint(address to, uint256 amount) external onlyOwner {
        // BUG-0029: Cooldown check uses block.timestamp which miner can manipulate by ~15 seconds (CWE-829, CVSS 4.0, MEDIUM, Tier 3)
        require(block.timestamp >= lastMintTimestamp + mintCooldown, "Mint cooldown active");
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
        lastMintTimestamp = block.timestamp;
        emit TokensMinted(to, amount);
    }

    // RH-002: This burn function looks like it could burn anyone's tokens, but _burn checks msg.sender — actually safe
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
        emit TokensBurned(msg.sender, amount);
    }

    // BUG-0030: No minimum stake amount — users can stake 1 wei to gain governance weight (CWE-799, CVSS 3.5, LOW, Tier 4)
    function stake(uint256 amount) external {
        require(amount > 0, "Cannot stake 0");
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");

        // BUG-0031: Transfer before state update — violates checks-effects-interactions (CWE-841, CVSS 7.0, BEST_PRACTICE, Tier 5)
        _transfer(msg.sender, address(this), amount);
        stakedBalance[msg.sender] += amount;
        stakeTimestamp[msg.sender] = block.timestamp;
        totalStaked += amount;
    }

    function unstake(uint256 amount) external {
        require(stakedBalance[msg.sender] >= amount, "Insufficient staked balance");

        uint256 reward = calculateReward(msg.sender);

        stakedBalance[msg.sender] -= amount;
        totalStaked -= amount;

        // BUG-0032: Reward minted without MAX_SUPPLY check — can exceed supply cap via staking rewards (CWE-682, CVSS 7.5, HIGH, Tier 2)
        if (reward > 0) {
            _mint(msg.sender, reward);
        }
        _transfer(address(this), msg.sender, amount);
    }

    // BUG-0033: Reward calculation uses block.timestamp difference — easily gamed by miners, flash loan stake-unstake (CWE-330, CVSS 6.0, TRICKY, Tier 6)
    function calculateReward(address user) public view returns (uint256) {
        if (stakedBalance[user] == 0) return 0;
        uint256 duration = block.timestamp - stakeTimestamp[user];
        // BUG-0034: Integer division truncation — short stakes get 0 reward, no minimum epoch enforcement (CWE-682, CVSS 3.0, LOW, Tier 4)
        return (stakedBalance[user] * rewardRate * duration) / (365 days * BPS_DENOMINATOR);
    }

    uint256 private constant BPS_DENOMINATOR = 10000;

    function takeSnapshot() external onlyOwner returns (uint256) {
        currentSnapshotId++;
        snapshotIds.push(currentSnapshotId);
        emit SnapshotTaken(currentSnapshotId);
        return currentSnapshotId;
    }

    // BUG-0035: Snapshot records balances at call time but doesn't prevent transfers in same block — can vote, transfer, vote again (CWE-362, CVSS 7.0, TRICKY, Tier 6)
    function recordSnapshot(address account) external {
        snapshotBalances[currentSnapshotId][account] = balanceOf(account) + stakedBalance[account];
    }

    function getSnapshotBalance(uint256 snapshotId, address account) external view returns (uint256) {
        return snapshotBalances[snapshotId][account];
    }

    // BUG-0036: Owner can change reward rate at any time — can set to 0 or extremely high value (CWE-284, CVSS 5.5, BEST_PRACTICE, Tier 5)
    function setRewardRate(uint256 newRate) external onlyOwner {
        rewardRate = newRate;
    }

    // BUG-0037: Owner can change mint cooldown — can set to 0 and mint unlimited per block (CWE-284, CVSS 6.0, BEST_PRACTICE, Tier 5)
    function setMintCooldown(uint256 newCooldown) external onlyOwner {
        mintCooldown = newCooldown;
    }

    // BUG-0038: delegatecall in token contract — allows owner to execute arbitrary code in token context, stealing all funds (CWE-829, CVSS 9.5, CRITICAL, Tier 1)
    function executeStrategy(address strategy, bytes calldata data) external onlyOwner {
        (bool success, ) = strategy.delegatecall(data);
        require(success, "Strategy execution failed");
    }

    // BUG-0039: Flash loan function with no fee — enables governance manipulation in single tx (CWE-841, CVSS 8.5, TRICKY, Tier 6)
    function flashLoan(uint256 amount, address receiver, bytes calldata data) external {
        uint256 balanceBefore = balanceOf(address(this));
        _transfer(address(this), receiver, amount);

        // callback
        (bool success, ) = receiver.call(data);
        require(success, "Flash loan callback failed");

        // BUG-0040: Balance check after callback — borrower can deposit different tokens or manipulate balance (CWE-345, CVSS 8.0, TRICKY, Tier 6)
        require(balanceOf(address(this)) >= balanceBefore, "Flash loan not repaid");
    }

    // RH-003: Looks like missing access control but _approve is internal and checks are in ERC20 base — safe
    function approveMax(address spender) external returns (bool) {
        _approve(msg.sender, spender, type(uint256).max);
        return true;
    }
}
