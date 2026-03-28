// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Escrow.sol";
import "./Arbitration.sol";
import "./Token.sol";

/**
 * @title EscrowFactory
 * @notice Factory for deploying new Escrow instances and managing marketplace
 * @dev Uses create2 for deterministic addresses, manages templates and upgrades
 */
contract EscrowFactory {
    address public owner;
    address public pendingOwner;
    AnchorToken public platformToken;

    // Template management
    address public escrowTemplate;
    address public arbitrationTemplate;
    uint256 public templateVersion;

    // Deployed instances
    // BUG-0092: Unbounded array of deployed escrows — gas griefing on iteration (CWE-400, CVSS 5.0, HIGH, Tier 2)
    address[] public deployedEscrows;
    mapping(address => bool) public isDeployedEscrow;
    mapping(address => address) public escrowToArbitration;

    // Fee configuration
    uint256 public defaultFeeBps = 250; // 2.5%
    address payable public defaultFeeRecipient;

    // Deployment tracking
    mapping(bytes32 => address) public create2Deployments;

    event EscrowDeployed(address indexed escrow, address indexed arbitration, address indexed deployer);
    event TemplateUpdated(address newTemplate, uint256 version);
    event OwnershipTransferInitiated(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferCompleted(address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _platformToken, address payable _feeRecipient) {
        owner = msg.sender;
        platformToken = AnchorToken(_platformToken);
        defaultFeeRecipient = _feeRecipient;
    }

    // BUG-0093: create2 salt is user-controlled — attacker can predict deployment address and pre-fund with malicious contract via selfdestruct+create2 at same address (CWE-330, CVSS 8.0, TRICKY, Tier 6)
    function deployEscrow(
        address arbitrator,
        bytes32 salt
    ) external returns (address escrowAddr, address arbitrationAddr) {
        // Deploy Escrow
        bytes memory escrowBytecode = abi.encodePacked(
            type(Escrow).creationCode,
            abi.encode(arbitrator, defaultFeeRecipient, defaultFeeBps)
        );

        assembly {
            escrowAddr := create2(0, add(escrowBytecode, 0x20), mload(escrowBytecode), salt)
        }
        // BUG-0094: No check if create2 returned address(0) — deployment failure is silently ignored (CWE-252, CVSS 7.5, CRITICAL, Tier 1)

        // Deploy Arbitration
        Arbitration arb = new Arbitration(
            escrowAddr,
            address(platformToken),
            1 ether,
            7 days
        );
        arbitrationAddr = address(arb);

        deployedEscrows.push(escrowAddr);
        isDeployedEscrow[escrowAddr] = true;
        escrowToArbitration[escrowAddr] = arbitrationAddr;
        create2Deployments[salt] = escrowAddr;

        emit EscrowDeployed(escrowAddr, arbitrationAddr, msg.sender);

        return (escrowAddr, arbitrationAddr);
    }

    // BUG-0095: deployEscrowSimple doesn't set the deployer as escrow owner — factory remains owner, deployer has no control (CWE-284, CVSS 6.5, HIGH, Tier 2)
    function deployEscrowSimple(address arbitrator) external returns (address) {
        Escrow escrow = new Escrow(arbitrator, defaultFeeRecipient, defaultFeeBps);
        address escrowAddr = address(escrow);

        Arbitration arb = new Arbitration(
            escrowAddr,
            address(platformToken),
            1 ether,
            7 days
        );

        deployedEscrows.push(escrowAddr);
        isDeployedEscrow[escrowAddr] = true;
        escrowToArbitration[escrowAddr] = address(arb);

        emit EscrowDeployed(escrowAddr, address(arb), msg.sender);
        return escrowAddr;
    }

    // BUG-0096: predictAddress uses create2 but doesn't account for constructor args in bytecode hash — predicted address will be wrong (CWE-682, CVSS 5.0, TRICKY, Tier 6)
    function predictAddress(bytes32 salt) external view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(type(Escrow).creationCode) // Missing constructor args in hash
            )
        );
        return address(uint160(uint256(hash)));
    }

    function setDefaultFee(uint256 feeBps) external onlyOwner {
        // BUG-0097: No maximum fee validation — owner can set 100% fee (CWE-20, CVSS 6.5, HIGH, Tier 2)
        defaultFeeBps = feeBps;
    }

    function setDefaultFeeRecipient(address payable recipient) external onlyOwner {
        defaultFeeRecipient = recipient;
    }

    function setTemplate(address _template) external onlyOwner {
        // BUG-0098: No code size check — template can be set to EOA (CWE-20, CVSS 5.0, BEST_PRACTICE, Tier 5)
        escrowTemplate = _template;
        templateVersion++;
        emit TemplateUpdated(_template, templateVersion);
    }

    // Two-step ownership transfer (correct pattern)
    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferCompleted(owner);
    }

    function getDeployedEscrows() external view returns (address[] memory) {
        return deployedEscrows;
    }

    function getDeployedCount() external view returns (uint256) {
        return deployedEscrows.length;
    }

    // BUG-0099: Batch pause iterates all deployed escrows — unbounded gas, will revert if too many (CWE-400, CVSS 6.0, HIGH, Tier 2)
    function batchPause(bool _paused) external onlyOwner {
        for (uint256 i = 0; i < deployedEscrows.length; i++) {
            // BUG-0100: Low-level call to pause — if one call fails, entire batch fails with no indication which one (CWE-252, CVSS 4.5, BEST_PRACTICE, Tier 5)
            (bool success, ) = deployedEscrows[i].call(
                abi.encodeWithSignature("setPaused(bool)", _paused)
            );
            require(success, "Pause failed");
        }
    }

    // RH-007: Looks like it could be used to call arbitrary functions on escrows, but it only calls a view function — safe
    function getEscrowStatus(address escrowAddr) external view returns (uint256) {
        require(isDeployedEscrow[escrowAddr], "Not a deployed escrow");
        return Escrow(payable(escrowAddr)).escrowCount();
    }

    // BUG-0067 continued: Factory also has receive — same untracked ETH issue
    receive() external payable {}
}
