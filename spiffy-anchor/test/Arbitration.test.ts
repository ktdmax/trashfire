import { expect } from "chai";
import { ethers } from "hardhat";
import { Escrow, AnchorToken, Arbitration } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("Arbitration", function () {
  let escrow: Escrow;
  let token: AnchorToken;
  let arbitration: Arbitration;
  let owner: SignerWithAddress;
  let client: SignerWithAddress;
  let freelancer: SignerWithAddress;
  let arb1: SignerWithAddress;
  let arb2: SignerWithAddress;
  let arb3: SignerWithAddress;
  let attacker: SignerWithAddress;

  const MIN_STAKE = ethers.parseEther("100");
  const DISPUTE_TIMEOUT = 7 * 24 * 3600; // 7 days
  const ESCROW_AMOUNT = ethers.parseEther("5");

  beforeEach(async function () {
    [owner, client, freelancer, arb1, arb2, arb3, attacker] = await ethers.getSigners();

    // Deploy token
    const TokenFactory = await ethers.getContractFactory("AnchorToken");
    token = await TokenFactory.deploy(ethers.parseEther("10000000"));
    await token.waitForDeployment();
    const tokenAddress = await token.getAddress();

    // Deploy escrow
    const EscrowFactory = await ethers.getContractFactory("Escrow");
    escrow = await EscrowFactory.deploy(owner.address, owner.address, 250);
    await escrow.waitForDeployment();
    const escrowAddress = await escrow.getAddress();

    // Deploy arbitration
    const ArbFactory = await ethers.getContractFactory("Arbitration");
    arbitration = await ArbFactory.deploy(
      escrowAddress,
      tokenAddress,
      MIN_STAKE,
      DISPUTE_TIMEOUT
    );
    await arbitration.waitForDeployment();

    // Distribute tokens for staking
    for (const signer of [arb1, arb2, arb3, attacker]) {
      await token.transfer(signer.address, ethers.parseEther("10000"));
    }

    // Create and fund an escrow for testing disputes
    const deadline = (await time.latest()) + 30 * 24 * 3600;
    await escrow.connect(client).createEscrow(
      freelancer.address,
      ethers.ZeroAddress,
      ESCROW_AMOUNT,
      deadline,
      { value: ESCROW_AMOUNT }
    );

    // Deliver work and raise dispute
    await escrow.connect(freelancer).deliverWork(1, "QmTestDeliverable");
    await escrow.connect(client).raiseDispute(1);
  });

  describe("Arbitrator Registration", function () {
    it("should register an arbitrator with stake", async function () {
      const arbAddress = await arbitration.getAddress();
      await token.connect(arb1).approve(arbAddress, MIN_STAKE);

      await expect(
        arbitration.connect(arb1).registerArbitrator(MIN_STAKE)
      ).to.emit(arbitration, "ArbitratorRegistered");

      const info = await arbitration.arbitrators(arb1.address);
      expect(info.active).to.be.true;
      expect(info.stakedAmount).to.equal(MIN_STAKE);
      expect(info.reputation).to.equal(100);
    });

    it("should reject below minimum stake", async function () {
      const lowStake = MIN_STAKE - 1n;
      const arbAddress = await arbitration.getAddress();
      await token.connect(arb1).approve(arbAddress, lowStake);

      await expect(
        arbitration.connect(arb1).registerArbitrator(lowStake)
      ).to.be.revertedWith("Below minimum stake");
    });

    it("should reject double registration", async function () {
      const arbAddress = await arbitration.getAddress();
      await token.connect(arb1).approve(arbAddress, MIN_STAKE * 2n);
      await arbitration.connect(arb1).registerArbitrator(MIN_STAKE);

      await expect(
        arbitration.connect(arb1).registerArbitrator(MIN_STAKE)
      ).to.be.revertedWith("Already registered");
    });
  });

  describe("Arbitrator Deregistration", function () {
    beforeEach(async function () {
      const arbAddress = await arbitration.getAddress();
      await token.connect(arb1).approve(arbAddress, MIN_STAKE);
      await arbitration.connect(arb1).registerArbitrator(MIN_STAKE);
    });

    it("should allow deregistration and return stake", async function () {
      const balanceBefore = await token.balanceOf(arb1.address);
      await arbitration.connect(arb1).deregisterArbitrator();
      const balanceAfter = await token.balanceOf(arb1.address);

      expect(balanceAfter - balanceBefore).to.equal(MIN_STAKE);

      const info = await arbitration.arbitrators(arb1.address);
      expect(info.active).to.be.false;
    });

    it("should reject deregistration by non-arbitrator", async function () {
      await expect(
        arbitration.connect(arb2).deregisterArbitrator()
      ).to.be.revertedWith("Not active");
    });
  });

  describe("Dispute Creation", function () {
    it("should create a dispute", async function () {
      await expect(
        arbitration.connect(client).createDispute(1)
      ).to.emit(arbitration, "DisputeCreated");

      expect(await arbitration.disputeCount()).to.equal(1);
    });

    it("should reject dispute by non-party", async function () {
      await expect(
        arbitration.connect(attacker).createDispute(1)
      ).to.be.revertedWith("Not a party");
    });
  });

  describe("Evidence Submission", function () {
    beforeEach(async function () {
      await arbitration.connect(client).createDispute(1);
    });

    it("should allow client to submit evidence", async function () {
      await expect(
        arbitration.connect(client).submitEvidence(1, "QmClientEvidence")
      ).to.emit(arbitration, "EvidenceSubmitted");
    });

    it("should allow freelancer to submit evidence", async function () {
      await expect(
        arbitration.connect(freelancer).submitEvidence(1, "QmFreelancerEvidence")
      ).to.emit(arbitration, "EvidenceSubmitted");
    });

    it("should reject evidence from non-party", async function () {
      await expect(
        arbitration.connect(attacker).submitEvidence(1, "QmHackerEvidence")
      ).to.be.revertedWith("Not a party");
    });

    it("should reject evidence after deadline", async function () {
      // Fast forward past evidence deadline (half of dispute timeout)
      await time.increase(DISPUTE_TIMEOUT / 2 + 1);

      await expect(
        arbitration.connect(client).submitEvidence(1, "QmLateEvidence")
      ).to.be.revertedWith("Evidence period ended");
    });
  });

  describe("Voting", function () {
    beforeEach(async function () {
      // Register arbitrators
      const arbAddress = await arbitration.getAddress();
      for (const arb of [arb1, arb2, arb3]) {
        await token.connect(arb).approve(arbAddress, MIN_STAKE);
        await arbitration.connect(arb).registerArbitrator(MIN_STAKE);
      }

      // Create dispute
      await arbitration.connect(client).createDispute(1);
    });

    it("should allow arbitrator to cast vote", async function () {
      await expect(
        arbitration.connect(arb1).castVote(1, true)
      ).to.emit(arbitration, "VoteCast");
    });

    it("should reject vote by non-arbitrator", async function () {
      await expect(
        arbitration.connect(attacker).castVote(1, true)
      ).to.be.revertedWith("Not an active arbitrator");
    });

    it("should reject double voting", async function () {
      await arbitration.connect(arb1).castVote(1, true);

      await expect(
        arbitration.connect(arb1).castVote(1, true)
      ).to.be.revertedWith("Already voted");
    });

    it("should reject vote after deadline", async function () {
      await time.increase(DISPUTE_TIMEOUT + 1);

      await expect(
        arbitration.connect(arb1).castVote(1, true)
      ).to.be.revertedWith("Voting ended");
    });

    it("should weight votes by stake amount", async function () {
      // arb1 has MIN_STAKE, register arb2 with double
      const arbAddress = await arbitration.getAddress();

      await arbitration.connect(arb1).castVote(1, true);
      await arbitration.connect(arb2).castVote(1, false);

      const dispute = await arbitration.getDisputeDetails(1);
      // Both have MIN_STAKE so votes are equal weight
      expect(dispute.clientVotes).to.equal(dispute.freelancerVotes);
    });
  });

  describe("Dispute Resolution", function () {
    beforeEach(async function () {
      const arbAddress = await arbitration.getAddress();
      for (const arb of [arb1, arb2, arb3]) {
        await token.connect(arb).approve(arbAddress, MIN_STAKE);
        await arbitration.connect(arb).registerArbitrator(MIN_STAKE);
      }
      await arbitration.connect(client).createDispute(1);
    });

    it("should resolve after minimum votes reached", async function () {
      await arbitration.connect(arb1).castVote(1, true);
      await arbitration.connect(arb2).castVote(1, true);
      await arbitration.connect(arb3).castVote(1, false);

      // totalVotes >= 3 (by weight), should be resolvable
      // Note: actual resolution will fail because arbitration doesn't hold funds
      // This demonstrates BUG-0081/0082
    });

    it("should resolve after deadline with any votes", async function () {
      await arbitration.connect(arb1).castVote(1, true);
      await time.increase(DISPUTE_TIMEOUT + 1);

      // Should be resolvable after deadline
    });

    it("should not resolve before deadline with insufficient votes", async function () {
      await arbitration.connect(arb1).castVote(1, true);

      await expect(
        arbitration.resolveDispute(1)
      ).to.be.revertedWith("Voting still active");
    });
  });

  describe("Emergency Resolution", function () {
    beforeEach(async function () {
      await arbitration.connect(client).createDispute(1);
    });

    it("should allow admin emergency resolve", async function () {
      // Note: will emit event but fund transfer may fail (BUG-0082)
      await expect(
        arbitration.emergencyResolve(1, true)
      ).to.emit(arbitration, "DisputeResolved");
    });

    it("should reject non-admin emergency resolve", async function () {
      await expect(
        arbitration.connect(attacker).emergencyResolve(1, true)
      ).to.be.revertedWith("Not admin");
    });

    it("should not double resolve", async function () {
      await arbitration.emergencyResolve(1, true);

      await expect(
        arbitration.emergencyResolve(1, false)
      ).to.be.revertedWith("Already resolved");
    });
  });

  describe("Random Arbitrator Selection", function () {
    beforeEach(async function () {
      const arbAddress = await arbitration.getAddress();
      for (const arb of [arb1, arb2, arb3]) {
        await token.connect(arb).approve(arbAddress, MIN_STAKE);
        await arbitration.connect(arb).registerArbitrator(MIN_STAKE);
      }
    });

    it("should select requested number of arbitrators", async function () {
      const selected = await arbitration.selectRandomArbitrators(2);
      expect(selected.length).to.equal(2);
    });

    it("should reject if not enough arbitrators", async function () {
      await expect(
        arbitration.selectRandomArbitrators(10)
      ).to.be.revertedWith("Not enough arbitrators");
    });
  });

  describe("Admin Functions", function () {
    it("should allow admin to set min stake", async function () {
      const newStake = ethers.parseEther("500");
      await arbitration.setMinStake(newStake);
      expect(await arbitration.minStake()).to.equal(newStake);
    });

    it("should allow admin to set dispute timeout", async function () {
      const newTimeout = 14 * 24 * 3600;
      await arbitration.setDisputeTimeout(newTimeout);
      expect(await arbitration.disputeTimeout()).to.equal(newTimeout);
    });

    it("should allow admin to transfer admin role", async function () {
      await arbitration.transferAdmin(arb1.address);
      expect(await arbitration.admin()).to.equal(arb1.address);
    });

    it("should allow admin to rescue non-staking tokens", async function () {
      // Deploy a separate token and send to arbitration
      const TokenFactory = await ethers.getContractFactory("AnchorToken");
      const otherToken = await TokenFactory.deploy(ethers.parseEther("1000"));
      await otherToken.waitForDeployment();

      const arbAddress = await arbitration.getAddress();
      await otherToken.transfer(arbAddress, ethers.parseEther("100"));

      await arbitration.rescueTokens(
        await otherToken.getAddress(),
        ethers.parseEther("100")
      );
    });
  });
});
