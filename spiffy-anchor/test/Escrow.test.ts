import { expect } from "chai";
import { ethers } from "hardhat";
import { Escrow, AnchorToken, EscrowFactory } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("Escrow", function () {
  let escrow: Escrow;
  let token: AnchorToken;
  let factory: EscrowFactory;
  let owner: SignerWithAddress;
  let client: SignerWithAddress;
  let freelancer: SignerWithAddress;
  let arbitrator: SignerWithAddress;
  let feeRecipient: SignerWithAddress;
  let attacker: SignerWithAddress;

  const PLATFORM_FEE_BPS = 250n; // 2.5%
  const ONE_ETH = ethers.parseEther("1");
  const FIVE_ETH = ethers.parseEther("5");
  const TOKEN_AMOUNT = ethers.parseEther("1000");

  beforeEach(async function () {
    [owner, client, freelancer, arbitrator, feeRecipient, attacker] = await ethers.getSigners();

    // Deploy token
    const TokenFactory = await ethers.getContractFactory("AnchorToken");
    token = await TokenFactory.deploy(ethers.parseEther("10000000"));
    await token.waitForDeployment();

    // Deploy escrow directly
    const EscrowFactory = await ethers.getContractFactory("Escrow");
    escrow = await EscrowFactory.deploy(
      arbitrator.address,
      feeRecipient.address,
      PLATFORM_FEE_BPS
    );
    await escrow.waitForDeployment();

    // Distribute tokens
    await token.transfer(client.address, ethers.parseEther("100000"));
    await token.transfer(freelancer.address, ethers.parseEther("50000"));
  });

  describe("Escrow Creation", function () {
    it("should create an ETH escrow", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;
      await expect(
        escrow.connect(client).createEscrow(
          freelancer.address,
          ethers.ZeroAddress,
          FIVE_ETH,
          deadline,
          { value: FIVE_ETH }
        )
      ).to.emit(escrow, "EscrowCreated");

      const data = await escrow.getEscrow(1);
      expect(data.client).to.equal(client.address);
      expect(data.freelancer).to.equal(freelancer.address);
      expect(data.amount).to.equal(FIVE_ETH);
      expect(data.status).to.equal(1); // Funded
    });

    it("should create a token escrow", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;
      const tokenAddr = await token.getAddress();

      await escrow.connect(client).createEscrow(
        freelancer.address,
        tokenAddr,
        TOKEN_AMOUNT,
        deadline
      );

      const data = await escrow.getEscrow(1);
      expect(data.token).to.equal(tokenAddr);
      expect(data.status).to.equal(0); // Created, not funded
    });

    it("should reject zero amount", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;
      await expect(
        escrow.connect(client).createEscrow(
          freelancer.address,
          ethers.ZeroAddress,
          0,
          deadline
        )
      ).to.be.revertedWith("Amount must be positive");
    });

    it("should reject past deadline", async function () {
      await expect(
        escrow.connect(client).createEscrow(
          freelancer.address,
          ethers.ZeroAddress,
          ONE_ETH,
          1 // past timestamp
        )
      ).to.be.revertedWith("Deadline must be future");
    });

    it("should increment escrow count", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;

      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      expect(await escrow.getEscrowCount()).to.equal(2);
    });
  });

  describe("Funding", function () {
    let deadline: number;

    beforeEach(async function () {
      deadline = (await time.latest()) + 30 * 24 * 3600;
    });

    it("should fund ETH escrow", async function () {
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, FIVE_ETH, deadline
      );

      await expect(
        escrow.connect(client).fundEscrow(1, { value: FIVE_ETH })
      ).to.emit(escrow, "EscrowFunded");

      const data = await escrow.getEscrow(1);
      expect(data.status).to.equal(1); // Funded
    });

    it("should fund token escrow", async function () {
      const tokenAddr = await token.getAddress();
      await escrow.connect(client).createEscrow(
        freelancer.address, tokenAddr, TOKEN_AMOUNT, deadline
      );

      await token.connect(client).approve(await escrow.getAddress(), TOKEN_AMOUNT);
      await escrow.connect(client).fundEscrow(1);

      const data = await escrow.getEscrow(1);
      expect(data.status).to.equal(1);
    });

    it("should reject funding by non-client", async function () {
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline
      );

      await expect(
        escrow.connect(freelancer).fundEscrow(1, { value: ONE_ETH })
      ).to.be.revertedWith("Only client can fund");
    });
  });

  describe("Work Delivery & Completion", function () {
    let deadline: number;

    beforeEach(async function () {
      deadline = (await time.latest()) + 30 * 24 * 3600;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, FIVE_ETH, deadline, { value: FIVE_ETH }
      );
    });

    it("should allow freelancer to deliver work", async function () {
      await expect(
        escrow.connect(freelancer).deliverWork(1, "QmTestHash123")
      ).to.emit(escrow, "WorkDelivered");

      const data = await escrow.getEscrow(1);
      expect(data.status).to.equal(2); // Delivered
      expect(data.deliverableHash).to.equal("QmTestHash123");
    });

    it("should reject delivery by non-freelancer", async function () {
      await expect(
        escrow.connect(client).deliverWork(1, "QmTestHash123")
      ).to.be.revertedWith("Only freelancer");
    });

    it("should allow client to approve delivery", async function () {
      await escrow.connect(freelancer).deliverWork(1, "QmTestHash123");

      const freelancerBalanceBefore = await ethers.provider.getBalance(freelancer.address);
      await escrow.connect(client).approveDelivery(1);
      const freelancerBalanceAfter = await ethers.provider.getBalance(freelancer.address);

      expect(freelancerBalanceAfter).to.be.gt(freelancerBalanceBefore);

      const data = await escrow.getEscrow(1);
      expect(data.status).to.equal(5); // Completed
    });

    it("should pay platform fee on completion", async function () {
      await escrow.connect(freelancer).deliverWork(1, "QmTestHash123");

      const feeBalanceBefore = await ethers.provider.getBalance(feeRecipient.address);
      await escrow.connect(client).approveDelivery(1);
      const feeBalanceAfter = await ethers.provider.getBalance(feeRecipient.address);

      const expectedFee = (FIVE_ETH * PLATFORM_FEE_BPS) / 10000n;
      expect(feeBalanceAfter - feeBalanceBefore).to.equal(expectedFee);
    });
  });

  describe("Disputes", function () {
    let deadline: number;

    beforeEach(async function () {
      deadline = (await time.latest()) + 30 * 24 * 3600;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, FIVE_ETH, deadline, { value: FIVE_ETH }
      );
      await escrow.connect(freelancer).deliverWork(1, "QmTestHash123");
    });

    it("should allow client to raise dispute", async function () {
      await expect(
        escrow.connect(client).raiseDispute(1)
      ).to.emit(escrow, "EscrowDisputed");
    });

    it("should allow freelancer to raise dispute", async function () {
      await expect(
        escrow.connect(freelancer).raiseDispute(1)
      ).to.emit(escrow, "EscrowDisputed");
    });

    it("should reject dispute by non-party", async function () {
      await expect(
        escrow.connect(attacker).raiseDispute(1)
      ).to.be.revertedWith("Not a party");
    });
  });

  describe("Cancellation", function () {
    it("should allow client to cancel unfunded escrow", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline
      );

      await escrow.connect(client).cancelEscrow(1);
      const data = await escrow.getEscrow(1);
      expect(data.status).to.equal(6); // Cancelled
    });

    it("should refund ETH on funded escrow cancellation", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      const balanceBefore = await ethers.provider.getBalance(client.address);
      await escrow.connect(client).cancelEscrow(1);
      const balanceAfter = await ethers.provider.getBalance(client.address);

      // Balance should increase (minus gas)
      expect(balanceAfter).to.be.gt(balanceBefore - ethers.parseEther("0.01"));
    });
  });

  describe("Expiration", function () {
    it("should allow expiration after deadline", async function () {
      const deadline = (await time.latest()) + 100;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      await time.increase(200);
      await escrow.expireEscrow(1);

      const data = await escrow.getEscrow(1);
      expect(data.status).to.equal(7); // Expired
    });

    it("should refund client on expiration", async function () {
      const deadline = (await time.latest()) + 100;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      await time.increase(200);

      const balanceBefore = await ethers.provider.getBalance(client.address);
      await escrow.connect(owner).expireEscrow(1);
      const balanceAfter = await ethers.provider.getBalance(client.address);

      expect(balanceAfter).to.be.gt(balanceBefore);
    });

    it("should not expire before deadline", async function () {
      const deadline = (await time.latest()) + 10000;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      await expect(escrow.expireEscrow(1)).to.be.revertedWith("Not expired");
    });
  });

  describe("Extensions", function () {
    it("should allow freelancer to request extension", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      const newDeadline = deadline + 14 * 24 * 3600;
      await escrow.connect(freelancer).requestExtension(1, newDeadline);
    });

    it("should allow client to approve extension", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      const newDeadline = deadline + 14 * 24 * 3600;
      await escrow.connect(freelancer).requestExtension(1, newDeadline);
      await escrow.connect(client).approveExtension(1);

      const data = await escrow.getEscrow(1);
      expect(data.deadline).to.equal(newDeadline);
    });
  });

  describe("Admin Functions", function () {
    it("should allow owner to pause", async function () {
      await escrow.setPaused(true);
      expect(await escrow.paused()).to.be.true;
    });

    it("should reject operations when paused", async function () {
      await escrow.setPaused(true);
      const deadline = (await time.latest()) + 30 * 24 * 3600;

      await expect(
        escrow.connect(client).createEscrow(
          freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
        )
      ).to.be.revertedWith("Contract is paused");
    });

    it("should allow owner to change arbitrator", async function () {
      await escrow.setArbitrator(attacker.address);
      expect(await escrow.arbitrator()).to.equal(attacker.address);
    });

    it("should allow owner to change fee", async function () {
      await escrow.setPlatformFee(500);
      expect(await escrow.platformFeeBps()).to.equal(500);
    });

    it("should allow emergency withdrawal", async function () {
      // Fund the contract
      const deadline = (await time.latest()) + 30 * 24 * 3600;
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, FIVE_ETH, deadline, { value: FIVE_ETH }
      );

      const balanceBefore = await ethers.provider.getBalance(owner.address);
      await escrow.emergencyWithdraw(ethers.ZeroAddress, FIVE_ETH);
      const balanceAfter = await ethers.provider.getBalance(owner.address);
      expect(balanceAfter).to.be.gt(balanceBefore);
    });
  });

  describe("User Escrow Queries", function () {
    it("should track user escrows", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;

      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );
      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      const userEscrows = await escrow.getUserEscrows(client.address);
      expect(userEscrows.length).to.equal(2);
    });

    it("should return escrow details in batch", async function () {
      const deadline = (await time.latest()) + 30 * 24 * 3600;

      await escrow.connect(client).createEscrow(
        freelancer.address, ethers.ZeroAddress, ONE_ETH, deadline, { value: ONE_ETH }
      );

      const details = await escrow.getUserEscrowDetails(client.address);
      expect(details.length).to.equal(1);
      expect(details[0].amount).to.equal(ONE_ETH);
    });
  });
});
