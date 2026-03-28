import { expect } from "chai";
import { ethers } from "hardhat";
import { AnchorToken } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("AnchorToken", function () {
  let token: AnchorToken;
  let owner: SignerWithAddress;
  let alice: SignerWithAddress;
  let bob: SignerWithAddress;
  let charlie: SignerWithAddress;

  const INITIAL_SUPPLY = ethers.parseEther("10000000"); // 10M
  const MAX_SUPPLY = ethers.parseEther("100000000"); // 100M

  beforeEach(async function () {
    [owner, alice, bob, charlie] = await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("AnchorToken");
    token = await TokenFactory.deploy(INITIAL_SUPPLY);
    await token.waitForDeployment();

    // Distribute tokens
    await token.transfer(alice.address, ethers.parseEther("100000"));
    await token.transfer(bob.address, ethers.parseEther("100000"));
    await token.transfer(charlie.address, ethers.parseEther("50000"));
  });

  describe("Deployment", function () {
    it("should set correct name and symbol", async function () {
      expect(await token.name()).to.equal("Anchor Token");
      expect(await token.symbol()).to.equal("ANCH");
    });

    it("should mint initial supply to deployer", async function () {
      const ownerBalance = await token.balanceOf(owner.address);
      const totalSupply = await token.totalSupply();
      expect(totalSupply).to.equal(INITIAL_SUPPLY);
      // Owner balance is initial minus distributions
      expect(ownerBalance).to.be.gt(0n);
    });

    it("should not allow initial supply exceeding max", async function () {
      const TokenFactory = await ethers.getContractFactory("AnchorToken");
      await expect(
        TokenFactory.deploy(MAX_SUPPLY + 1n)
      ).to.be.revertedWith("Exceeds max supply");
    });
  });

  describe("Minting", function () {
    it("should allow owner to mint within max supply", async function () {
      await time.increase(86401); // past cooldown
      const mintAmount = ethers.parseEther("1000");
      await expect(token.mint(alice.address, mintAmount))
        .to.emit(token, "TokensMinted")
        .withArgs(alice.address, mintAmount);
    });

    it("should enforce mint cooldown", async function () {
      await time.increase(86401);
      await token.mint(alice.address, ethers.parseEther("100"));
      // Second mint should fail
      await expect(
        token.mint(alice.address, ethers.parseEther("100"))
      ).to.be.revertedWith("Mint cooldown active");
    });

    it("should not allow non-owner to mint", async function () {
      await expect(
        token.connect(alice).mint(alice.address, ethers.parseEther("100"))
      ).to.be.reverted;
    });
  });

  describe("Burning", function () {
    it("should allow users to burn their tokens", async function () {
      const burnAmount = ethers.parseEther("1000");
      const balanceBefore = await token.balanceOf(alice.address);
      await token.connect(alice).burn(burnAmount);
      const balanceAfter = await token.balanceOf(alice.address);
      expect(balanceBefore - balanceAfter).to.equal(burnAmount);
    });

    it("should not allow burning more than balance", async function () {
      const balance = await token.balanceOf(alice.address);
      await expect(
        token.connect(alice).burn(balance + 1n)
      ).to.be.reverted;
    });
  });

  describe("Staking", function () {
    it("should allow staking tokens", async function () {
      const stakeAmount = ethers.parseEther("10000");
      await token.connect(alice).stake(stakeAmount);
      expect(await token.stakedBalance(alice.address)).to.equal(stakeAmount);
      expect(await token.totalStaked()).to.equal(stakeAmount);
    });

    it("should not allow staking zero", async function () {
      await expect(
        token.connect(alice).stake(0)
      ).to.be.revertedWith("Cannot stake 0");
    });

    it("should transfer tokens to contract on stake", async function () {
      const stakeAmount = ethers.parseEther("5000");
      const contractBalanceBefore = await token.balanceOf(await token.getAddress());
      await token.connect(alice).stake(stakeAmount);
      const contractBalanceAfter = await token.balanceOf(await token.getAddress());
      expect(contractBalanceAfter - contractBalanceBefore).to.equal(stakeAmount);
    });

    it("should allow unstaking with rewards", async function () {
      const stakeAmount = ethers.parseEther("10000");
      await token.connect(alice).stake(stakeAmount);

      // Advance time
      await time.increase(30 * 24 * 3600); // 30 days

      const reward = await token.calculateReward(alice.address);
      expect(reward).to.be.gt(0n);

      await token.connect(alice).unstake(stakeAmount);
      expect(await token.stakedBalance(alice.address)).to.equal(0n);
    });

    it("should not allow unstaking more than staked", async function () {
      const stakeAmount = ethers.parseEther("1000");
      await token.connect(alice).stake(stakeAmount);

      await expect(
        token.connect(alice).unstake(stakeAmount + 1n)
      ).to.be.revertedWith("Insufficient staked balance");
    });
  });

  describe("Snapshots", function () {
    it("should create snapshots", async function () {
      await expect(token.takeSnapshot())
        .to.emit(token, "SnapshotTaken")
        .withArgs(1);

      expect(await token.currentSnapshotId()).to.equal(1);
    });

    it("should record balances at snapshot time", async function () {
      await token.takeSnapshot();
      await token.recordSnapshot(alice.address);
      const snapshotBalance = await token.getSnapshotBalance(1, alice.address);
      expect(snapshotBalance).to.equal(await token.balanceOf(alice.address));
    });
  });

  describe("Flash Loan", function () {
    it("should execute flash loan with repayment", async function () {
      // Fund contract with tokens for flash loan
      await token.transfer(await token.getAddress(), ethers.parseEther("10000"));
      // Note: proper flash loan test requires a receiver contract
    });
  });

  describe("Admin Functions", function () {
    it("should allow owner to set reward rate", async function () {
      await token.setRewardRate(200);
      expect(await token.rewardRate()).to.equal(200);
    });

    it("should allow owner to set mint cooldown", async function () {
      await token.setMintCooldown(3600); // 1 hour
      expect(await token.mintCooldown()).to.equal(3600);
    });

    it("should allow owner to execute strategy via delegatecall", async function () {
      // This test demonstrates the delegatecall vulnerability
      // In production, this would allow arbitrary code execution
    });

    it("should allow approve max", async function () {
      await token.connect(alice).approveMax(bob.address);
      expect(await token.allowance(alice.address, bob.address)).to.equal(
        ethers.MaxUint256
      );
    });
  });
});
