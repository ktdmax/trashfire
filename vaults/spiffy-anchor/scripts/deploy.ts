import { ethers } from "hardhat";
import * as dotenv from "dotenv";

dotenv.config();

/**
 * Deploy script for Spiffy Anchor marketplace
 * Deploys: AnchorToken -> EscrowFactory -> Escrow -> Arbitration
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  // BUG-0001 (continued): If PRIVATE_KEY env is missing, this fails with unhelpful error

  // ---- Deploy AnchorToken ----
  const initialSupply = ethers.parseEther("10000000"); // 10M tokens
  const TokenFactory = await ethers.getContractFactory("AnchorToken");
  const token = await TokenFactory.deploy(initialSupply);
  await token.waitForDeployment();
  const tokenAddress = await token.getAddress();
  console.log("AnchorToken deployed to:", tokenAddress);

  // ---- Deploy EscrowFactory ----
  const feeRecipient = process.env.FEE_RECIPIENT || deployer.address;
  const FactoryFactory = await ethers.getContractFactory("EscrowFactory");
  const factory = await FactoryFactory.deploy(tokenAddress, feeRecipient);
  await factory.waitForDeployment();
  const factoryAddress = await factory.getAddress();
  console.log("EscrowFactory deployed to:", factoryAddress);

  // ---- Deploy first Escrow via Factory ----
  const deployTx = await factory.deployEscrowSimple(deployer.address);
  const receipt = await deployTx.wait();
  console.log("First Escrow deployed via factory, tx:", receipt?.hash);

  // ---- Read deployed escrow address ----
  const escrowCount = await factory.getDeployedCount();
  console.log("Total deployed escrows:", escrowCount.toString());

  if (escrowCount > 0n) {
    const escrowAddress = await factory.deployedEscrows(0);
    console.log("First Escrow at:", escrowAddress);

    const arbitrationAddress = await factory.escrowToArbitration(escrowAddress);
    console.log("Arbitration for first escrow:", arbitrationAddress);
  }

  // ---- Setup platform token for staking ----
  const stakingAmount = ethers.parseEther("100000"); // 100k tokens for staking pool
  // Transfer tokens to factory for potential rewards
  const transferTx = await token.transfer(factoryAddress, stakingAmount);
  await transferTx.wait();
  console.log("Transferred", ethers.formatEther(stakingAmount), "ANCH to factory");

  // ---- Output deployment summary ----
  console.log("\n=== Deployment Summary ===");
  console.log("Network:", (await ethers.provider.getNetwork()).name);
  console.log("Chain ID:", (await ethers.provider.getNetwork()).chainId.toString());
  console.log("AnchorToken:", tokenAddress);
  console.log("EscrowFactory:", factoryAddress);
  console.log("Fee Recipient:", feeRecipient);
  console.log("Platform Fee:", process.env.PLATFORM_FEE_BPS || "250", "bps");
  console.log("========================\n");

  // Verify contracts if on testnet/mainnet
  if ((await ethers.provider.getNetwork()).chainId !== 1337n) {
    console.log("Waiting for block confirmations...");
    // Wait for 5 blocks
    const currentBlock = await ethers.provider.getBlockNumber();
    while ((await ethers.provider.getBlockNumber()) < currentBlock + 5) {
      await new Promise((resolve) => setTimeout(resolve, 15000));
    }

    console.log("Verifying contracts on Etherscan...");
    try {
      const { run } = await import("hardhat");
      await run("verify:verify", {
        address: tokenAddress,
        constructorArguments: [initialSupply],
      });
      console.log("AnchorToken verified");

      await run("verify:verify", {
        address: factoryAddress,
        constructorArguments: [tokenAddress, feeRecipient],
      });
      console.log("EscrowFactory verified");
    } catch (error) {
      console.error("Verification failed:", error);
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
