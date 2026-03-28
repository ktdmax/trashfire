import { ethers } from "hardhat";

/**
 * Seed script — populates the deployed marketplace with test data
 * Run after deploy.ts on a local hardhat node
 */
async function main() {
  const signers = await ethers.getSigners();
  const [deployer, client1, client2, freelancer1, freelancer2, arbitrator1, arbitrator2, arbitrator3] = signers;

  console.log("Seeding marketplace with test data...\n");

  // ---- Connect to deployed contracts ----
  // NOTE: In real usage, read addresses from deploy output or config
  // For local dev, we redeploy
  const initialSupply = ethers.parseEther("10000000");
  const TokenFactory = await ethers.getContractFactory("AnchorToken");
  const token = await TokenFactory.deploy(initialSupply);
  await token.waitForDeployment();
  const tokenAddress = await token.getAddress();

  const FactoryFactory = await ethers.getContractFactory("EscrowFactory");
  const factory = await FactoryFactory.deploy(tokenAddress, deployer.address);
  await factory.waitForDeployment();

  // Deploy an escrow instance
  const tx = await factory.deployEscrowSimple(arbitrator1.address);
  await tx.wait();
  const escrowAddress = await factory.deployedEscrows(0);
  const Escrow = await ethers.getContractFactory("Escrow");
  const escrow = Escrow.attach(escrowAddress);

  const arbAddress = await factory.escrowToArbitration(escrowAddress);
  const ArbFactory = await ethers.getContractFactory("Arbitration");
  const arbitration = ArbFactory.attach(arbAddress);

  // ---- Distribute tokens ----
  console.log("Distributing tokens...");
  const distributionAmount = ethers.parseEther("10000");
  for (const signer of [client1, client2, freelancer1, freelancer2, arbitrator1, arbitrator2, arbitrator3]) {
    await token.transfer(signer.address, distributionAmount);
  }
  console.log(`Distributed ${ethers.formatEther(distributionAmount)} ANCH to 7 accounts`);

  // ---- Register arbitrators ----
  console.log("\nRegistering arbitrators...");
  const stakeAmount = ethers.parseEther("1000");
  for (const arb of [arbitrator1, arbitrator2, arbitrator3]) {
    await token.connect(arb).approve(arbAddress, stakeAmount);
    await arbitration.connect(arb).registerArbitrator(stakeAmount);
    console.log(`  Arbitrator ${arb.address} registered with ${ethers.formatEther(stakeAmount)} ANCH`);
  }

  // ---- Create escrows ----
  console.log("\nCreating escrows...");

  // Escrow 1: ETH escrow, client1 -> freelancer1
  const escrow1Amount = ethers.parseEther("5");
  const deadline1 = Math.floor(Date.now() / 1000) + 30 * 24 * 3600; // 30 days
  const tx1 = await escrow.connect(client1).createEscrow(
    freelancer1.address,
    ethers.ZeroAddress, // ETH
    escrow1Amount,
    deadline1,
    { value: escrow1Amount }
  );
  await tx1.wait();
  console.log("  Escrow 1: 5 ETH, client1 -> freelancer1 (funded)");

  // Escrow 2: Token escrow, client2 -> freelancer2
  const escrow2Amount = ethers.parseEther("2000");
  await token.connect(client2).approve(escrowAddress, escrow2Amount);
  const tx2 = await escrow.connect(client2).createEscrow(
    freelancer2.address,
    tokenAddress,
    escrow2Amount,
    deadline1
  );
  await tx2.wait();
  // Fund it
  await escrow.connect(client2).fundEscrow(2);
  console.log("  Escrow 2: 2000 ANCH, client2 -> freelancer2 (funded)");

  // Escrow 3: ETH escrow, client1 -> freelancer2 (will be delivered)
  const escrow3Amount = ethers.parseEther("1");
  const tx3 = await escrow.connect(client1).createEscrow(
    freelancer2.address,
    ethers.ZeroAddress,
    escrow3Amount,
    deadline1,
    { value: escrow3Amount }
  );
  await tx3.wait();
  // Deliver work
  await escrow.connect(freelancer2).deliverWork(3, "QmTestHash123456789");
  console.log("  Escrow 3: 1 ETH, client1 -> freelancer2 (delivered)");

  // Escrow 4: ETH escrow, will be disputed
  const escrow4Amount = ethers.parseEther("3");
  const tx4 = await escrow.connect(client2).createEscrow(
    freelancer1.address,
    ethers.ZeroAddress,
    escrow4Amount,
    deadline1,
    { value: escrow4Amount }
  );
  await tx4.wait();
  await escrow.connect(freelancer1).deliverWork(4, "QmDisputedWork987654");
  await escrow.connect(client2).raiseDispute(4);
  console.log("  Escrow 4: 3 ETH, client2 -> freelancer1 (disputed)");

  // Escrow 5: Small ETH escrow, will be completed
  const escrow5Amount = ethers.parseEther("0.5");
  const tx5 = await escrow.connect(client1).createEscrow(
    freelancer1.address,
    ethers.ZeroAddress,
    escrow5Amount,
    deadline1,
    { value: escrow5Amount }
  );
  await tx5.wait();
  await escrow.connect(freelancer1).deliverWork(5, "QmCompletedWork111222");
  await escrow.connect(client1).approveDelivery(5);
  console.log("  Escrow 5: 0.5 ETH, client1 -> freelancer1 (completed)");

  // ---- Create a dispute and vote ----
  console.log("\nCreating dispute for escrow 4...");
  const disputeTx = await arbitration.connect(client2).createDispute(4);
  await disputeTx.wait();

  // Submit evidence
  await arbitration.connect(client2).submitEvidence(1, "QmClientEvidence111");
  await arbitration.connect(freelancer1).submitEvidence(1, "QmFreelancerEvidence222");

  // Cast votes
  await arbitration.connect(arbitrator1).castVote(1, true); // for client
  await arbitration.connect(arbitrator2).castVote(1, false); // for freelancer
  await arbitration.connect(arbitrator3).castVote(1, true); // for client
  console.log("  3 arbitrators voted on dispute 1");

  // ---- Stake tokens for governance ----
  console.log("\nStaking tokens for governance...");
  const govStake = ethers.parseEther("5000");
  await token.connect(client1).approve(tokenAddress, govStake);
  await token.connect(client1).stake(govStake);
  console.log(`  client1 staked ${ethers.formatEther(govStake)} ANCH`);

  // Take governance snapshot
  await token.takeSnapshot();
  console.log("  Snapshot taken");

  // ---- Print summary ----
  console.log("\n=== Seed Summary ===");
  console.log(`Token: ${tokenAddress}`);
  console.log(`Factory: ${await factory.getAddress()}`);
  console.log(`Escrow: ${escrowAddress}`);
  console.log(`Arbitration: ${arbAddress}`);
  console.log(`Escrows created: ${await escrow.getEscrowCount()}`);
  console.log(`Disputes created: ${await arbitration.disputeCount()}`);
  console.log(`Total staked (governance): ${ethers.formatEther(await token.totalStaked())} ANCH`);
  console.log("====================\n");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
