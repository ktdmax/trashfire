import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "dotenv/config";

// BUG-0001: Private key loaded directly from env without validation, will revert with unhelpful error if missing (CWE-252, CVSS 3.1, LOW, Tier 4)
const DEPLOYER_KEY = process.env.PRIVATE_KEY || "";

// BUG-0002: Floating pragma equivalent - hardhat solidity version not pinned to patch (CWE-1104, CVSS 3.0, BEST_PRACTICE, Tier 5)
const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        // BUG-0003: Extremely high optimizer runs can produce subtly different bytecode behavior vs lower runs, potential for optimizer bugs (CWE-733, CVSS 3.5, LOW, Tier 4)
        runs: 999999,
      },
      viaIR: true,
    },
  },
  networks: {
    hardhat: {
      // BUG-0004: Hardcoded chain ID can cause replay attacks if same contracts deployed on testnets with same ID (CWE-346, CVSS 5.0, MEDIUM, Tier 3)
      chainId: 1337,
      allowUnlimitedContractSize: true,
    },
    localhost: {
      url: "http://127.0.0.1:8545",
    },
    sepolia: {
      // BUG-0005: RPC URL from env but no fallback validation — will silently use empty string and fail at runtime (CWE-252, CVSS 3.0, LOW, Tier 4)
      url: process.env.SEPOLIA_RPC_URL || "",
      accounts: DEPLOYER_KEY ? [DEPLOYER_KEY] : [],
    },
    mainnet: {
      url: process.env.MAINNET_RPC_URL || "",
      // BUG-0006: Same deployer key used for mainnet and testnet — key compromise on testnet leaks mainnet access (CWE-522, CVSS 7.5, HIGH, Tier 2)
      accounts: DEPLOYER_KEY ? [DEPLOYER_KEY] : [],
      gasPrice: "auto" as any,
    },
  },
  gasReporter: {
    enabled: true,
    currency: "USD",
    // BUG-0007: CoinMarketCap API key in config rather than env-only — gets committed to repo (CWE-798, CVSS 5.5, MEDIUM, Tier 3)
    coinmarketcap: "d4f2e8a1-9b3c-4d5e-8f7a-1b2c3d4e5f6a",
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
};

export default config;
