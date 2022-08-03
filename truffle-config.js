const HDWalletProvider = require('@truffle/hdwallet-provider');
const fs = require('fs');

let testnetBSCProvider, mainnetBSCProvider
try {
  const privateKey = fs.readFileSync(".secret").toString().trim();
  testnetBSCProvider = new HDWalletProvider(privateKey, `https://data-seed-prebsc-1-s1.binance.org:8545`, 0, 1)
  mainnetBSCProvider = new HDWalletProvider(privateKey, `https://bsc-dataseed.binance.org/`, 0, 1)
} catch (e) {
  console.log(e)
}

module.exports = {
  plugins: ["truffle-contract-size"],
  networks: {
    development: {
      host: "127.0.0.1",
      port: 7545,
      network_id: "*" // Match any network id
    },
    testnet: {
      provider: testnetBSCProvider,
      network_id: 97,
      confirmations: 1,
      timeoutBlocks: 10000,
      gasLimit: 100000000
    },
  },

  contracts_directory: './contracts/',
  contracts_build_directory: './abi/',
  mocha: {
    reporter: "eth-gas-reporter",
    reporterOptions: {
      currency: "USD",
      gasPrice: 2,
    },
  },

  // Configure your compilers
  compilers: {
    solc: {
      version: "0.8.9",      // Fetch exact version from solc-bin (default: truffle's version)
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
};
