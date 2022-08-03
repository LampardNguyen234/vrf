const { setConfig } = require('./config.js')

const VRFVerifier = artifacts.require("VRFVerifier");

module.exports = async function (deployer, network) {
    let mainContract
    let mainContractAddress

    await deployer.deploy(VRFVerifier);
    mainContract = await VRFVerifier.deployed();
    mainContractAddress = await mainContract.address
    console.log("Main VRFVerifier contract deployed at address", mainContractAddress)
    setConfig('deployed.' + network + '.VRFVerifier', mainContractAddress)
};