const Web3 = require('web3')
const provider = new Web3.providers.HttpProvider('https://rpc.astranaut.dev/')
const web3 = new Web3(provider)

const privateKey = "7fec54acd65a8e1109a02e9938ae6082f56e3aacdeccca26abc8cfbc8963b6c2"
const address = "0x1553584463f017f46227A10B76bc561908D4C448"
const loadKeys = (web3) => {
    web3.eth.accounts.wallet.add({
        privateKey: privateKey,
        address: address
    });
}

loadKeys(web3);

const VRFVerifierABI = require('../abi/VRFVerifier.json').abi

const networkID = '11115'
const VRFVerifierAddress = require('../abi/VRFVerifier.json').networks[networkID].address
const VRFVerifier = new web3.eth.Contract(VRFVerifierABI, VRFVerifierAddress);

module.exports = {web3, VRFVerifier, VRFVerifierAddress, address}