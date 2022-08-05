const {keygen, validate_key, prove, proof_to_hash, verify, decode_proof, digest} = require("./utils")
const {VRFVerifier, web3, address} = require("./load")
const elliptic = require("elliptic");
const EC = new elliptic.ec('secp256k1');
const utils = require("minimalistic-crypto-utils");

const generateRandomNumberAndProof = (secret_key, public_key, seed) => {
    // First validate if the public_key is in a good form
    validate_key(public_key)

    // Create the proof
    let pi = prove(secret_key, seed);

    // Generate the random number
    const randomNumber = proof_to_hash(pi);

    // Locally verify if the random number is correctly generated.
    const res = verify(public_key, pi, seed);
    if (res !== randomNumber) {
        throw new Error(`expect res to be ${randomNumber}, got ${res}`)
    }

    return {
        pi, randomNumber
    }
}

const verifyVRFProof = async (
    public_key,
    pi,
    seed
) => {
    let decoded_pi = utils.toArray(pi, 'hex');
    decoded_pi = decode_proof(decoded_pi);
    let public_key_point = EC.curve.decodePoint(public_key, 'hex')

    const gasEstimate = await VRFVerifier.methods.verify(
        [public_key_point.x.toString(), public_key_point.y.toString()],
        [decoded_pi.Gamma.x.toString(), decoded_pi.Gamma.y.toString(),
            decoded_pi.c.toString(), decoded_pi.s.toString()],
        digest(seed)
    ).estimateGas(
        { from: address });
    console.log(`estimatedGas for "verify()": ${gasEstimate}`)

    return await VRFVerifier.methods.verify(
        [public_key_point.x.toString(), public_key_point.y.toString()],
        [decoded_pi.Gamma.x.toString(), decoded_pi.Gamma.y.toString(),
            decoded_pi.c.toString(), decoded_pi.s.toString()],
        digest(seed)
    ).send({
        from: address,
        gas: gasEstimate
    })
}

(async () => {
    try {
        // the input
        let seed = "0x0102030405060708"

        // generate a key pair
        let {public_key, secret_key} = keygen()

        // Generate random number and proof
        let {pi, randomNumber} = generateRandomNumberAndProof(secret_key, public_key, seed)

        let ret = await verifyVRFProof(public_key, pi, seed)
        console.log("ret:", ret)
    } catch (e) {
        // This should return `Error: Returned error: execution reverted: User already has a proxy`
        console.log(e);
    }
})();

