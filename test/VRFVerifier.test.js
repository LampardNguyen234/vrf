/* global artifacts:false, it:false, contract:false, assert:false */
const crypto = require("crypto");
const {assert} = require('chai')
const VRFVerifier = artifacts.require('VRFVerifier')
const {
    keygen,
    hash_to_curve,
    verify,
    decode_proof,
    hash_points,
    encode_point,
    validate_key,
    random_point,
    string_to_point, prove, digest, proof_to_hash
} = require('../scripts/utils')
const utils = require("minimalistic-crypto-utils");
const {randomBytes} = require("ethers/lib/utils");

require('chai')
    .use(require('chai-as-promised'))
    .should()

contract('VRFVerifier', (accounts) => {
    let instance;
    let public_key;
    let secret_key;
    let alpha;

    before(async () => {
        instance = await VRFVerifier.deployed()
    })

    beforeEach(async () => {
        let k = keygen();
        public_key = k.public_key
        secret_key = k.secret_key
        alpha = "0x73616d706c65"
    })

    describe('deployment', async () => {
        it('should deploy successfully', async () => {
            const addr = await instance.address

            assert.notEqual(addr, "")
            assert.notEqual(addr, null)
            assert.notEqual(addr, undefined)
        })
    })

    describe('encodePoint', async () => {
        it('should encode points with compression', async () => {
            public_key_point = string_to_point(public_key)

            let ret = await instance.encodePoint.call(
                public_key_point.x.toString(), public_key_point.y.toString()
            )

            assert.equal(ret, encode_point(public_key_point))
        })
    })

    describe('hashPoints', async () => {
        it('should match client side hashes', async () => {
            let H = random_point();
            let Gamma = random_point();
            let U = random_point();
            let V = random_point();

            let local_hash = hash_points(H, Gamma, U, V)

            let ret = await instance.hashPoints.call(
                H.x.toString(), H.y.toString(),
                Gamma.x.toString(), Gamma.y.toString(),
                U.x.toString(), U.y.toString(),
                V.x.toString(), V.y.toString(),
            )

            assert.equal("0x".concat(local_hash.toString(16, 32)), ret.toString())
        })
    })

    describe('hashToTryAndIncrement', async () => {
        it('should be the same as at the client side', async () => {
            let public_key_point = string_to_point(public_key)
            let hash = hash_to_curve(public_key_point, alpha)

            let ret = await instance.hashToTryAndIncrement.call(
                [public_key_point.x.toString(), public_key_point.y.toString()], alpha
            );

            assert.equal(ret['0'].toString(), hash.x.toString(), "x-coordinates don't match")
            assert.equal(ret['1'].toString(), hash.y.toString(), "y-coordinates don't match")
        })
    })

    describe('verify', async () => {
        let pi;
        let decoded_pi;
        let public_key_point;
        before(
            async () => {
                pi = prove(secret_key, alpha);
                const beta = proof_to_hash(pi);
                const res = verify(public_key, pi, alpha);
                assert.equal(beta.toString(), res.toString())

                decoded_pi = utils.toArray(pi, 'hex')
                decoded_pi = decode_proof(decoded_pi);

                public_key_point = string_to_point(public_key)
            }
        )
        it('correct evaluation should work', async () => {
            let ret = await instance.verify.call(
                [public_key_point.x.toString(), public_key_point.y.toString()],
                [decoded_pi.Gamma.x.toString(), decoded_pi.Gamma.y.toString(), decoded_pi.c.toString(), decoded_pi.s.toString()],
                digest(alpha),
            )

            assert.equal(ret, true)
        })

        it('altered proofs should not pass (Gamma.x)', async () => {
            let ret = await instance.verify.call(
                [public_key_point.x.toString(), public_key_point.y.toString()],
                [random_point().x.toString(), decoded_pi.Gamma.y.toString(), decoded_pi.c.toString(), decoded_pi.s.toString()],
                digest(alpha),
            )

            // correct proof should pass
            assert.equal(ret, false)
        })

        it('altered proofs should not pass (Gamma.y)', async () => {
            let ret = await instance.verify.call(
                [public_key_point.x.toString(), public_key_point.y.toString()],
                [decoded_pi.Gamma.x.toString(), random_point().y.toString(), decoded_pi.c.toString(), decoded_pi.s.toString()],
                digest(alpha),
            )

            // correct proof should pass
            assert.equal(ret, false)
        })

        it('altered proofs should not pass (c)', async () => {
            let ret = await instance.verify.call(
                [public_key_point.x.toString(), public_key_point.y.toString()],
                [decoded_pi.Gamma.x.toString(), decoded_pi.Gamma.y.toString(), random_point().x.toString(), decoded_pi.s.toString()],
                digest(alpha),
            )

            // correct proof should pass
            assert.equal(ret, false)
        })

        it('altered proofs should not pass (s)', async () => {
            let ret = await instance.verify.call(
                [public_key_point.x.toString(), public_key_point.y.toString()],
                [decoded_pi.Gamma.x.toString(), decoded_pi.Gamma.y.toString(), decoded_pi.c.toString(),  random_point().x.toString()],
                digest(alpha),
            )

            // correct proof should pass
            assert.equal(ret, false)
        })

        it('altered public_key should not pass (public_key.x)', async () => {
            let ret = await instance.verify.call(
                [random_point().x.toString(), public_key_point.y.toString()],
                [decoded_pi.Gamma.x.toString(), decoded_pi.Gamma.y.toString(), decoded_pi.c.toString(),  random_point().x.toString()],
                digest(alpha),
            )

            // correct proof should pass
            assert.equal(ret, false)
        })

        it('altered public_key should not pass (public_key.y)', async () => {
            let ret = await instance.verify.call(
                [public_key_point.x.toString(), random_point().y.toString()],
                [decoded_pi.Gamma.x.toString(), decoded_pi.Gamma.y.toString(), decoded_pi.c.toString(),  random_point().x.toString()],
                digest(alpha),
            )

            // correct proof should pass
            assert.equal(ret, false)
        })

        it('altered seed should not pass', async () => {
            let new_alpha = randomBytes(32);
            let ret = await instance.verify.call(
                [public_key_point.x.toString(), public_key_point.y.toString()],
                [decoded_pi.Gamma.x.toString(), decoded_pi.Gamma.y.toString(), decoded_pi.c.toString(), decoded_pi.s.toString()],
                digest(new_alpha),
            )

            assert.equal(ret, false)
        })
    })

})