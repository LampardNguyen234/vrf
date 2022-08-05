const BN = require("bn.js");
const sha256 = require("js-sha256");
const elliptic = require("elliptic");
const utils = require("minimalistic-crypto-utils");
const EC = new elliptic.ec('secp256k1');
const ethers = require("ethers");

function _prove(secret_key, msg) {
    let public_key = EC.keyFromPrivate(secret_key.toArray()).getPublic();
    let H = hash_to_curve(public_key, msg);
    let h_string = H.encode('array', true);
    let Gamma = H.mul(secret_key);
    let k = nonce_generation(secret_key, h_string);
    let c = hash_points(H, Gamma, EC.g.mul(k), H.mul(k));
    let s = k.add(c.mul(secret_key)).umod(EC.n);
    return [
        ...Gamma.encode('array', true),
        ...c.toArray('be', 16),
        ...s.toArray('be', 32),
    ];
}

function _proof_to_hash(pi) {
    let D = decode_proof(pi);
    if (D === 'INVALID') {
        throw new Error('Invalid proof');
    }
    let Gamma = D.Gamma;
    return sha256.sha256
        .create()
        .update([254])
        .update([0x03])
        .update(Gamma.encode('array', false))
        .update([0x00])
        .digest();
}

function _verify(public_key, pi, msg) {
    let D = decode_proof(pi);
    if (D === 'INVALID') {
        throw new Error('Invalid proof');
    }
    let Gamma = D.Gamma, c = D.c, s = D.s;
    let H = hash_to_curve(public_key, msg);
    let U = EC.g.mul(s).add(public_key.mul(c).neg());
    let V = H.mul(s).add(Gamma.mul(c).neg());
    let c2 = hash_points(H, Gamma, U, V);
    if (!c.eq(c2)) {
        throw new Error('Invalid proof');
    }
    return _proof_to_hash(pi);
}

function _validate_key(public_key_string) {
    let public_key = string_to_point(public_key_string);
    if (public_key === 'INVALID' || public_key.isInfinity()) {
        throw new Error('Invalid public key');
    }
    return public_key;
}

function _toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

function _hexStringToByte(str) {
    if (!str) {
        return new Uint8Array();
    }

    let a = [];
    for (let i = 0, len = str.length; i < len; i+=2) {
        a.push(parseInt(str.substr(i,2),16));
    }

    return new Uint8Array(a);
}

function string_to_point(s) {
    try {
        return EC.curve.decodePoint(s, "hex");
    } catch {
        return 'INVALID';
    }
}

function arbitrary_string_to_point(s) {
    if (s.length !== 32) {
        throw new Error('s should be 32 byte');
    }
    return string_to_point([2, ...s])
}

function hash_to_curve(public_key, msg) {
    let hash = 'INVALID';
    let ctr = 0;
    let hash_string;
    let to_be_digested;
    while ((hash === 'INVALID' || hash.isInfinity()) && ctr < 256) {
        to_be_digested = ethers.utils.solidityPack(
            ["bytes", "bytes", "bytes", "bytes", "bytes"],
            [[254], [0x01], public_key.encode("array", true), msg, [ctr]]
        )
        to_be_digested = _hexStringToByte(to_be_digested.substring(2))
        hash_string = sha256.sha256
            .create()
            .update(to_be_digested)
            .digest();
        hash = arbitrary_string_to_point(hash_string); // cofactor = 1, skip multiply
        ctr += 1;
    }
    if (hash === 'INVALID') {
        throw new Error('hash_to_curve failed');
    }
    return hash;
}

function nonce_generation(secret_key, h_string) {
    let h1 = sha256.sha256.array(h_string);
    let K = new Array(32)
        .fill(0)
        .map(function (b) { return b.toString(16).padStart(2, '0'); })
        .join('');
    let V = new Array(32)
        .fill(1)
        .map(function (b) { return b.toString(16).padStart(2, '0'); })
        .join('');
    K = sha256.sha256.hmac
        .create(K)
        .update(V)
        .update([0x00])
        .update(secret_key.toArray())
        .update(h1)
        .hex();
    V = sha256.sha256.hmac.create(K).update(V).hex();
    K = sha256.sha256.hmac
        .create(K)
        .update(V)
        .update([0x01])
        .update(secret_key.toArray())
        .update(h1)
        .hex();
    V = sha256.sha256.hmac.create(K).update(V).hex();
    V = sha256.sha256.hmac.create(K).update(V).hex(); // qLen = hLen = 32, skip loop
    return new BN(V, 'hex');
}

function hash_points() {
    let points = [];
    for (let _i = 0; _i < arguments.length; _i++) {
        points[_i] = arguments[_i];
    }
    const str = [254, 0x02];
    for (let _a = 0, points_1 = points; _a < points_1.length; _a++) {
        let point = points_1[_a];
        str.push.apply(str, point.encode('array', true));
    }
    let c_string = sha256.sha256.digest(str);
    let truncated_c_string = c_string.slice(0, 16);
    let c = new BN(truncated_c_string);
    return c;
}

function decode_proof(pi) {
    const gamma_string = pi.slice(0, 33);
    const c_string = pi.slice(33, 33 + 16);
    const s_string = pi.slice(33 + 16, 33 + 16 + 32);
    const Gamma = string_to_point(gamma_string);
    if (Gamma === 'INVALID') {
        return 'INVALID';
    }

    const c = new BN(c_string);
    const s = new BN(s_string);

    return {
        Gamma,
        c,
        s,
    };
}

function keygen() {
    let keypair = EC.genKeyPair();
    let secret_key = keypair.getPrivate('hex');
    let public_key = keypair.getPublic('hex');
    return {
        secret_key: secret_key,
        public_key: public_key,
    };
}

function prove(secret_key, msg) {
    let pi = _prove(new BN(secret_key, 'hex'), digest(msg));
    return utils.toHex(pi);
}

function proof_to_hash(pi) {
    let beta = _proof_to_hash(utils.toArray(pi, 'hex'));
    return utils.toHex(beta);
}

function verify(public_key, pi, msg) {
    let beta = _verify(EC.curve.decodePoint(public_key, 'hex'), utils.toArray(pi, 'hex'), digest(msg));
    return utils.toHex(beta);
}

function validate_key(public_key) {
    _validate_key(utils.toArray(public_key, 'hex'));
    return;
}

function encode_point(p, compress=true, toString=true) {
    let compressed = p.encode("array", compress)
    if (toString) {
        let ret = compressed.map(b => b.toString(16).padStart(2, '0')).join('');
        return "0x".concat(ret)
    }

    return compressed
}

function digest(msg) {
    return sha256.sha256
        .create()
        .update(msg).digest()
}

function random_point() {
    let {public_key} = keygen()

    return EC.curve.decodePoint(public_key, 'hex')
}

module.exports = {
    string_to_point,
    hash_to_curve,
    hash_points,
    decode_proof,
    encode_point,
    keygen,
    prove,
    proof_to_hash,
    verify,
    validate_key,
    digest,
    random_point
}

