use super::{Sha256, Sha512, Shake256, Shake512};
use crate::tests::{SignatureVector, check, patterned_bytes};
use digest::Output;

struct TestVector<const N: usize> {
    layer: u32,
    tree: u64,
    address: u32,
    seed: [u8; N],
    expected: SignatureVector<N>,
}

// Generated with XMSS/xmss-reference commit 171ccbd26f098542a67eb5d2b128281c80bd71a6
// using the XMSS-SHA2_10_256 parameter set and RFC 8391 Section 3.1.7 private-key
// expansion.
// Signatures are stored as SHA-256 digests of the complete reference output.
const SHA256: [TestVector<32>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "ca6321c3015970e58f2f8ab0912aae8b27cc657c9ce8533b3783a8de8c013c7d",
            public_key: "9e04d2eb1655163bd257ab3ab9e0ac286bfb7fac680bd8eb0606ad37e4f773d4",
        },
    },
    TestVector {
        layer: 1,
        tree: 0x0123_4567_89ab_cdef,
        address: 42,
        seed: patterned_bytes(1, 0),
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "da9276b149de8fbf62d89c4027ac816202035edacbda690933481e8f9f54768c",
            public_key: "b7bf12f9d0e95578616f241957f504c1fb135a5a0a6cedb6c4610b5517c2374a",
        },
    },
];

// Generated with XMSS/xmss-reference commit 171ccbd26f098542a67eb5d2b128281c80bd71a6
// using the XMSS-SHA2_10_512 parameter set and RFC 8391 Section 3.1.7 private-key
// expansion.
// Signatures are stored as SHA-256 digests of the complete reference output.
const SHA512: [TestVector<64>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "210cf4189ec66982afb030f3e161a09551c38378acf2a04bebfc9f934834ac81",
            public_key: "4cc21096660f9835809a93db9ee2f7d6e8792cc411863cb69f01004e143761beb7616165e9355f1d52f9c86bd7affeb4673f0d2ff579a9de2adc6d2ba7474231",
        },
    },
    TestVector {
        layer: 1,
        tree: 0x0123_4567_89ab_cdef,
        address: 42,
        seed: patterned_bytes(1, 0),
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "a9a444b747af39cde50f52af301df28d0c002536efe7fd90244e3c89e4461c53",
            public_key: "e7cab9ff7c13677644405827cf9e057a4402ebe2efea0fdfaa088e6e11cbdba4db9e54b15a99015f6ebbe168323ff916fbe1a008e26690a34ca4352e60e6a0c1",
        },
    },
];

// Generated with XMSS/xmss-reference commit 171ccbd26f098542a67eb5d2b128281c80bd71a6
// using the XMSS-SHAKE_10_256 parameter set and RFC 8391 Section 3.1.7 private-key
// expansion.
// Signatures are stored as SHA-256 digests of the complete reference output.
const SHAKE256: [TestVector<32>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "8c99308be2afc4386197d19af7604e09fc292a3da061f6d2b7492650e170b605",
            public_key: "ea818c3d07c2f6eefa2d88085d0ea69b15f6ec8c278b81918fb0ec2966928c96",
        },
    },
    TestVector {
        layer: 1,
        tree: 0x0123_4567_89ab_cdef,
        address: 42,
        seed: patterned_bytes(1, 0),
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "3c9fdf65ec376a4ac72be059d57cc53702ece8c92291f6768c08c23947793432",
            public_key: "4eaccfd05b5422fe2cd2c4e54a718d727ad195bc6f8088bb2b7bc9864da2ad95",
        },
    },
];

// Generated with XMSS/xmss-reference commit 171ccbd26f098542a67eb5d2b128281c80bd71a6
// using the XMSS-SHAKE_10_512 parameter set and RFC 8391 Section 3.1.7 private-key
// expansion.
// Signatures are stored as SHA-256 digests of the complete reference output.
const SHAKE512: [TestVector<64>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "0b7b02134775dadf6910b31109df3d4acbf1b60dd8a4a58bb6d4c2666d6fed04",
            public_key: "1657c432900fa14f5b9793c3512302f8a2ae7f00a85a0a53352dd7ae0690df23cee6786038e5b212dc8649eeb1a898f6cb2365b713c78d176ce2dd3cf14339b1",
        },
    },
    TestVector {
        layer: 1,
        tree: 0x0123_4567_89ab_cdef,
        address: 42,
        seed: patterned_bytes(1, 0),
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "193613e9ddcad2ead579eb08057711f5a7283c7fff15db0940fe77e839646ec5",
            public_key: "fcae458fee13056302c0032e550313d1eca2713eb862ee876cdb9e40d1cdf26010df171eda3654e645f1d618826fd4839d30446139faa77d3b13087538203c6b",
        },
    },
];

#[test]
fn sha256() {
    for vector in &SHA256 {
        let seed = Output::<Sha256>::from(vector.seed);
        let mut scheme = Sha256::from(&seed);
        scheme.layer = vector.layer;
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        check(&scheme, &vector.expected, 67);
    }
}

#[test]
fn sha512() {
    for vector in &SHA512 {
        let seed = Output::<Sha512>::from(vector.seed);
        let mut scheme = Sha512::from(&seed);
        scheme.layer = vector.layer;
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        check(&scheme, &vector.expected, 131);
    }
}

#[test]
fn shake256() {
    for vector in &SHAKE256 {
        let seed = Output::<Shake256>::from(vector.seed);
        let mut scheme = Shake256::from(&seed);
        scheme.layer = vector.layer;
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        check(&scheme, &vector.expected, 67);
    }
}

#[test]
fn shake512() {
    for vector in &SHAKE512 {
        let seed = Output::<Shake512>::from(vector.seed);
        let mut scheme = Shake512::from(&seed);
        scheme.layer = vector.layer;
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        check(&scheme, &vector.expected, 131);
    }
}
