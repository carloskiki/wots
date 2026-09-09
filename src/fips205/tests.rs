use super::{Sha2, Shake};
use crate::{
    Scheme,
    tests::{SignatureVector, bytes_from_hex, check, patterned_bytes},
};
use digest::{Output, OutputSizeUser};

struct TestVector<const N: usize> {
    layer: u8,
    tree: u64,
    address: u32,
    seed: [u8; N],
    first_secret: &'static str,
    last_secret: &'static str,
    chain_output: &'static str,
    expected: SignatureVector<N>,
}

// Reference values from the existing Python hashlib implementation of FIPS 205
// Algorithms 5-7 and Section 11. Each instance uses zero and patterned inputs.
const SHA2_16: [TestVector<16>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        first_secret: "08fe3cd164b8dcc8b712dfe8d9b603f2",
        last_secret: "1046e31cb26f3c69dab961feb800b97a",
        chain_output: "a9da4caa812546b9dd9340c5426506df",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "ca7f0d9cec2dcf88e858c11c5f4ceb9b6bade9b4a59fbc3dccbd03014469db62",
            public_key: "992bf9c5ad173b939ad169f0c6d38be3",
        },
    },
    TestVector {
        layer: 7,
        tree: 0x0123_4567_89ab_cdef,
        address: 0x1020_3040,
        seed: patterned_bytes(1, 0),
        first_secret: "435dd06a2921a4a39ab486f3d4d87b94",
        last_secret: "13b1cea0b455543f8ffaa31e879c9967",
        chain_output: "8036fbc35592d5db51c3247933b7f868",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "82195d60c3fa4376ea2b3f7f664a7feff7c0f9a834c93e416a5505fabef87c2f",
            public_key: "88f62772885cfcf93e1b80eec7342fb9",
        },
    },
];

const SHAKE_16: [TestVector<16>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        first_secret: "3d823f5044cfb4e8943e0c536b6d1080",
        last_secret: "eb5e43cbbf36ad3ef82192ef4675720b",
        chain_output: "1929b8c537410f1d5b30c6d21e073dba",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "d56326f93e978bba2ec95b29d11780b75aedd6b036af03a392486f9d495d5d78",
            public_key: "f888a76ddbfbddae6231bd4beef8deee",
        },
    },
    TestVector {
        layer: 7,
        tree: 0x0123_4567_89ab_cdef,
        address: 0x1020_3040,
        seed: patterned_bytes(1, 0),
        first_secret: "ae787ed04397be7cadd1127da2ebdba5",
        last_secret: "c579701e2108b2da243b525e700d3880",
        chain_output: "a8682ccdd2a1a851b53d0b2b2a256b70",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "6500cba3e524f72ce4e335746cfa6834c9d7e9f3244f0d6132097d6c78a2d291",
            public_key: "b08d79349cd2719e85b55e86ab83430f",
        },
    },
];

const SHA2_24: [TestVector<24>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        first_secret: "0f4a2396d4adadbf5320ebdb616eb20f1ba2c2f501809d8d",
        last_secret: "0322682ee486dde070cc15016968e96661c54c6e9de628c3",
        chain_output: "3faec1c488da5a90799b1b9a084511f3ff45bff8241afd32",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "b9ecb67d818abb263446049b5d89ea6aa7bc8affc9092120a83048e8f7bf85b0",
            public_key: "afc9177d84b885b3f59b604a58e9987476c8f0d59e5c1c9a",
        },
    },
    TestVector {
        layer: 7,
        tree: 0x0123_4567_89ab_cdef,
        address: 0x1020_3040,
        seed: patterned_bytes(1, 0),
        first_secret: "5d2b23497ea1fb56c1a650098a201a30a2a70c6f5f0c0fc0",
        last_secret: "31a1151672a2b6422504429aafcbc409183cdf392c09f6a2",
        chain_output: "7346b2fffdf2411e05a9887df7aa51bae770c083ba91aeca",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "19771dc907b48dc25d44f2de009c167ab1baf7934fb15e84d14757cb17b6463a",
            public_key: "0e93eba9a1ece297ff6b6ca8bc9f4b919cbbb83cf358470d",
        },
    },
];

const SHAKE_24: [TestVector<24>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        first_secret: "f0001775ab0903e28c062893d5f7d9a82fb01e54023c299a",
        last_secret: "d0802835ea9f640596f945100f5e5df455c4b4c3b104a7a0",
        chain_output: "6d69430d16d5b8fb795df284cfa0648e393428595311ac21",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "9aeebc60c880b4b41c7525ed4af2b8a3c319801fa8c1673befd7dcd678149bec",
            public_key: "daab459fcbb316fc9f0c751c61d1de2685c989fb72a1bac5",
        },
    },
    TestVector {
        layer: 7,
        tree: 0x0123_4567_89ab_cdef,
        address: 0x1020_3040,
        seed: patterned_bytes(1, 0),
        first_secret: "857f123494d3f4cc310fcf8ef07eed1d1e7369f0780b652e",
        last_secret: "94390fdef14a3eb44b50a75f59037ff86a0a1f82929ae153",
        chain_output: "885fa8f4c99f979f06dde7c0dac3926323b6f5012a4d680c",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "ba81b8d66f9b2ef1fe502873148c94cf69dad5305c933a2c0ec7942a8ba04ade",
            public_key: "0c4559c307a8a6dbe6ea6d2b19c1e1ebd1f876f96adb0cf2",
        },
    },
];

const SHA2_32: [TestVector<32>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        first_secret: "60e9c390cf0cb6e6d84e3c39cd971d8f18710246970e53763395654499240d6a",
        last_secret: "c02949c689b3cd0249efd30dd4fe1259b11581d3a0d18a772e34672ef24c6e18",
        chain_output: "37eb2bbc52960c69189ac91ccbb27821b4f29088d2daf2ece7add88e1dfbf5f8",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "ebcb0e9a9a4cf26b58c9e80753cddd5485c17a98fcd79b86f5592f825df79243",
            public_key: "5e0d8591bdb73c3a481b2d55afa92555ec32ec0b8c65b787b4ac5f8e7ce003eb",
        },
    },
    TestVector {
        layer: 7,
        tree: 0x0123_4567_89ab_cdef,
        address: 0x1020_3040,
        seed: patterned_bytes(1, 0),
        first_secret: "2bc748f267814dff1a627b262908a0d75804e351916590664864d3529fa3b408",
        last_secret: "1046d76d903017218a1f46d2f97151899013b3b92263b66aa1b36cebcaf63edd",
        chain_output: "6e3029c4affad4c8a6cb20ce4c53539c19178c478986cb8e623f04028fe6ef37",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "81256fcf4a56df00e16fd32ac1a5594dfafc9c8d1c4248029ac3356733945386",
            public_key: "db11314cbdf715d0d96be4644752fd020d7a2b2cb9580a55f1451af09a838e33",
        },
    },
];

const SHAKE_32: [TestVector<32>; 2] = [
    TestVector {
        layer: 0,
        tree: 0,
        address: 0,
        seed: patterned_bytes(0, 0),
        first_secret: "4413a9e574f1ec8262647169e6aa8f8ee32bd758c2ba5f3ccc902200df2c9723",
        last_secret: "55a783486dedf5d9625b93c9d5f08ce17008ef301fa486aee3c571113469573a",
        chain_output: "65eccca1c491a7cff15444631d7537c52f6b1664de15478a564c2ad479daa353",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: patterned_bytes(0, 0),
            signature_hash: "2b12de68bc024b3730e55b204c2579ed322a490cc473cd25551819b97f5d75d1",
            public_key: "f81e7dea3dbc337cbfae4481ea92dc430f223f744dff609a08ca08ac79d92441",
        },
    },
    TestVector {
        layer: 7,
        tree: 0x0123_4567_89ab_cdef,
        address: 0x1020_3040,
        seed: patterned_bytes(1, 0),
        first_secret: "964699339184bd89ef4de9cec13b20cfb5ea4f7f3104c656660b8ccfea1d09da",
        last_secret: "80686261ac719a9ebbd41776d8963ab22ca53c41b4b61931c75111e85fd2861c",
        chain_output: "65f387d0cddd44dfb657014f316361ffd5f4c6bc39adfc92e8ae9fd5705e7a3c",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: patterned_bytes(3, 37),
            signature_hash: "9ced4133274f4a48636010b372a3dad14540eb1733197df88025da12c3bd67c6",
            public_key: "d0cccd60063a5757f6d545dfdfad7d40d5a52d30fdd021e97d0c9e3dd148e0d5",
        },
    },
];

#[test]
fn sha2_16() {
    for vector in &SHA2_16 {
        let mut scheme = Sha2::<16>::from(&vector.seed);
        scheme.layer = vector.layer;
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

#[test]
fn shake_16() {
    for vector in &SHAKE_16 {
        let mut scheme = Shake::<16>::from(&vector.seed);
        scheme.layer = u32::from(vector.layer);
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

#[test]
fn sha2_24() {
    for vector in &SHA2_24 {
        let mut scheme = Sha2::<24>::from(&vector.seed);
        scheme.layer = vector.layer;
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

#[test]
fn shake_24() {
    for vector in &SHAKE_24 {
        let mut scheme = Shake::<24>::from(&vector.seed);
        scheme.layer = u32::from(vector.layer);
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

#[test]
fn sha2_32() {
    for vector in &SHA2_32 {
        let mut scheme = Sha2::<32>::from(&vector.seed);
        scheme.layer = vector.layer;
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

#[test]
fn shake_32() {
    for vector in &SHAKE_32 {
        let mut scheme = Shake::<32>::from(&vector.seed);
        scheme.layer = u32::from(vector.layer);
        scheme.tree = vector.tree;
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

fn test_vector<S, const N: usize>(scheme: S, vector: &TestVector<N>)
where
    S: Scheme<MessageSize = <S as OutputSizeUser>::OutputSize>,
    Output<S>: From<[u8; N]>,
{
    let len = N * 2 + 3;
    check(&scheme, &vector.expected, len);
    let private_key = Output::<S>::from(vector.expected.private_key);
    let starts: Vec<_> = scheme.generate(&private_key).collect();
    assert_eq!(
        starts[0].as_slice(),
        bytes_from_hex::<N>(vector.first_secret)
    );
    assert_eq!(
        starts[len - 1].as_slice(),
        bytes_from_hex::<N>(vector.last_secret)
    );
    assert_eq!(
        scheme.chain((len - 1) as u32, 14, &private_key).as_slice(),
        bytes_from_hex::<N>(vector.chain_output)
    );
}
