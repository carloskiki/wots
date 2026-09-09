use super::Sha256;
use crate::{
    Scheme,
    tests::{SignatureVector, bytes_from_hex, check, patterned_bytes},
};
use digest::{Digest, Output};

struct TestVector {
    identifier: [u8; 16],
    address: u32,
    randomizer: [u8; 32],
    message: &'static [u8],
    first_secret: &'static str,
    last_secret: &'static str,
    expected: SignatureVector<32>,
    lms_root: Option<&'static str>,
}

// Generated independently with Python hashlib. Each instance has two vectors:
// patterned inputs and zero inputs, except W=4, whose second vector is the
// published RFC 8554 Appendix F, Test Case 2 (top-level LM-OTS signature).
const SHA256_W1: [TestVector; 2] = [
    TestVector {
        identifier: patterned_bytes(1, 0),
        address: 19088743,
        randomizer: patterned_bytes(3, 37),
        message: b"LM-OTS test message",
        first_secret: "00a25cdd2f146fb33926aee4f2af964c248966d3f2f15ec3db649649f9c784e6",
        last_secret: "3bd83e89041b03e6ccd8216aef9ad8078bbaba503e6d678d5b90f3d19ef5fd67",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: bytes_from_hex(
                "6231777f1ba0321846498ab0dd3ab1d216e29694db870846a1087fad01f2a2f3",
            ),
            signature_hash: "40f9bea1ec1c448ba86184e8ec1e0d354c2816915c2bba39efef15592abf8106",
            public_key: "930420908c6b6484a5ae6b361471ab547f9f8543f4e195850d9ee5df48be782e",
        },
        lms_root: None,
    },
    TestVector {
        identifier: patterned_bytes(0, 0),
        address: 0,
        randomizer: patterned_bytes(0, 0),
        message: b"",
        first_secret: "83c272799301bd680149468f931037183a881ece73ac4c165a034226decdf712",
        last_secret: "4d3c16c92aa6273b92a8b108989f3ddd23ac80f028ad64cd0439bb5cd951cd37",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: bytes_from_hex(
                "6280e1a08bd6fd945496905e346759da56b3abe210d0d9a926462c300e5baf67",
            ),
            signature_hash: "430a398a29b90db7fcc59185f364983bf5243afc5fc2dc5c8df693fd0d00df6a",
            public_key: "df8762df7b251bd81bd7a98ab1dfb7c9e260316aad2a103d7742a9ca685a56f0",
        },
        lms_root: None,
    },
];

const SHA256_W2: [TestVector; 2] = [
    TestVector {
        identifier: patterned_bytes(1, 0),
        address: 19088743,
        randomizer: patterned_bytes(3, 37),
        message: b"LM-OTS test message",
        first_secret: "00a25cdd2f146fb33926aee4f2af964c248966d3f2f15ec3db649649f9c784e6",
        last_secret: "942825cb900a1f6364d627ad66230b2a589d9a389e40502fc994febd4d3a4544",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: bytes_from_hex(
                "6231777f1ba0321846498ab0dd3ab1d216e29694db870846a1087fad01f2a2f3",
            ),
            signature_hash: "70ef3e75012728504a5c2d5cf31ef76dd7bf8c2fc38b58b3b7329b7ae320f7d6",
            public_key: "864f926b88b00cc6eda6a7f8df14d90995b05b9d29973abe39572935a0408a7f",
        },
        lms_root: None,
    },
    TestVector {
        identifier: patterned_bytes(0, 0),
        address: 0,
        randomizer: patterned_bytes(0, 0),
        message: b"",
        first_secret: "83c272799301bd680149468f931037183a881ece73ac4c165a034226decdf712",
        last_secret: "855c9712ff45bb0c095506b56c625eb2b5392496969a820ca5fb9b6c606d2887",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: bytes_from_hex(
                "6280e1a08bd6fd945496905e346759da56b3abe210d0d9a926462c300e5baf67",
            ),
            signature_hash: "67d3b6ea8f2228bf3c2c60e99b080057d3688f5ceb698130fac5a56f172db680",
            public_key: "2c28b9a02449e0b5ecbd09e395168c0304e17a34412a7228713965156200391f",
        },
        lms_root: None,
    },
];

const SHA256_W4: [TestVector; 2] = [
    TestVector {
        identifier: patterned_bytes(1, 0),
        address: 19088743,
        randomizer: patterned_bytes(3, 37),
        message: b"LM-OTS test message",
        first_secret: "00a25cdd2f146fb33926aee4f2af964c248966d3f2f15ec3db649649f9c784e6",
        last_secret: "dcbab7932e0b4e1fe1cdcdbaabea2c3c30ad992be4c68eec88562531994263fe",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: bytes_from_hex(
                "6231777f1ba0321846498ab0dd3ab1d216e29694db870846a1087fad01f2a2f3",
            ),
            signature_hash: "454a205e4093dfa533c19493eedb4dbc039065083fdd78fb1930067e04fa1c5a",
            public_key: "5b08bf0acec7fd740bd60c37d5f6b5c5d33cdd88cb3275fa2ccd9fb47039e98c",
        },
        lms_root: None,
    },
    TestVector {
        identifier: bytes_from_hex("d08fabd4a2091ff0a8cb4ed834e74534"),
        address: 3,
        randomizer: bytes_from_hex(
            "3d46bee8660f8f215d3f96408a7a64cf1c4da02b63a55f62c666ef5707a914ce",
        ),
        message: &bytes_from_hex::<56>(
            "0000000500000004215f83b7ccb9acbcd08db97b0d04dc2ba1cd035833e0e90059603f26e07ad2aad152338e7a5e5984bcd5f7bb4eba40b7",
        ),
        first_secret: "e62465a0680552573fd1dee2fa3fef45f9c1c543dde626fe728bd0963fdc5a56",
        last_secret: "69a391d7004b274ec3fbe24feea8ee9615c2b5b26783370497c81f0378f8b619",
        expected: SignatureVector {
            private_key: bytes_from_hex(
                "558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439",
            ),
            message: bytes_from_hex(
                "86aaba2943104a7223c7be465692f55477d1586d37c4c0250a04fedb0c9e8ef1",
            ),
            signature_hash: "a870be7db67d44a32f39c71c58bd3c03a843c13faad1750e442a95c74ef66c03",
            public_key: "a81150e45a64456bc42a11c4598b4e59f4a0c9f8f2b46a0c3984385a6d99029e",
        },
        lms_root: Some("32a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e"),
    },
];

const SHA256_W8: [TestVector; 2] = [
    TestVector {
        identifier: patterned_bytes(1, 0),
        address: 19088743,
        randomizer: patterned_bytes(3, 37),
        message: b"LM-OTS test message",
        first_secret: "00a25cdd2f146fb33926aee4f2af964c248966d3f2f15ec3db649649f9c784e6",
        last_secret: "1f1f8c192221acfb1894d262c1d932d52e0288acc3a73eeca07a8172a059abb6",
        expected: SignatureVector {
            private_key: patterned_bytes(73, 19),
            message: bytes_from_hex(
                "6231777f1ba0321846498ab0dd3ab1d216e29694db870846a1087fad01f2a2f3",
            ),
            signature_hash: "c31eb91ad18b1b7e7315b656828b58215f80ef38f3bc2d1cb9d21931bce0ef48",
            public_key: "3cd8ecae3d399247037075f2ef4cf3d1acecaf05b8c57c35e32771645aff9492",
        },
        lms_root: None,
    },
    TestVector {
        identifier: patterned_bytes(0, 0),
        address: 0,
        randomizer: patterned_bytes(0, 0),
        message: b"",
        first_secret: "83c272799301bd680149468f931037183a881ece73ac4c165a034226decdf712",
        last_secret: "4cdc8732f28544d5dd6c3cfc252c2e0061d275ca36ccdf6875b323af10702420",
        expected: SignatureVector {
            private_key: patterned_bytes(0, 0),
            message: bytes_from_hex(
                "6280e1a08bd6fd945496905e346759da56b3abe210d0d9a926462c300e5baf67",
            ),
            signature_hash: "586ddcf68cbd083924642094883db07daa691819a6dba703a89f2fcc813c6503",
            public_key: "30caeb690254345f3f470a706314ff8687e36b97c6f35c68981bcc876df420b3",
        },
        lms_root: None,
    },
];

#[test]
fn sha256_w1() {
    for vector in &SHA256_W1 {
        let mut scheme = Sha256::<1>::from(&vector.identifier);
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

#[test]
fn sha256_w2() {
    for vector in &SHA256_W2 {
        let mut scheme = Sha256::<2>::from(&vector.identifier);
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

#[test]
fn sha256_w4() {
    for vector in &SHA256_W4 {
        let mut scheme = Sha256::<4>::from(&vector.identifier);
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

#[test]
fn sha256_w8() {
    for vector in &SHA256_W8 {
        let mut scheme = Sha256::<8>::from(&vector.identifier);
        scheme.address = vector.address;
        test_vector(scheme, vector);
    }
}

fn test_vector<const W: u32>(mut scheme: Sha256<W>, vector: &TestVector) {
    let len = usize::from(Sha256::<W>::LEN);
    check(&scheme, &vector.expected, len);
    let private_key = Output::<Sha256<W>>::from(vector.expected.private_key);
    let randomizer = Output::<Sha256<W>>::from(vector.randomizer);
    let message = scheme.hash_message(&randomizer, vector.message);
    assert_eq!(message.as_slice(), vector.expected.message);
    let starts: Vec<_> = scheme.generate(&private_key).collect();
    assert_eq!(
        starts[0].as_slice(),
        bytes_from_hex::<32>(vector.first_secret)
    );
    assert_eq!(
        starts[len - 1].as_slice(),
        bytes_from_hex::<32>(vector.last_secret)
    );
    let public_key = Output::<Sha256<W>>::from(bytes_from_hex::<32>(vector.expected.public_key));
    let signature: Vec<_> = scheme.sign(&private_key, &message).collect();
    let changed_message = scheme.hash_message(&randomizer, b"LM-OTS changed message");
    assert!(!scheme.verify(&public_key, &changed_message, signature.clone()));
    let mut changed_randomizer = randomizer;
    changed_randomizer[0] ^= 1;
    let changed_message = scheme.hash_message(&changed_randomizer, vector.message);
    assert!(!scheme.verify(&public_key, &changed_message, signature.clone()));

    if let Some(root) = vector.lms_root {
        check_lms_root(&scheme, &public_key, root);
    }
    scheme.address ^= 1;
    assert!(!scheme.verify(&public_key, &message, signature.clone()));
    scheme.address ^= 1;
    let mut changed_identifier = vector.identifier;
    changed_identifier[0] ^= 1;
    let changed_scheme = Sha256::<W> {
        identifier: &changed_identifier,
        address: scheme.address,
    };
    assert!(!changed_scheme.verify(&public_key, &message, signature));
}

fn check_lms_root<const W: u32>(scheme: &Sha256<W>, public_key: &Output<Sha256<W>>, root: &str) {
    // Authenticate K against the published LMS root using the RFC's path.
    // https://www.rfc-editor.org/rfc/rfc8554.html#appendix-F
    let identifier = scheme.identifier;
    let mut index = 1024 + scheme.address;
    let mut digest = sha2::Sha256::new();
    digest.update(identifier);
    digest.update(index.to_be_bytes());
    digest.update(0x8282u16.to_be_bytes());
    digest.update(public_key);
    let mut node = digest.finalize();
    for sibling in [
        "b326493313053ced3876db9d237148181b7173bc7d042cefb4dbe94d2e58cd21",
        "a769db4657a103279ba8ef3a629ca84ee836172a9c50e51f45581741cf808315",
        "0b491cb4ecbbabec128e7c81a46e62a67b57640a0a78be1cbf7dd9d419a10cd8",
        "686d16621a80816bfdb5bdc56211d72ca70b81f1117d129529a7570cf79cf52a",
        "7028a48538ecdd3b38d3d5d62d26246595c4fb73a525a5ed2c30524ebb1d8cc8",
        "2e0c19bc4977c6898ff95fd3d310b0bae71696cef93c6a552456bf96e9d075e3",
        "83bb7543c675842bafbfc7cdb88483b3276c29d4f0a341c2d406e40d4653b7e4",
        "d045851acf6a0a0ea9c710b805cced4635ee8c107362f0fc8d80c14d0ac49c51",
        "6703d26d14752f34c1c0d2c4247581c18c2cf4de48e9ce949be7c888e9caebe4",
        "a415e291fd107d21dc1f084b1158208249f28f4f7c7e931ba7b3bd0d824a4570",
    ] {
        let sibling = bytes_from_hex::<32>(sibling);
        let mut digest = sha2::Sha256::new();
        digest.update(identifier);
        digest.update((index / 2).to_be_bytes());
        digest.update(0x8383u16.to_be_bytes());
        if index % 2 == 0 {
            digest.update(node);
            digest.update(sibling);
        } else {
            digest.update(sibling);
            digest.update(node);
        }
        node = digest.finalize();
        index /= 2;
    }
    assert_eq!(node.as_slice(), bytes_from_hex::<32>(root));
}
