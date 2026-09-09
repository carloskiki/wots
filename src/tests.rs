use crate::Scheme;
use digest::{Digest, Output, OutputSizeUser};

pub(crate) struct SignatureVector<const N: usize> {
    pub private_key: [u8; N],
    pub message: [u8; N],
    pub signature_hash: &'static str,
    pub public_key: &'static str,
}

pub(crate) const fn patterned_bytes<const N: usize>(multiplier: u8, addend: u8) -> [u8; N] {
    let mut result = [0; N];
    let mut i = 0;
    while i < N {
        result[i] = (i as u8).wrapping_mul(multiplier).wrapping_add(addend);
        i += 1;
    }
    result
}

pub(crate) const fn bytes_from_hex<const N: usize>(value: &str) -> [u8; N] {
    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid hexadecimal test-vector byte"),
        }
    }
    let value = value.as_bytes();
    assert!(value.len() == N * 2);
    let mut result = [0; N];
    let mut i = 0;
    while i < N {
        result[i] = nibble(value[2 * i]) << 4 | nibble(value[2 * i + 1]);
        i += 1;
    }
    result
}

pub(crate) fn check<S, const N: usize>(scheme: &S, vector: &SignatureVector<N>, len: usize)
where
    S: Scheme<MessageSize = <S as OutputSizeUser>::OutputSize>,
    Output<S>: From<[u8; N]>,
{
    let private_key = Output::<S>::from(vector.private_key);
    let message = Output::<S>::from(vector.message);
    let public_key = Output::<S>::from(bytes_from_hex::<N>(vector.public_key));

    assert_eq!(scheme.generate(&private_key).count(), len);
    let signature: Vec<_> = scheme.sign(&private_key, &message).collect();
    assert_eq!(signature.len(), len);
    let mut digest = sha2::Sha256::new();
    for element in &signature {
        digest.update(element);
    }
    assert_eq!(
        digest.finalize().as_slice(),
        bytes_from_hex::<32>(vector.signature_hash)
    );
    assert_eq!(scheme.verifying_key(&private_key), public_key);
    assert!(scheme.verify(&public_key, &message, signature.clone()));

    let mut changed_message = message.clone();
    changed_message[0] ^= 0x80;
    assert!(!scheme.verify(&public_key, &changed_message, signature.clone()));
    for index in [0, len - 1] {
        let mut changed_signature = signature.clone();
        changed_signature[index][0] ^= 1;
        assert!(!scheme.verify(&public_key, &message, changed_signature));
    }
    assert!(!scheme.verify(&public_key, &message, signature[..len - 1].iter().cloned()));

    // Check coefficient order and checksum alignment for the vector and both
    // checksum extremes. These are encoding checks, not additional signatures.
    for message in [
        message,
        Output::<S>::from([0; N]),
        Output::<S>::from([0xff; N]),
    ] {
        let bits_per_digit = S::W.ilog2() as usize;
        let bit_string: String = message.iter().map(|byte| format!("{byte:08b}")).collect();
        let expected: Vec<_> = bit_string
            .as_bytes()
            .chunks(bits_per_digit)
            .map(|bits| {
                bits.iter()
                    .fold(0u32, |value, bit| value * 2 + u32::from(bit - b'0'))
            })
            .collect();
        let mut digits = scheme.encode(&message);
        for &digit in &expected {
            assert_eq!(digits.next(), Some(digit));
        }
        let checksum: u32 = expected.iter().map(|digit| S::W - 1 - digit).sum();
        let mut decoded_checksum = 0;
        for _ in expected.len()..len {
            decoded_checksum = decoded_checksum * S::W + digits.next().unwrap();
        }
        assert_eq!(decoded_checksum, checksum);
        assert_eq!(digits.next(), None);
        assert_eq!(digits.next(), None);
    }
}
