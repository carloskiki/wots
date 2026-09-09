use digest::{
    Digest, ExtendableOutput, Output, OutputSizeUser,
    array::{Array, ArraySize},
    block_api::{CoreProxy, UpdateCore},
    common::Block,
    typenum::{Const, ToUInt, U},
};
use sha2::{Sha256, Sha512};

#[cfg(test)]
mod tests;

const WOTS_HASH: u8 = 0;
const WOTS_PK: u8 = 1;
const WOTS_PRF: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shake<'a, const N: usize> {
    pub layer: u32,
    pub tree: u64,
    pub address: u32,
    pub seed: &'a [u8; N],
}

impl<'a, const N: usize> From<&'a [u8; N]> for Shake<'a, N> {
    fn from(seed: &'a [u8; N]) -> Self {
        const {
            if !matches!(N, 16 | 24 | 32) {
                panic!("Invalid N parameter");
            }
        }

        Self {
            layer: 0,
            tree: 0,
            address: 0,
            seed,
        }
    }
}

impl<const N: usize> Shake<'_, N> {
    fn digest_state(&self, kind: u8, chain_index: u32, hash_index: u32) -> shake::Shake256 {
        use digest::Update;

        let mut digest = shake::Shake256::default();
        digest.update(self.seed);
        digest.update(&self.layer.to_be_bytes());
        // The tree address occupies 12 bytes, with its top four bytes zero.
        digest.update(&[0; 4]);
        digest.update(&self.tree.to_be_bytes());
        digest.update(&[0; 3]);
        digest.update(&[kind]);
        digest.update(&self.address.to_be_bytes());
        digest.update(&chain_index.to_be_bytes());
        digest.update(&hash_index.to_be_bytes());
        digest
    }

    /// Computes F with address type `kind = 0`, or PRF with `kind = 5` and `hash_index = 0`.
    pub fn digest(&self, kind: u8, chain_index: u32, hash_index: u32, value: &[u8; N]) -> [u8; N] {
        use digest::Update;

        let mut digest = self.digest_state(kind, chain_index, hash_index);
        digest.update(value);
        let mut output = [0; N];
        digest.finalize_xof_into(&mut output);
        output
    }

    fn compress_elements(&self, elements: impl IntoIterator<Item = impl AsRef<[u8]>>) -> [u8; N] {
        let mut digest = self.digest_state(WOTS_PK, 0, 0);
        for element in elements {
            digest::Update::update(&mut digest, element.as_ref());
        }
        let mut output = [0; N];
        digest.finalize_xof_into(&mut output);
        output
    }
}

pub struct Sha2<const N: usize> {
    pub layer: u8,
    pub tree: u64,
    pub address: u32,
    digest_prefix: <Sha256 as CoreProxy>::Core,
    seed: [u8; N],
}

impl<'a, const N: usize> From<&'a [u8; N]> for Sha2<N> {
    fn from(seed: &'a [u8; N]) -> Self {
        const {
            if !matches!(N, 16 | 24 | 32) {
                panic!("Invalid N parameter");
            }
        }

        let mut digest_prefix: <Sha256 as CoreProxy>::Core = Default::default();
        let mut block = Block::<Sha256>::default();
        block[..N].copy_from_slice(seed);
        digest_prefix.update_blocks(&[block]);

        Self {
            layer: 0,
            tree: 0,
            address: 0,
            digest_prefix,
            seed: *seed,
        }
    }
}

impl<const N: usize> Sha2<N> {
    fn update_address(
        &self,
        digest: &mut impl digest::Update,
        kind: u8,
        chain_index: u32,
        hash_index: u32,
    ) {
        digest.update(&[self.layer]);
        digest.update(&self.tree.to_be_bytes());
        digest.update(&[kind]);
        digest.update(&self.address.to_be_bytes());
        digest.update(&chain_index.to_be_bytes());
        digest.update(&hash_index.to_be_bytes());
    }

    fn digest_state(&self, kind: u8, chain_index: u32, hash_index: u32) -> Sha256 {
        let mut digest = Sha256::compose(self.digest_prefix.clone(), Default::default());
        self.update_address(&mut digest, kind, chain_index, hash_index);
        digest
    }

    /// Computes F with address type `kind = 0`, or PRF with `kind = 5` and `hash_index = 0`.
    pub fn digest(&self, kind: u8, chain_index: u32, hash_index: u32, value: &[u8; N]) -> [u8; N] {
        let mut digest = self.digest_state(kind, chain_index, hash_index);
        digest.update(value);
        digest.finalize()[..N].try_into().unwrap()
    }

    fn compress_elements(&self, elements: impl IntoIterator<Item = impl AsRef<[u8]>>) -> [u8; N] {
        if N == 16 {
            let mut digest = self.digest_state(WOTS_PK, 0, 0);
            for element in elements {
                digest.update(element.as_ref());
            }
            digest.finalize()[..N].try_into().unwrap()
        } else {
            // T_len uses SHA-512 for n = 24 and n = 32.
            let mut digest = Sha512::new();
            digest.update(self.seed);
            digest.update(&[0; 128][N..]);
            self.update_address(&mut digest, WOTS_PK, 0, 0);
            for element in elements {
                digest.update(element.as_ref());
            }
            digest.finalize()[..N].try_into().unwrap()
        }
    }
}

macro_rules! impl_scheme {
    ($ty:ty) => {
        impl<const N: usize> OutputSizeUser for $ty
        where
            Const<N>: ToUInt,
            U<N>: ArraySize,
        {
            type OutputSize = U<N>;
        }

        impl<const N: usize> crate::Scheme for $ty
        where
            Const<N>: ToUInt,
            U<N>: ArraySize<ArrayType<u8> = [u8; N]>,
        {
            const W: u32 = 16;
            type MessageSize = U<N>;

            fn chain(
                &self,
                chain_index: u32,
                hash_index: u32,
                element: &Output<Self>,
            ) -> Output<Self> {
                self.digest(WOTS_HASH, chain_index, hash_index, element.as_ref())
                    .into()
            }

            fn encode(&self, message: &Array<u8, Self::MessageSize>) -> impl Iterator<Item = u32> {
                let mut iteration = 0;
                let mut checksum = 0u32;
                std::iter::from_fn(move || {
                    if iteration < N * 2 {
                        let shift = if iteration % 2 == 0 { 4 } else { 0 };
                        let value = (u32::from(message[iteration / 2]) >> shift) & 0x0f;
                        checksum += Self::W - 1 - value;
                        iteration += 1;
                        Some(value)
                    } else if iteration < N * 2 + 3 {
                        let shift = (N * 2 + 2 - iteration) * 4;
                        iteration += 1;
                        Some((checksum >> shift) & 0x0f)
                    } else {
                        None
                    }
                })
            }

            fn compress(&self, elements: impl IntoIterator<Item = Output<Self>>) -> Output<Self> {
                self.compress_elements(elements).into()
            }

            fn generate(&self, key: &Output<Self>) -> impl Iterator<Item = Output<Self>> {
                (0..(N * 2 + 3) as u32).map(move |chain_index| {
                    self.digest(WOTS_PRF, chain_index, 0, key.as_ref()).into()
                })
            }
        }
    };
}

impl_scheme!(Shake<'_, N>);
impl_scheme!(Sha2<N>);
