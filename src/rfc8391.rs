use std::ops::Shl;
use digest::{
    Digest, Output, OutputSizeUser, XofFixedWrapper,
    array::ArraySize,
    block_api::{CoreProxy, UpdateCore},
    common::{Block, BlockSizeUser},
    consts::{U32, U64},
    typenum::{self, Unsigned},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generic<'a, D: OutputSizeUser> {
    pub layer: u32,
    pub tree: u64,
    pub address: u32,
    pub seed: &'a Output<D>,
}

impl<'a, D: OutputSizeUser> From<&'a Output<D>> for Generic<'a, D> {
    fn from(seed: &'a Output<D>) -> Self {
        Self {
            layer: 0,
            tree: 0,
            address: 0,
            seed,
        }
    }
}

impl<D: Digest> Generic<'_, D> {
    fn prf(&self, kind: u8, high_index: u32, low_index: u32, bit_mask: u8) -> Output<D> {
        let mut digest = D::new();
        digest.update(&{
            let mut tmp = Output::<D>::default();
            tmp[D::OutputSize::USIZE - 1] = 3;
            tmp
        });
        digest.update(self.seed);
        digest.update(self.layer.to_be_bytes());
        digest.update(self.tree.to_be_bytes());
        digest.update([0; 3]);
        digest.update([kind]);
        digest.update(self.address.to_be_bytes());
        digest.update(high_index.to_be_bytes());
        digest.update(low_index.to_be_bytes());
        digest.update([0; 3]);
        digest.update([bit_mask]);
        digest.finalize()
    }
}

impl<D: OutputSizeUser> OutputSizeUser for Generic<'_, D> {
    type OutputSize = D::OutputSize;
}

pub struct CoreMemo<D: CoreProxy> {
    pub layer: u32,
    pub tree: u64,
    pub address: u32,
    prf: D::Core,
}

impl<D: Digest + CoreProxy<Core: Clone>> CoreMemo<D> {
    fn prf(&self, kind: u8, high_index: u32, low_index: u32, bit_mask: u8) -> Output<D> {
        let mut digest = D::compose(self.prf.clone(), Default::default());
        digest.update(self.layer.to_be_bytes());
        digest.update(self.tree.to_be_bytes());
        digest.update([0; 3]);
        digest.update([kind]);
        digest.update(self.address.to_be_bytes());
        digest.update(high_index.to_be_bytes());
        digest.update(low_index.to_be_bytes());
        digest.update([0; 3]);
        digest.update([bit_mask]);
        digest.finalize()
    }
}

impl<D: CoreProxy + OutputSizeUser> OutputSizeUser for CoreMemo<D> {
    type OutputSize = D::OutputSize;
}

impl<D: OutputSizeUser + CoreProxy> From<&Output<D>> for CoreMemo<D>
where
    D::OutputSize: Shl<typenum::B1, Output: ArraySize>,
    D::Core: UpdateCore + Default + BlockSizeUser<BlockSize = typenum::Double<D::OutputSize>>,
{
    fn from(seed: &Output<D>) -> Self {
        let mut prf = D::Core::default();
        let mut block = Block::<D::Core>::default();
        block[D::OutputSize::USIZE - 1] = 3;
        block[D::OutputSize::USIZE..].copy_from_slice(seed);
        prf.update_blocks(&[block]);
        Self {
            layer: 0,
            tree: 0,
            address: 0,
            prf,
        }
    }
}

macro_rules! impl_scheme {
    ([$($bounds:tt)*] $ty:ty) => {
impl<$($bounds)*> crate::Scheme for $ty {
    const W: u32 = 16;

    type MessageSize = D::OutputSize;

    fn chain(&self, chain_index: u32, hash_index: u32, element: &Output<Self>) -> Output<Self> {
        let key = self.prf(0, chain_index, hash_index, 0);
        let bm = self.prf(0, chain_index, hash_index, 1);
        let mut index = 0;

        let mut digest = D::new();
        digest.update(Output::<D>::default());
        digest.update(&key);
        digest.update(bm.map(|x| {
            let byte = x ^ element[index];
            index += 1;
            byte
        }));
        digest.finalize()
    }

    fn encode(
        &self,
        message: &digest::array::Array<u8, Self::MessageSize>,
    ) -> impl Iterator<Item = u32> {
        let mut iteration = 0;
        let mut checksum: u32 = 0;
        std::iter::from_fn(move || {
            if iteration / 2 < message.len() {
                let mut value = message[iteration / 2] as u32;
                if iteration % 2 == 0 {
                    value >>= 4;
                } else {
                    value &= 0x0f;
                }
                checksum += Self::W - 1 - value;
                iteration += 1;
                return Some(value);
            }
            if iteration < message.len() * 2 + 3 {
                let shift = (2 - (iteration - message.len() * 2)) * 4;
                let value = (checksum >> shift) & 0x0f;
                iteration += 1;
                return Some(value);
            }
            None
        })
    }

    fn compress(&self, elements: impl IntoIterator<Item = Output<Self>>) -> Output<Self> {
        let rand_hash = |left: &[u8], right: &[u8], height: u32, index: u32| {
            let key = self.prf(1, height, index, 0);
            let bm_0 = self.prf(1, height, index, 1);
            let bm_1 = self.prf(1, height, index, 2);

            let mut h = D::new();
            let mut index = 0;
            h.update(&{
                let mut prefix = Output::<D>::default();
                prefix[D::OutputSize::USIZE - 1] = 1;
                prefix
            });
            h.update(&key);
            h.update(bm_0.map(|x| {
                let byte = x ^ left[index];
                index += 1;
                byte
            }));
            index = 0;
            h.update(bm_1.map(|x| {
                let byte = x ^ right[index];
                index += 1;
                byte
            }));
            h.finalize()
        };

        let mut layers: [_; 8] = std::array::from_fn(|_| Output::<Self>::default());
        let mut len = 0u32;

        for mut node in elements {
            let mut height = 0u32;
            let mut index = len;

            while index % 2 == 1 {
                node = rand_hash(&layers[height as usize], &node, height, index / 2);
                index /= 2;
                height += 1;
            }

            layers[height as usize] = node;
            len += 1;
        }

        if len == 0 {
            panic!("elements iterator should not be empty");
        }

        let first_height = len.trailing_zeros() as usize;
        let mut root = std::mem::take(&mut layers[first_height]);
        let mut index = (len >> first_height) - 1;

        for (height, layer) in layers.into_iter().enumerate().skip(first_height + 1) {
            index /= 2;
            if len & (1 << height) != 0 {
                root = rand_hash(&layer, &root, height as u32, index / 2);
            }
        }

        root
    }

    fn generate(&self, key: &Output<Self>) -> impl Iterator<Item = Output<Self>> {
        (0..<Self::MessageSize as Unsigned>::USIZE * 2 + 3).map(move |i| {
            let mut digest = D::new();
            digest.update(&{
                let mut prefix = Output::<D>::default();
                prefix[D::OutputSize::USIZE - 1] = 3;
                prefix
            });
            digest.update(key);
            digest.update([0; 28]);
            digest.update((i as u32).to_be_bytes());
            digest.finalize()
        })
    }
}
};
}

impl_scheme!([D: Digest] Generic<'_, D>);
impl_scheme!([D: CoreProxy<Core: Clone> + Digest] CoreMemo<D>);

pub type Sha256 = CoreMemo<sha2::Sha256>;
pub type Sha512 = CoreMemo<sha2::Sha512>;
pub type Shake256<'a> = Generic<'a, XofFixedWrapper<shake::Shake128, U32>>;
pub type Shake512<'a> = Generic<'a, XofFixedWrapper<shake::Shake256, U64>>;
