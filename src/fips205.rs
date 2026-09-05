use digest::{
    Digest, Output, OutputSizeUser, XofFixedWrapper,
    array::ArraySize,
    block_api::{CoreProxy, UpdateCore},
    common::{Block, BlockSizeUser},
    consts::{U32, U64},
    typenum::{self, Unsigned},
};
use sha2::{Sha256, block_api::Sha256VarCore};
use std::ops::Shl;

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
    pub fn digest(&self, operation: Operation, value: &[u8; N]) -> [u8; N] {
        todo!()
    }
}

pub struct Sha2<const N: usize> {
    pub layer: u8,
    pub tree: u64,
    pub address: u32,
    digest_prefix: <Sha256 as CoreProxy>::Core,
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
        block.copy_from_slice(seed);
        digest_prefix.update_blocks(&[block]);

        Self {
            layer: 0,
            tree: 0,
            address: 0,
            digest_prefix,
        }
    }
}

impl<const N: usize> Sha2<N> {
    pub fn digest(&self, operation: Operation, value: &[u8; N]) -> [u8; N] {
        todo!()
    }
}

enum Operation {
    Compress,
    Chain {
        chain_index: u32,
        hash_index: u32,
    }
}
