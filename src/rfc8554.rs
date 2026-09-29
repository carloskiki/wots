//! LM-OTS from RFC 8554, Section 4 and Appendix A.
//!
//! The `Scheme` methods operate on the message digest Q returned by
//! [`Sha256::hash_message`]. Signatures contain the chain elements y, and public
//! keys contain K; typecodes, the randomizer C, and LMS/HSS framing are external.

use digest::{Digest, Output, OutputSizeUser, consts::U32};

#[cfg(test)]
mod tests;

const D_PBLC: u16 = 0x8080;
const D_MESG: u16 = 0x8181;

/// LMOTS_SHA256_N32 with RFC parameter `W` bits per digit (1, 2, 4, or 8).
/// The radix used by [`crate::Scheme::W`] is `2^W`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256<'a, const LOG_W: u32 = 4> {
    /// LMS key identifier I.
    pub identifier: &'a [u8; 16],
    /// LMS leaf number q.
    pub address: u32,
}

impl<'a, const LOG_W: u32> From<&'a [u8; 16]> for Sha256<'a, LOG_W> {
    fn from(identifier: &'a [u8; 16]) -> Self {
        const { assert!(matches!(LOG_W, 1 | 2 | 4 | 8), "Invalid W parameter") };
        Self {
            identifier,
            address: 0,
        }
    }
}

impl<const LOG_W: u32> Sha256<'_, LOG_W> {
    // Number of chains p from RFC 8554, Table 1.
    const LEN: u16 = match LOG_W {
        1 => 265,
        2 => 133,
        4 => 67,
        8 => 34,
        _ => panic!("Invalid W parameter"),
    };

    fn digest_state(&self) -> sha2::Sha256 {
        let mut digest = sha2::Sha256::new();
        digest.update(self.identifier);
        digest.update(self.address.to_be_bytes());
        digest
    }

    /// Hashes one chain step, or expands a secret element when `hash_index = 255`.
    fn digest(&self, chain_index: u16, hash_index: u8, value: &Output<Self>) -> Output<Self> {
        let mut digest = self.digest_state();
        digest.update(chain_index.to_be_bytes());
        digest.update([hash_index]);
        digest.update(value);
        digest.finalize()
    }

    /// Computes Q for use with `Scheme::sign` and `Scheme::verify`.
    /// The caller supplies a uniformly random 32-byte C and carries it with the signature.
    pub fn hash_message(&self, randomizer: &Output<Self>, message: &[u8]) -> Output<Self> {
        let mut digest = self.digest_state();
        digest.update(D_MESG.to_be_bytes());
        digest.update(randomizer);
        digest.update(message);
        digest.finalize()
    }
}

impl<const LOG_W: u32> OutputSizeUser for Sha256<'_, LOG_W> {
    type OutputSize = U32;
}

impl<const LOG_W: u32> crate::Scheme for Sha256<'_, LOG_W> {
    const W: u32 = {
        assert!(matches!(LOG_W, 1 | 2 | 4 | 8), "Invalid W parameter");
        1 << LOG_W
    };

    fn chain(&self, chain_index: u32, hash_index: u32, element: &Output<Self>) -> Output<Self> {
        self.digest(
            chain_index.try_into().expect("chain index must fit in u16"),
            hash_index.try_into().expect("hash index must fit in u8"),
            element,
        )
    }

    fn encode(&self, message: &Output<Self>) -> impl Iterator<Item = u32> {
        crate::encode::<LOG_W>(message, usize::from(Self::LEN) - 256 / LOG_W as usize)
    }

    fn compress(&self, elements: impl IntoIterator<Item = Output<Self>>) -> Output<Self> {
        let mut digest = self.digest_state();
        digest.update(D_PBLC.to_be_bytes());
        for element in elements {
            digest.update(element);
        }
        digest.finalize()
    }

    fn generate(&self, key: &Output<Self>) -> impl Iterator<Item = Output<Self>> {
        (0..Self::LEN).map(move |chain_index| self.digest(chain_index, 0xff, key))
    }
}
