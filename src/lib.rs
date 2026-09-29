use digest::{Output, OutputSizeUser};

#[cfg(feature = "rfc8391")]
pub mod rfc8391;

#[cfg(feature = "rfc8554")]
pub mod rfc8554;

#[cfg(feature = "fips205")]
pub mod fips205;

#[cfg(all(
    test,
    any(feature = "rfc8391", feature = "rfc8554", feature = "fips205")
))]
mod tests;

pub trait Scheme: OutputSizeUser + Sized {
    const W: u32;

    fn chain(&self, chain_index: u32, hash_index: u32, element: &Output<Self>) -> Output<Self>;

    fn encode(&self, message: &Output<Self>) -> impl Iterator<Item = u32>;

    fn compress(&self, elements: impl IntoIterator<Item = Output<Self>>) -> Output<Self>;

    fn generate(&self, key: &Output<Self>) -> impl Iterator<Item = Output<Self>>;

    fn sign(
        &self,
        key: &Output<Self>,
        message: &Output<Self>,
    ) -> impl Iterator<Item = Output<Self>> {
        kernel(
            self.generate(key)
                .zip(self.encode(message).map(|end| 0..end)),
            self,
        )
    }

    fn verify(
        &self,
        key: &Output<Self>,
        message: &Output<Self>,
        signature: impl IntoIterator<Item = Output<Self>>,
    ) -> bool {
        &self.compress(kernel(
            signature
                .into_iter()
                .zip(self.encode(message).map(|digit| digit..Self::W - 1)),
            self,
        )) == key
    }

    fn verifying_key(&self, signing_key: &Output<Self>) -> Output<Self> {
        self.compress(kernel(
            self.generate(signing_key)
                .zip(std::iter::repeat(0..Self::W - 1)),
            self,
        ))
    }
}

/// Encodes message digits followed by the checksum, most significant digit first.
#[cfg(any(feature = "rfc8391", feature = "rfc8554", feature = "fips205"))]
fn encode<const LOG_W: u32>(message: &[u8], checksum_digits: usize) -> impl Iterator<Item = u32> {
    const { assert!(matches!(LOG_W, 1 | 2 | 4 | 8), "Invalid digit width") };
    let mask = (1 << LOG_W) - 1;
    let message_digits = message.len() * (8 / LOG_W as usize);
    let len = message_digits + checksum_digits;
    let mut checksum = 0u32;
    let mut iterations = 0..len;

    std::iter::from_fn(move || {
        let iteration = iterations.next()?;
        Some(if iteration < message_digits {
            let bit = iteration * LOG_W as usize;
            let value = (u32::from(message[bit / 8]) >> (8 - LOG_W as usize - bit % 8)) & mask;
            checksum += mask - value;
            value
        } else {
            // Reading the significant checksum digits directly also accounts
            // for standards that left-align the checksum in a byte string.
            let shift = (len - 1 - iteration) * LOG_W as usize;
            (checksum >> shift) & mask
        })
    })
}

fn kernel<S: Scheme>(
    elements: impl IntoIterator<Item = (Output<S>, std::ops::Range<u32>)>,
    s: &S,
) -> impl Iterator<Item = Output<S>> {
    elements
        .into_iter()
        .enumerate()
        .map(|(i, (mut element, hash_indices))| {
            let i = i
                .try_into()
                .expect("elements should be shorter than `u32::MAX`");
            hash_indices.for_each(|j| {
                element = s.chain(i, j, &element);
            });
            element
        })
}
