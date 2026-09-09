use digest::{
    Output, OutputSizeUser,
    array::{Array, ArraySize},
};

#[cfg(feature = "rfc8391")]
pub mod rfc8391;

#[cfg(feature = "rfc8554")]
pub mod rfc8554;

#[cfg(feature = "fips205")]
pub mod fips205;

pub mod compressed;

#[cfg(all(
    test,
    any(feature = "rfc8391", feature = "rfc8554", feature = "fips205")
))]
mod tests;

pub trait Scheme: OutputSizeUser + Sized {
    const W: u32;

    type MessageSize: ArraySize;

    fn chain(&self, chain_index: u32, hash_index: u32, element: &Output<Self>) -> Output<Self>;

    fn encode(&self, message: &Array<u8, Self::MessageSize>) -> impl Iterator<Item = u32>;

    fn compress(&self, elements: impl IntoIterator<Item = Output<Self>>) -> Output<Self>;

    fn generate(&self, key: &Output<Self>) -> impl Iterator<Item = Output<Self>>;

    fn sign(
        &self,
        key: &Output<Self>,
        message: &Array<u8, Self::MessageSize>,
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
        message: &Array<u8, Self::MessageSize>,
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
