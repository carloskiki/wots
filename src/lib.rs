use digest::{
    Output, OutputSizeUser,
    array::{Array, ArraySize},
};

#[cfg(feature = "rfc8391")]
pub mod rfc8391;

pub mod compressed;
pub mod leighton_micali;

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
        kernel(self.generate(key).zip(self.encode(message)), self)
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
                .zip(self.encode(message).map(|x| Self::W - 1 - x)),
            self,
        )) == key
    }
}

fn kernel<S: Scheme>(
    elements: impl IntoIterator<Item = (Output<S>, u32)>,
    s: &S,
) -> impl Iterator<Item = Output<S>> {
    elements
        .into_iter()
        .enumerate()
        .map(|(i, (mut element, repetitions))| {
            let i = i
                .try_into()
                .expect("elements should be shorter than `u32::MAX`");
            (0..repetitions).for_each(|j| {
                element = s.chain(i, j, &element);
            });
            element
        })
}

// SigningKey
// Signature (length depends on digitizer + step output size...)
