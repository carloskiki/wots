use digest::{Digest, Output, OutputSizeUser, typenum::Unsigned};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scheme<'a, D: OutputSizeUser> {
    pub layer: u32,
    pub tree: u64,
    pub address: u32,
    pub seed: &'a Output<D>,
}

impl<D: OutputSizeUser> OutputSizeUser for Scheme<'_, D> {
    type OutputSize = D::OutputSize;
}

impl<D: Digest> crate::Scheme for Scheme<'_, D> {
    const W: u32 = 16;

    type MessageSize = D::OutputSize;

    fn chain(&self, chain_index: u32, hash_index: u32, element: &Output<Self>) -> Output<Self> {
        macro_rules! bytes {
            ($bit_mask:expr) => {
                &[
                    self.seed,
                    &self.layer.to_be_bytes(),
                    &self.tree.to_be_bytes(),
                    &[0, 0, 0, 0],
                    &self.address.to_be_bytes(),
                    &chain_index.to_be_bytes(),
                    &hash_index.to_be_bytes(),
                    &[$bit_mask, 0, 0, 0],
                ]
            };
        }

        let key = prf::<D>(bytes!(0));
        let bm = prf::<D>(bytes!(1));
        let mut index = 0;
        f::<D>(&[
            &key,
            &bm.map(|x| {
                let byte = x ^ element[index];
                index += 1;
                byte
            }),
        ])
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
                    value &= 0x0f;
                } else {
                    value >>= 4;
                }
                checksum += Self::W - 1 - value;
                iteration += 1;
                return Some(value);
            }
            if iteration < message.len() * 2 + 3 {
                let shift = 3 - (iteration - message.len() * 2) * 4;
                let value = (checksum >> shift) & 0x0f;
                iteration += 1;
                return Some(value);
            }
            None
        })
    }

    fn compress(&self, elements: impl IntoIterator<Item = Output<Self>>) -> Output<Self> {
        let rand_hash = |left: &[u8], right: &[u8], height: u32, index: u32| {
            macro_rules! bytes {
                ($bit_mask:expr) => {
                    &[
                        self.seed,
                        &self.layer.to_be_bytes(),
                        &self.tree.to_be_bytes(),
                        &[1, 0, 0, 0],
                        &self.address.to_be_bytes(),
                        &height.to_be_bytes(),
                        &index.to_be_bytes(),
                        &[$bit_mask, 0, 0, 0],
                    ]
                };
            }
            let key = prf::<D>(bytes!(0));
            let bm_0 = prf::<D>(bytes!(1));
            let bm_1 = prf::<D>(bytes!(2));

            let mut h = D::new();
            let mut index = 0;
            h.update([1]);
            h.update([0; 31]);
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

        let layers: [_; 7] = std::array::from_fn(|_| Output::<Self>::default());
        todo!()
    }

    fn generate(&self, key: &Output<Self>) -> impl Iterator<Item = Output<Self>> {
        (0..<Self::MessageSize as Unsigned>::USIZE * 2 + 3).map(move |i| {
            let mut count = [0u8; 32];
            count[0] = i as u8;
            prf::<D>(&[key, &count])
        })
    }
}

pub fn f<D: Digest>(bytes: &[&[u8]]) -> Output<D> {
    let mut hasher = D::new();
    let prefix = Output::<D>::default();

    hasher.update(&prefix);
    bytes.iter().for_each(|b| hasher.update(b));
    hasher.finalize()
}

pub fn prf<D: Digest>(bytes: &[&[u8]]) -> Output<D> {
    let mut hasher = D::new();
    let mut prefix = Output::<D>::default();
    prefix[0] = 3;

    hasher.update(&prefix);
    bytes.iter().for_each(|b| hasher.update(b));
    hasher.finalize()
}
