use ::core::ops::AddAssign;
use zeroize::Zeroize;

/// A Lane is the basic unit a sponge function works on.
/// We need only two things from a lane: the ability to convert it to bytes and back.
pub trait Lane: AddAssign + Copy + Default + Sized + Zeroize {
    fn to_bytes(a: &[Self]) -> Vec<u8>;
    fn pack_bytes(bytes: &[u8]) -> Vec<Self>;
}

impl Lane for u8 {
    fn to_bytes(a: &[Self]) -> Vec<u8> {
        a.to_vec()
    }

    fn pack_bytes(bytes: &[u8]) -> Vec<Self> {
        bytes.to_vec()
    }
}

macro_rules! impl_lane {
    ($t:ty) => {
        impl Lane for $t {
            fn to_bytes(a: &[Self]) -> Vec<u8> {
                use ark_ff::{BigInteger, PrimeField};

                a.iter()
                    .map(|x| x.into_bigint().to_bytes_be())
                    .flatten()
                    .collect()
            }

            fn pack_bytes(bytes: &[u8]) -> Vec<Self> {
                use ark_ff::Field;

                // XXX. insecure
                let n = 2;
                let mut packed = Vec::new();
                for chunk in bytes.chunks(n) {
                    packed.push(Self::from_random_bytes(chunk).unwrap());
                }
                packed
            }
        }
    };
}

pub(crate) use impl_lane;
