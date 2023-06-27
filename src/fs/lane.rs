use ::core::ops::AddAssign;
use zeroize::Zeroize;

/// A Lane is the basic unit a sponge function works on.
/// We need only two things from a lane: the ability to convert it to bytes and back.
pub trait Lane: AddAssign + Copy + Default + Sized + Zeroize {
    fn random_bytes_size() -> usize;
    fn fill_bytes(a: &[Self], dst: &mut [u8]);
    fn pack_bytes(bytes: &[u8]) -> Vec<Self>;
}

impl Lane for u8 {

    fn random_bytes_size() -> usize {
        1
    }

    fn fill_bytes(a: &[Self], dst: &mut [u8]) {
        dst.copy_from_slice(a)
    }

    fn pack_bytes(bytes: &[u8]) -> Vec<Self> {
        bytes.to_vec()
    }
}

macro_rules! impl_lane {
    ($t:ty, $n: expr) => {
        impl Lane for $t {

            fn random_bytes_size() -> usize {
                $n
            }

            fn fill_bytes(a: &[Self], dst: &mut [u8]) {
                use ark_ff::{BigInteger, PrimeField};

                let length = usize::min(Self::random_bytes_size(), dst.len());
                let bytes = a[0].into_bigint().to_bytes_le();
                dst[..length].copy_from_slice(&bytes[..length]);

                if dst.len() > length {
                    Self::fill_bytes(&a[1..], &mut dst[length..]);
                }
            }

            fn pack_bytes(bytes: &[u8]) -> Vec<Self> {
                use ark_ff::{PrimeField, Field};

                let n = (Self::MODULUS_BIT_SIZE as usize -1) / 8;
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
