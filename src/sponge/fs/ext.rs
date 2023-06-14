use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, RngCore};

use super::{Lane, TagError, Transcript};
use super::{Merlin, Sponge8};

pub trait FieldChallenges {
    fn get_field_challenge<F: PrimeField>(&mut self) -> Result<F, TagError>;
}

pub trait AbsorbSerializable {
    fn absorb_serializable<S: CanonicalSerialize>(&mut self, input: S) -> Result<(), TagError>;
}

impl<S: Sponge8> AbsorbSerializable for Merlin<S> {
    fn absorb_serializable<CS: CanonicalSerialize>(&mut self, input: CS) -> Result<(), TagError> {
        let mut buf = Vec::new();
        input
            .serialize_compressed(&mut buf)
            .map_err(|_| "Failed to serialize")?;
        self.absorb(S::L::pack_bytes(&buf).as_slice())
    }
}

impl<S: Sponge8, FS: Sponge8<L=u8>, R: RngCore + CryptoRng> AbsorbSerializable for Transcript<S, FS, R> {
    fn absorb_serializable<CS: CanonicalSerialize>(&mut self, input: CS) -> Result<(), TagError> {
        self.merlin.absorb_serializable(input)
    }
}

impl<S: Sponge8> FieldChallenges for Merlin<S> {
    fn get_field_challenge<F: PrimeField>(&mut self) -> Result<F, TagError> {
        let mut buf = [0u8; 16];
        self.challenge_bytes(&mut buf)?;
        F::from_random_bytes(&buf).ok_or("Invalid field element".into())
    }
}

impl<S: Sponge8, FS: Sponge8<L = u8>, R: RngCore + CryptoRng> FieldChallenges
    for Transcript<S, FS, R>
{
    fn get_field_challenge<F: PrimeField>(&mut self) -> Result<F, TagError> {
        self.merlin.get_field_challenge()
    }
}
