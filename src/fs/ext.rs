use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, RngCore};

use super::{Lane, InvalidTag, Transcript};
use super::{Merlin, SpongeExt};

pub trait FieldChallenges {
    fn get_field_challenge<F: PrimeField>(&mut self) -> Result<F, InvalidTag>;
}

pub trait AbsorbSerializable {
    fn absorb_serializable<S: CanonicalSerialize>(&mut self, input: S) -> Result<&mut Self, InvalidTag>;
}

impl<S: SpongeExt> AbsorbSerializable for Merlin<S> {
    fn absorb_serializable<CS: CanonicalSerialize>(&mut self, input: CS) -> Result<&mut Self, InvalidTag> {
        let mut buf = Vec::new();
        input
            .serialize_compressed(&mut buf)
            .map_err(|_| "Failed to serialize")?;
        self.absorb(S::L::pack_bytes(&buf).as_slice())
    }
}

impl<S: SpongeExt, FS: SpongeExt<L = u8>, R: RngCore + CryptoRng> AbsorbSerializable
    for Transcript<S, FS, R>
{
    fn absorb_serializable<CS: CanonicalSerialize>(&mut self, input: CS) -> Result<&mut Self, InvalidTag> {
        self.merlin.absorb_serializable(input)?;
        Ok(self)
    }
}

impl<S: SpongeExt> FieldChallenges for Merlin<S> {
    fn get_field_challenge<F: PrimeField>(&mut self) -> Result<F, InvalidTag> {
        let mut buf = [0u8; 16];
        self.challenge_bytes(&mut buf)?;
        F::from_random_bytes(&buf).ok_or("Invalid field element".into())
    }
}

impl<S: SpongeExt, FS: SpongeExt<L = u8>, R: RngCore + CryptoRng> FieldChallenges
    for Transcript<S, FS, R>
{
    fn get_field_challenge<F: PrimeField>(&mut self) -> Result<F, InvalidTag> {
        self.merlin.get_field_challenge()
    }
}
