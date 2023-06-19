use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, RngCore};

use super::{InvalidTag, Lane, Transcript, TranscriptBuilder};
use super::{Merlin, SpongeExt};

pub trait FieldChallenges {
    fn get_field_challenge<F: PrimeField>(&mut self, byte_count: usize) -> Result<F, InvalidTag>;
}

pub trait AbsorbSerializable {
    fn absorb_serializable<S: CanonicalSerialize>(
        &mut self,
        input: S,
    ) -> Result<&mut Self, InvalidTag>;
}

pub trait RekeySerializable {
    fn rekey_serializable<S: CanonicalSerialize>(self, input: S) -> Self;
}

impl<S: SpongeExt> AbsorbSerializable for Merlin<S> {
    fn absorb_serializable<CS: CanonicalSerialize>(
        &mut self,
        input: CS,
    ) -> Result<&mut Self, InvalidTag> {
        let mut buf = Vec::new();
        input
            .serialize_compressed(&mut buf)
            .map_err(|_| "Failed to serialize")?;
        self.absorb(S::L::pack_bytes(&buf).as_slice())
    }
}

impl<S: SpongeExt, FS: SpongeExt<L = u8>, R: RngCore + CryptoRng> AbsorbSerializable
    for Transcript<S, R, FS>
{
    fn absorb_serializable<CS: CanonicalSerialize>(
        &mut self,
        input: CS,
    ) -> Result<&mut Self, InvalidTag> {
        self.merlin.absorb_serializable(input)?;
        Ok(self)
    }
}

impl<S: SpongeExt> FieldChallenges for Merlin<S> {
    /// Get a field element challenge from the protocol transcript.
    ///
    /// The number of random bytes used to generate the challenge is explicit:
    /// commonly implementations choose 16 for 127-bit knowledge soundness,
    /// but larger challenges are supported. To get a challenge uniformly distributed
    /// over the entire field `F`, squeeze F::num_bits()/8 + 100.
    fn get_field_challenge<F: PrimeField>(&mut self, byte_count: usize) -> Result<F, InvalidTag> {
        let mut chal = vec![0u8; byte_count];
        self.challenge_bytes(&mut chal)?;
        Ok(F::from_le_bytes_mod_order(&chal))
    }
}

impl<S: SpongeExt, FS: SpongeExt, R: RngCore + CryptoRng> FieldChallenges
    for Transcript<S, R, FS>
{
    fn get_field_challenge<F: PrimeField>(&mut self, byte_count: usize) -> Result<F, InvalidTag> {
        self.merlin.get_field_challenge(byte_count)
    }
}

impl<S: SpongeExt, FS: SpongeExt<L = u8>> RekeySerializable for TranscriptBuilder<S, FS> {
    fn rekey_serializable<CS: CanonicalSerialize>(self, input: CS) -> Self {
        let mut writer = Vec::new();
        input.serialize_compressed(&mut writer).unwrap();
        self.rekey(writer.as_slice())
    }
}
