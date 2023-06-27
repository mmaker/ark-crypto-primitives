use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, RngCore};

use super::super::{IOPattern, InvalidTag, Lane, Merlin, Sponge, Transcript, TranscriptBuilder};

pub trait AbsorbSerializable {
    fn absorb_serializable<S: CanonicalSerialize>(
        &mut self,
        input: S,
    ) -> Result<&mut Self, InvalidTag>;
}

pub trait RekeySerializable {
    fn rekey_serializable<S: CanonicalSerialize>(self, input: S) -> Self;
}

pub trait IOPatternExt {
    fn absorb_serializable<S: CanonicalSerialize + Default>(self, count: usize) -> Self;
}

impl IOPatternExt for IOPattern {
    fn absorb_serializable<S: CanonicalSerialize + Default>(self, count: usize) -> Self {
        self.absorb(S::default().compressed_size() * count)
    }
}

impl<S: Sponge> AbsorbSerializable for Merlin<S> {
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

impl<S: Sponge, R: RngCore + CryptoRng> AbsorbSerializable
    for Transcript<S, R>
{
    fn absorb_serializable<CS: CanonicalSerialize>(
        &mut self,
        input: CS,
    ) -> Result<&mut Self, InvalidTag> {
        self.merlin.absorb_serializable(input)?;
        Ok(self)
    }
}

impl<S: Sponge> RekeySerializable for TranscriptBuilder<S> {
    fn rekey_serializable<CS: CanonicalSerialize>(self, input: CS) -> Self {
        let mut writer = Vec::new();
        input.serialize_compressed(&mut writer).unwrap();
        self.rekey(writer.as_slice())
    }
}
