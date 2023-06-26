use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, RngCore};

use super::{InvalidTag, Lane, Transcript, TranscriptBuilder};
use super::{IOPattern, Merlin, SpongeExt};


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



impl<S: SpongeExt, FS: SpongeExt<L = u8>> RekeySerializable for TranscriptBuilder<S, FS> {
    fn rekey_serializable<CS: CanonicalSerialize>(self, input: CS) -> Self {
        let mut writer = Vec::new();
        input.serialize_compressed(&mut writer).unwrap();
        self.rekey(writer.as_slice())
    }
}


