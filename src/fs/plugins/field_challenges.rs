use crate::fs::{InvalidTag, Merlin, SpongeExt, Transcript};
use ark_ff::PrimeField;
use rand::{CryptoRng, RngCore};

pub trait FieldChallenges {
    fn get_field_challenge<F: PrimeField>(&mut self, byte_count: usize) -> Result<F, InvalidTag>;
}

impl<S: SpongeExt, FS: SpongeExt, R: RngCore + CryptoRng> FieldChallenges for Transcript<S, R, FS> {
    fn get_field_challenge<F: PrimeField>(&mut self, byte_count: usize) -> Result<F, InvalidTag> {
        self.merlin.get_field_challenge(byte_count)
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
