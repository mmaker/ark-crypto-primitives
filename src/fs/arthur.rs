use rand::{CryptoRng, RngCore};

use super::{DefaultHash, DefaultRng, InvalidTag, Merlin, SpongeExt};

// Arthur is a cryptographically-secure random number generator that is
// seeded by a random-number generator and is bound to the protocol transcript.
pub(crate) struct Arthur<R: RngCore + CryptoRng, FS: SpongeExt> {
    pub(crate) sponge: FS,
    pub(crate) csrng: R,
}

impl<FS: SpongeExt, R: RngCore + CryptoRng> RngCore for Arthur<R, FS> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(buf.as_mut());
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(buf.as_mut());
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.csrng.fill_bytes(dest);
        self.sponge.absorb_bytes_unsafe(dest);
        self.sponge.squeeze_bytes_unsafe(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.sponge.squeeze_bytes_unsafe(dest);
        Ok(())
    }
}

/// Builder for the prover state.
pub struct TranscriptBuilder<S: SpongeExt, FS = DefaultHash>
where
    S: SpongeExt,
    FS: SpongeExt,
{
    merlin: Merlin<S>,
    fsponge: FS,
}

impl<S: SpongeExt, FS: SpongeExt> TranscriptBuilder<S, FS> {
    pub(crate) fn new(tag: &str) -> Self {
        let merlin = Merlin::new(tag).expect("Invalid tag");

        let mut fsponge = FS::new();
        fsponge.absorb_bytes_unsafe(tag.as_bytes());

        Self { fsponge, merlin }
    }

    // rekey the private sponge with some additional secrets (i.e. with the witness)
    // and ratchet
    pub fn rekey(mut self, data: &[u8]) -> Self {
        self.fsponge.absorb_bytes_unsafe(data);
        self.fsponge.ratchet_unsafe();
        self
    }

    // Finalize the state integrating a cryptographically-secure
    // random number generator that will be used to seed the state before future squeezes.
    pub fn finalize_with_rng<R: RngCore + CryptoRng>(self, csrng: R) -> Transcript<S, R, FS> {
        let arthur = Arthur {
            sponge: self.fsponge,
            csrng,
        };

        Transcript {
            merlin: self.merlin,
            arthur,
        }
    }
}

/// The state of an interactive proof system.
/// Holds the state of the verifier, and provides the random coins for the prover.
pub struct Transcript<S: SpongeExt, R = DefaultRng, FS = DefaultHash>
where
    FS: SpongeExt,
    R: RngCore + CryptoRng,
{
    /// The randomness state of the prover.
    pub(crate) arthur: Arthur<R, FS>,
    pub(crate) merlin: Merlin<S>,
}

impl<S: SpongeExt, FS: SpongeExt, R: RngCore + CryptoRng> Transcript<S, R, FS> {
    #[inline]
    pub fn absorb(&mut self, input: &[S::L]) -> Result<&mut Self, InvalidTag> {
        self.merlin.absorb(input)?;
        Ok(self)
    }

    /// Get a challenge of `count` bytes.
    pub fn challenge_bytes(&mut self, dest: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.challenge_bytes(dest)?;
        self.arthur.sponge.absorb_bytes_unsafe(dest);
        Ok(())
    }

    #[inline]
    pub fn ratchet(&mut self) -> Result<&mut Self, InvalidTag> {
        self.merlin.ratchet()?;
        Ok(self)
    }

    #[inline]
    pub fn rng<'a>(&'a mut self) -> &'a mut (impl CryptoRng + RngCore) {
        &mut self.arthur
    }

    // XXX. implement drop for more helpful error messages.
}

impl<FS: SpongeExt, R: RngCore + CryptoRng> CryptoRng for Arthur<R, FS> {}

