use super::{safe::IOPattern, InvalidTag, Safe, SpongeExt};

/// Merlin is wrapper around a sponge that provides a secure
/// Fiat-Shamir implementation for public-coin protocols.
#[derive(Clone)]
pub struct Merlin<S: SpongeExt>(Safe<S>);

impl<S: SpongeExt> Merlin<S> {
    pub fn new(io_pattern: &IOPattern) -> Self {
        let safe_sponge = Safe::new(io_pattern);
        Self(safe_sponge)
    }

    pub fn absorb(&mut self, input: &[S::L]) -> Result<&mut Self, InvalidTag> {
        self.0.absorb(input)?;
        Ok(self)
    }

    pub fn ratchet(&mut self) -> Result<&mut Self, InvalidTag> {
        self.0.ratchet()?;
        Ok(self)
    }

    pub fn ratchet_and_export(self) -> Result<Vec<S::L>, InvalidTag> {
        self.0.ratchet_and_export()
    }

    pub fn challenge_bytes(&mut self, mut dest: &mut [u8]) -> Result<(), InvalidTag> {
        self.0.squeeze(&mut dest)
    }

    // pub fn challenge(&mut self, mut dest: &mut [S::L]) -> Result<(), InvalidTag> {
    //     self.0.squeeze(&mut dest)
    // }
}


impl<S: SpongeExt> From<&IOPattern> for Merlin<S> {
    fn from(io_pattern: &IOPattern) -> Self {
        Merlin::new(&io_pattern)
    }
}