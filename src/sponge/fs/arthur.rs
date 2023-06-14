use ark_std::rand::{CryptoRng, RngCore};

use super::Sponge;

// Arthur is a cryptographically-secure random number generator that is
// seeded by a random-number generator and is bound to the protocol transcript.
pub(crate) struct Arthur<FS: Sponge<L = u8>, R: RngCore + CryptoRng> {
    pub(crate) sponge: FS,
    pub(crate) csrng: R,
}

impl<FS: Sponge<L = u8>, R: RngCore + CryptoRng> RngCore for Arthur<FS, R> {
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
        self.sponge.absorb_unsafe(dest);
        self.sponge.squeeze_unsafe(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.sponge.squeeze_unsafe(dest);
        Ok(())
    }
}

impl<FS: Sponge<L = u8>, R: RngCore + CryptoRng> CryptoRng for Arthur<FS, R> {}
