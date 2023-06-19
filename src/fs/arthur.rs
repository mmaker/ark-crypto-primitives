use ark_std::rand::{CryptoRng, RngCore};

use super::SpongeExt;

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

impl<FS: SpongeExt, R: RngCore + CryptoRng> CryptoRng for Arthur<R, FS> {}
