/**
 * SAFE FS interface for legacy hash functions.
 *
 * This code is greately inspired from libsignal's poksho:
 * <https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shosha256.rs>.
 * With the variation that here, squeeze satisfies streaming and
 *   squeeze(1); squeeze(1); squeeze(1) = squeeze(3);
 *
 */
use digest::Digest;

use sha2;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Sponge, SpongeExt};

#[derive(Clone)]
pub struct Sha2Bridge {
    hasher: sha2::Sha256,
    cv: [u8; Self::DIGEST_SIZE],
    /// Current operation, keeping state between absorb and squeeze
    /// across multiple calls when streaming.
    mode: Mode,
    /// Digest left over from a previous squeeze.
    leftovers: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
enum Mode {
    Absorb,
    Ratcheted(usize),
}

impl Sha2Bridge {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;
    const _MASK_SQUEEZE_LEN: usize =
        (Self::BLOCK_SIZE - Self::DIGEST_SIZE - core::mem::size_of::<usize>());

    const MASK_ABSORB: [u8; Self::BLOCK_SIZE] = [0u8; Self::BLOCK_SIZE];

    // The squeeze mask fills a block
    // when combined with the digest of the state and the current index.
    const MASK_SQUEEZE: [u8; Self::_MASK_SQUEEZE_LEN] = {
        let mut mask_squeeze = [0u8; Self::_MASK_SQUEEZE_LEN];
        mask_squeeze[0] = 1u8;
        mask_squeeze
    };
}
impl Zeroize for Sha2Bridge {
    fn zeroize(&mut self) {
        self.cv.zeroize();
        self.hasher.reset();
    }
}

impl Drop for Sha2Bridge {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Sha2Bridge {}

impl Sponge for Sha2Bridge {
    type L = u8;

    fn new() -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&Self::MASK_ABSORB[..]);
        Self {
            hasher,
            cv: [0u8; Self::DIGEST_SIZE],
            mode: Mode::Ratcheted(0),
            leftovers: Vec::new(),
        }
    }

    fn from_capacity(input: &[Self::L]) -> Self {
        let mut sha2bridge = Self::new();
        sha2bridge.hasher.update(&Self::MASK_SQUEEZE[..]);
        sha2bridge.hasher.update(&(0usize).to_be_bytes());
        sha2bridge.hasher.update(&input);
        sha2bridge
    }

    fn absorb_unsafe(&mut self, input: &[Self::L]) -> &mut Self {
        if let Mode::Ratcheted(count) = self.mode {
            self.mode = Mode::Absorb;
            // append to the state the squeeze mask
            // with the length of the data read so far
            // and the current digest
            self.hasher.update(&Self::MASK_SQUEEZE[..]);
            self.hasher.update(&count.to_be_bytes());
            self.hasher.update(&self.cv);
            // add the absorb mask
            self.hasher.update(&Self::MASK_ABSORB[..]);
        }
        // add the input to the hasher
        self.hasher.update(input);
        self
    }

    fn squeeze_unsafe(&mut self, output: &mut [Self::L]) -> &mut Self {
        // Nothing to squeeze
        if output.is_empty() {
            self
        }
        // If we still have some digest not yet squeezed from previous invocations,
        // write it to the output
        else if !self.leftovers.is_empty() {
            let len = usize::min(output.len(), self.leftovers.len());
            self.leftovers[..len].copy_from_slice(&output[..len]);
            self.leftovers.drain(..len);
            // go back to the beginning
            self.squeeze_unsafe(&mut output[len..])
        }
        // If absorbing, change mode and set the state properly
        else if let Mode::Absorb = self.mode {
            self.mode = Mode::Ratcheted(0);
            self.cv.copy_from_slice(&self.hasher.finalize_reset());
            // go back to the beginning
            self.squeeze_unsafe(output)
        // Squeeze another digest
        } else if let Mode::Ratcheted(i) = self.mode {
            let len = usize::min(output.len(), Self::DIGEST_SIZE);
            // self.hasher is a fresly initialized state.
            // Add the squeeze mask, current digest, and index
            self.hasher.clone().update(&Self::MASK_SQUEEZE[..]);
            self.hasher.update(&self.cv[..]);
            self.hasher.update(&i.to_be_bytes());
            let digest = self.hasher.finalize_reset();
            // Copy the digest into the output, and store the rest for later
            output[..len].copy_from_slice(&digest[..len]);
            self.leftovers.extend_from_slice(&output[len..]);
            // update the state
            self.mode = Mode::Ratcheted(i + 1);
            self.squeeze_unsafe(&mut output[len..])
        } else {
            unreachable!()
        }
    }
}

impl SpongeExt for Sha2Bridge {
    fn squeeze_bytes_unsafe(&mut self, output: &mut [u8]) {
        self.squeeze_unsafe(output);
    }

    fn ratchet_unsafe(&mut self) -> &mut Self {
        if self.mode == Mode::Absorb {
            let digest = self.hasher.finalize_reset();
            self.cv.copy_from_slice(&digest)
        }
        self
    }

    fn export_unsafe(&self) -> Vec<u8> {
        self.cv.to_vec()
    }
}
