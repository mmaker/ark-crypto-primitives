use super::{Lane, Sponge};
use ark_ff::PrimeField;
use zeroize::{Zeroize, ZeroizeOnDrop};


/// The basic configuration of a cryptographic sponge.
///
/// A cryptographic sponge operates over some domain `SpongeConfig::L` of lanes.
/// It has a capacity `SpongeConfig::capacity()` and a rate `SpongeConfig::rate()`,
/// and it permutes its internal state using `SpongeConfig::permute()`.
///
/// From each squeeze, the operation, the least `N` bytes can are guaranteed to be indistinguihsable from random.
pub trait SpongeConfig: Clone {
    type L: Lane;

    fn new() -> Self;
    fn capacity(&self) -> usize;
    fn rate(&self) -> usize;
    fn permute(&mut self, state: &mut [Self::L]);
}

/// A cryptographic sponge.
#[derive(Clone)]
pub struct DuplexSponge<C: SpongeConfig> {
    config: C,
    state: Vec<C::L>,
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<C: SpongeConfig> Zeroize for DuplexSponge<C> {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.absorb_pos = 0;
        self.squeeze_pos = 0;
    }
}

impl<C: SpongeConfig> Drop for DuplexSponge<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: SpongeConfig> ZeroizeOnDrop for DuplexSponge<C> {}

impl<F: PrimeField + Lane, C: SpongeConfig<L = F>> Sponge for DuplexSponge<C> {
    type L = F;

    fn new() -> Self {
        let config = C::new();
        let state = vec![Self::L::default(); config.capacity() + config.rate()];
        Self {
            config,
            state,
            absorb_pos: 0,
            squeeze_pos: 0,
        }
    }

    fn absorb_unchecked(&mut self, input: &[Self::L]) -> &mut Self {
        if input.len() == 0 {
            self.squeeze_pos = self.config.rate();
            self
        } else if self.absorb_pos == self.config.rate() {
            self.config.permute(&mut self.state);
            self.absorb_pos = 0;
            self
        } else {
            // XXX. maybe we should absorb in overwrite mode?
            self.state[self.absorb_pos] += input[0];
            self.absorb_pos += 1;
            self.absorb_unchecked(&input[1..])
        }
    }

    fn squeeze_unchecked(&mut self, output: &mut [Self::L]) -> &mut Self {
        if output.len() == 0 {
            return self;
        }

        if self.squeeze_pos == self.config.rate() {
            self.squeeze_pos = 0;
            self.absorb_pos = 0;
            self.config.permute(&mut self.state);
        }

        output[0] = self.state[self.squeeze_pos];
        self.squeeze_pos += 1;
        self.squeeze_unchecked(&mut output[1..])
    }

    fn from_capacity(input: &[Self::L]) -> Self {
        let mut sponge = Self::new();
        assert_eq!(input.len(), sponge.config.capacity());
        sponge.state[sponge.config.rate()..].copy_from_slice(input);
        sponge
    }


    fn export_unchecked(&self) -> Vec<Self::L> {
        // XXX. double-check this
        self.state.to_vec()
    }

    fn ratchet_unchecked(&mut self) -> &mut Self {
        self.config.permute(self.state.as_mut_slice());
        // set to zero the state up to rate
        self.state[..self.config.rate()]
            .iter_mut()
            .for_each(|x| *x = F::zero());
        self
    }
}

