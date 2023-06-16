use ark_bls12_377::Fq;
use ark_ff::{BigInteger, PrimeField};

use crate::fs::{Lane, Sponge, SpongeExt};
use ark_std::Zero;

impl Lane for Fq {
    fn to_bytes(a: &[Self]) -> Vec<u8> {
        a.iter()
            .map(|x| x.into_bigint().to_bytes_le())
            .flatten()
            .collect()
    }

    fn pack_bytes(bytes: &[u8]) -> Vec<Self> {
        bytes.iter().map(|&x| Fq::from(x)).collect()
    }
}

pub trait SpongeConfig {
    // the lane requirement here is not really needed
    type L: Lane;

    fn new() -> Self;
    fn capacity(&self) -> usize;
    fn rate(&self) -> usize;
    fn permute(&mut self, state: &mut [Self::L]);
}

pub struct DuplexSponge<C: SpongeConfig> {
    config: C,
    state: Vec<C::L>,
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<L: Lane, C: SpongeConfig<L=L>> Sponge for DuplexSponge<C> {
    type L = L;

    fn new() -> Self {
        let config = C::new();
        let state = vec![Self::L::default(); config.capacity() + config.rate()];
        Self {config, state, absorb_pos: 0, squeeze_pos: 0 }
    }

    fn absorb_unsafe(&mut self, input: &[Self::L]) -> &mut Self {
        if input.len() == 0 {
            self.squeeze_pos = self.config.rate();
            self
        } else if self.absorb_pos == self.config.rate() {
            self.config.permute(&mut self.state);
            self.absorb_pos = 0;
            self
        } else {
            // XXX. absorbing in overwrite mode
            self.state[self.absorb_pos] = input[0];
            self.absorb_pos += 1;
            self.absorb_unsafe(&input[1..])
        }
    }

    fn squeeze_unsafe(&mut self, output: &mut [Self::L]) -> &mut Self {
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
        self.squeeze_unsafe(&mut output[1..])
    }

    fn finish(self) {
        // zeroize::Zeroize::zeroize(&mut self.state);
        todo!()
    }

    fn from_capacity(input: &[Self::L]) -> Self {
        let mut sponge = Self::new();
        assert_eq!(input.len(), sponge.config.capacity());
        sponge.state[sponge.config.rate()..].copy_from_slice(input);
        sponge
    }

}

impl<F: Lane + PrimeField, C: SpongeConfig<L=F>> SpongeExt for DuplexSponge<C> {
    fn squeeze_bytes_unsafe(&mut self, output: &mut [u8]) {
        // obtained with the above function
        let n = 251 / 8;
        let len = (output.len() + n - 1) / n;
        let mut buf = vec![Self::L::zero(); len];
        self.squeeze_unsafe(buf.as_mut_slice());
        for i in 0..len - 1 {
            output[i * n..(i + 1) * n].copy_from_slice(&buf[i].into_bigint().to_bytes_le()[..n]);
        }
        let remainder = output.len() % n;
        output[n * (len - 1)..]
            .copy_from_slice(&buf[len - 1].into_bigint().to_bytes_le()[..remainder]);
    }

    fn export_unsafe(&self) -> Vec<Self::L> {
        // XXX. double-check this
        self.state.to_vec()
    }

    fn ratchet_unsafe(&mut self) -> &mut Self {
        self.config.permute(self.state.as_mut_slice());
        // set to zero the state up to rate
        self.state[..self.config.rate()]
            .iter_mut()
            .for_each(|x| *x = F::zero());
        self
    }
}
