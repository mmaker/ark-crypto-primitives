use crate::sponge::poseidon::PoseidonSponge;
use crate::sponge::CryptographicSponge;
use ark_bls12_377::Fq;
use ark_ff::{BigInteger, PrimeField};

use crate::sponge::{poseidon::PoseidonConfig};
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

fn poseidon_test_config<F: PrimeField>() -> PoseidonConfig<F> {
    use crate::sponge::poseidon::find_poseidon_ark_and_mds;
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 5;
    let rate = 2;

    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds,
        partial_rounds,
        0,
    );

    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        rate,
        1,
    )
}

/// XXX. check that we are correcly giving out rate and capacity
impl Sponge for PoseidonSponge<Fq> {
    type L = Fq;
    // state length should be 3?
    type State = [Fq; 3];

    fn new() -> Self {
        let params = poseidon_test_config::<Fq>();
        <Self as CryptographicSponge>::new(&params)
    }
    fn absorb_unsafe(&mut self, input: &[Self::L]) -> &mut Self {
        self.absorb(&input);
        self
    }

    fn squeeze_unsafe(&mut self, output: &mut [Self::L]) -> &mut Self {
        let num_elements = output.len();
        let buf = <Self as CryptographicSponge>::squeeze_field_elements(self, num_elements);
        output.copy_from_slice(&buf);
        self
    }

    fn finish(self) {
        // TODO: zeroize
    }

    fn state(&self) -> Self::State {
        self.state.clone().try_into().unwrap()
    }
}

impl SpongeExt for PoseidonSponge<Fq> {
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
        self.state()[.. 1].to_vec()
    }

    fn ratchet_unsafe(&mut self) -> &mut Self {
        let digest = self.squeeze_field_elements(self.parameters.capacity);
        self.state[self.parameters.rate..].copy_from_slice(&digest);
        self.state[..self.parameters.rate]
            .iter_mut()
            .for_each(|x| *x = Fq::zero());
        self
    }
}
