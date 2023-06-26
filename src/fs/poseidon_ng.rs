use super::{sponge::SpongeConfig, Lane};
use crate::sponge::{
    poseidon::{PoseidonConfig, PoseidonDefaultConfigField, PoseidonSponge},
    CryptographicSponge,
};

use super::duplex::DuplexSponge;
use ark_std::UniformRand;

impl<F: Lane + PoseidonDefaultConfigField> SpongeConfig for PoseidonSponge<F> {
    type L = F;

    fn new() -> Self {
        let config = F::get_default_poseidon_parameters(10, false).unwrap();
        <Self as CryptographicSponge>::new(&config)
    }

    fn capacity(&self) -> usize {
        self.parameters.capacity
    }

    fn rate(&self) -> usize {
        self.parameters.rate
    }

    fn permute(&mut self, state: &mut [Self::L]) {
        self.state.clone_from_slice(&state);
        self.permute();
        state.clone_from_slice(&mut self.state)
    }
}

pub type PoseidonSpongeNG<F> = DuplexSponge<PoseidonSponge<F>>;


use super::lane::impl_lane;

impl_lane!(ark_ed_on_bls12_381::Fq);
impl_lane!(ark_ed_on_bls12_381::Fr);


impl PoseidonDefaultConfigField for ark_ed_on_bls12_381::Fq {
    fn get_default_poseidon_parameters(
        _rate: usize,
        _optimized_for_weights: bool,
    ) -> Option<PoseidonConfig<Self>> {
        use ark_std::test_rng;

        let mut test_rng = test_rng();

        let mut mds = vec![vec![]; 3];
        for i in 0..3 {
            for _ in 0..3 {
                mds[i].push(ark_ed_on_bls12_381::Fq::rand(&mut test_rng));
            }
        }

        let mut ark = vec![vec![]; 8 + 24];
        for i in 0..8 + 24 {
            for _ in 0..3 {
                ark[i].push(ark_ed_on_bls12_381::Fq::rand(&mut test_rng));
            }
        }

        let mut test_a = Vec::new();
        let mut test_b = Vec::new();
        for _ in 0..3 {
            test_a.push(ark_ed_on_bls12_381::Fq::rand(&mut test_rng));
            test_b.push(ark_ed_on_bls12_381::Fq::rand(&mut test_rng));
        }

        let params = PoseidonConfig::<ark_ed_on_bls12_381::Fq>::new(8, 24, 31, mds, ark, 2, 1);
        Some(params)
    }
}
