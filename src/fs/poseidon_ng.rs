use crate::sponge::{CryptographicSponge, poseidon::{PoseidonDefaultConfigField, PoseidonSponge}};
use super::{sponge::{SpongeConfig, DuplexSponge}, Lane};


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