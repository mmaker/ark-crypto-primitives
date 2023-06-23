use ark_ec::AffineRepr;
use ark_ff::Field;
use crate::fs::{InvalidTag, Lane, Merlin, SpongeExt};

pub trait AbsorbPoint {
    type F;
    fn absorb_points<A: AffineRepr<BaseField = Self::F>>(&mut self, input: &[A]) -> Result<&mut Self, InvalidTag>;
}


impl<S> AbsorbPoint for Merlin<S> where S: SpongeExt, S::L: Field {
    type F = S::L;
    fn absorb_points<A>(&mut self, input: &[A]) -> Result<&mut Self, InvalidTag>
        where A: AffineRepr<BaseField = S::L> {
        let mut buf = Vec::new();
        for point in input {
            point.serialize_uncompressed(&mut buf).unwrap();
        }
        self.absorb(S::L::pack_bytes(&buf).as_slice())
    }
}