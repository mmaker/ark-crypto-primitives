use crate::fs::{plugins::AbsorbSerializable, InvalidTag, Merlin, Sponge, Transcript};
use ark_ec::AffineRepr;
use ark_ff::Field;
use rand::{RngCore, CryptoRng};

pub trait AbsorbPoint: AbsorbSerializable {
    type F;

    fn absorb_points<A: AffineRepr<BaseField = Self::F>>(
        &mut self,
        input: &[A],
    ) -> Result<&mut Self, InvalidTag> {
        self.absorb_serializable(input)
    }
}

impl<S> AbsorbPoint for Merlin<S>
where
    S: Sponge,
    S::L: Field,
{
    type F = S::L;
    fn absorb_points<A>(&mut self, input: &[A]) -> Result<&mut Self, InvalidTag>
    where
        A: AffineRepr<BaseField = S::L>,
    {
        let input = input.iter().map(|point| {
            let (x, y) = point.xy().expect("Non-zero");
            [*x, *y]
        }).flatten().collect::<Vec<_>>();
        self.absorb(input.as_slice())?;
        Ok(self)
    }
}

impl<S, R> AbsorbPoint for Transcript<S, R>
where
S: Sponge,
R: RngCore + CryptoRng,
S::L: Field {
    type F =S::L;

    fn absorb_points<A: AffineRepr<BaseField = Self::F>>(
            &mut self,
            input: &[A],
        ) -> Result<&mut Self, InvalidTag> {
        self.merlin.absorb_points(input)?;
        Ok(self)
    }

}