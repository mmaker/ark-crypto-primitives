use zeroize::Zeroize;

use super::lane::Lane;

/// A Sponge is a stateful object that can absorb and squeeze data.
pub trait Sponge: Zeroize {
    /// The basic unit that the sponge works with.
    /// Must support packing and unpacking to bytes.
    type L: Lane;

    /// Initializes a new sponge, setting up the state.
    fn new() -> Self;
    /// Absorbs new elements in the sponge.
    fn absorb_unsafe(&mut self, input: &[Self::L]) -> &mut Self;
    /// Squeezes out new elements.
    fn squeeze_unsafe(&mut self, output: &mut [Self::L]) -> &mut Self;
    /// Provides access to the internal state of the sponge.
    fn from_capacity(input: &[Self::L]) -> Self;
}


/// A [`crate::fs::SpongeExt`] additionally provides
/// squeezing uniformly-random bytes and ratcheting.
/// While squeezing bytes is natural for common cryptographic sponges,
/// this operation is non-trivial for algebraic hashes: there is no guarantee that the output
/// $\pmod p$ is uniformly distributed over $2^{\lfloor log p\rfloor}$.
pub trait SpongeExt: Sponge {

    const N: usize;
    /// Squeeze bytes from the sponge.
    ///
    /// While this function is trivial for byte-oriented hashes,
    /// for algebraic hashes, it requires proper implementation.
    /// Many implementations simply truncate the least-significant bits, but this approach
    /// results in a statistical deviation from uniform randomness. The number of useful bits, denoted as `n`,
    /// has a statistical distance from uniformly random given by:
    ///
    /// ```text
    /// (2 * (p % 2^n) / 2^n) * (1 - (p % 2^n) / p)
    /// ```
    ///
    /// To determine the value of 'n' suitable for cryptographic operations, use the following function:
    ///
    /// ```python
    /// def useful_bits(p):
    ///     for n in range(p.bit_length()-1, 0, -1):
    ///         alpha = p % 2^n
    ///         if n+1 + p.bit_length() - alpha.bit_length() - (2^n-alpha).bit_length() >= 128:
    ///             return n
    /// ```
    fn squeeze_bytes_unsafe(&mut self, output: &mut [u8]);

    fn absorb_bytes_unsafe(&mut self, input: &[u8]) {
        self.absorb_unsafe(&Self::L::pack_bytes(input));
    }

    /// Exports the compressed hash state, allowing for preprocessing.
    fn export_unsafe(&self) -> Vec<Self::L>;

    /// Ratcheting.
    ///
    /// This operation consists in:
    /// - permute the state.
    /// - set the rate to zero.
    /// This has the effect that the state is compressed
    /// and the state holds no information about the elements absorbed so far.
    fn ratchet_unsafe(&mut self) -> &mut Self;
}
