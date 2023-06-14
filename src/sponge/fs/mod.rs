//!
//! **This is work in progress, not suitable for production.**
//!
//! This library is a secure construction for zero-knowledge proofs based on SAFE.
//! It enables secure provision of randomness for the prover and secure generation
//! of random coins for the verifier.
//! This allows the implementation of non-interactive protocols in a readable manner.
//!
//! ```rust
//! use ark_crypto_primitives::sponge::fs::legacy::Sha2Bridge;
//! use ark_crypto_primitives::sponge::fs::ext::{FieldChallenges, AbsorbSerializable};
//! use ark_crypto_primitives::sponge::fs::{Merlin, TagError};
//! use rand::rngs::OsRng;
//! use rand::RngCore;
//! use ark_bls12_377::{Fr, Fq};
//! use ark_bls12_377::G1Projective as G1;
//! use ark_ec::{AffineRepr, CurveGroup, Group};
//! use ark_std::UniformRand;
//! use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
//!
//! fn schnorr_proof(sk: Fr, pk: G1) -> Result<(Fr, Fr), TagError> {
//!     // create a new verifier transcript for the protocol identified by the tag.
//!     let merlin = Merlin::<PoseidonSponge<Fq>>::new("example.com A48A48,A2S16")?;
//!     // Build on the top a prover state, using another sponge, rekeying it with some witness data,
//!     // and finalizing it with a cryptographically-secure random number generator.
//!     let mut transcript = merlin.into_transcript::<Sha2Bridge>()
//!         .rekey(b"witness data")
//!         .finalize_with_rng(OsRng);
//!
//!     // Absorb the statement.
//!     transcript.absorb_serializable(pk)?;
//!     transcript.absorb_serializable(G1::generator())?;
//!     transcript.ratchet();
//!     // Actual proof.
//!     let k = Fr::rand(&mut transcript.rng());
//!     let K = G1::generator().into_affine() * k;
//!     // Absorptions can be chained together for streaming-frendliness.
//!     transcript.absorb(&[K.x, K.y])?;
//!     // Get a challenge from the verifier.
//!     let challenge = transcript.get_field_challenge::<Fr>()?;
//!     // At any point, the prover can get a csrng from the transcript.
//!     let response = k + challenge * sk;
//!     let proof = (challenge, response);
//!     transcript.finish()?;
//!     Ok(proof)
//! }
//!
//! let sk = Fr::rand(&mut OsRng);
//! let pk = G1::generator() * sk;
//! let proof = schnorr_proof(sk, pk).expect("Valid proof");
//! ```
//!
//! # Features
//!
//! This library is inspired by [Merlin] but is not a drop-in replacement.
//! Like Merlin, it supports multi-round protocols and domain separation.
//! Additionally, it addresses some core design limitations of [Merlin]:
//! - Supports algebraic hashes.
//!
//! To build a secure Fiat-Shamir transform, a permutation function is required.
//! You can choose from SHA3, Poseidon, Anemoi, instantiated over
//! $\mathbb{F}_{2^8}$ or any large-characteristic field $\mathbb{F}_p$.
//! - Provides retro-compatibility with Sha2 and MD hashes.
//!
//! We have a legacy interface for Sha2 that can be easily extended to Merkle-Damgard hashes
//! and any hash function that satisfies the [`digest::Digest`] trait.
//! - Provides an API for preprocessing.
//!
//! In recursive SNARKs, minimizing the number of invocations of the permutation
//! while maintaining security is crucial. We offer tools for preprocessing the Transcript (i.e., the state of the Fiat-Shamir transform) to achieve this.
//!
//! - Enables secure randomness generation for the prover.
//!
//! We provide a secure source of randomness for the prover that is bound to the protocol transcript, and seeded by the oeprating system.
//!
//! # Protocol Composition
//!
//! Transcript composition is a complex topic.
//! Although Merlin has been promoted as a composable transcript library,
//! it does not hold true for protocols without a unique response.
//! Take, for example, a Schnorr OR-proof
//! where $Y = xG$ or $Z = xG.$ The response is not determined during the commitment phase.
//! The response is (normally) never added to the transcript.
//! Chaining another protocol after the response results in the transcript state
//! not being bound to the protocol.
//!
//!
//! What do we learn? That it's better to have _static protocol composition_:
//! the prover better know in advance of the protocol the number of rounds and
//! the messages that are sent.
//! This serves as a security feature, preventing the prover from unexpectedly
//! branching without following a specific protocol.
//!
//! # Questions
//!
//! 1. Can you name a system that _needs_ challenges in the same domain it absorbs?
//!    I am talking about actual implementation.
//!
//!    For cryptographic sponges absorbing bytes, this is clearly not the case.
//!    For algebraic hashes, I think this is not the case either:
//!    all protocols I know of absorb elements over the coordinate space, and for efficiency reasons
//!    squeeze 128 bits of challenges. I'd be happy to be proven wrong here, but for now
//!    this means that the API won't squeeze out field elements but bytes.
//!
//!    This is not dramatic: it's easy to expose a method for squeezing field elements,
//!    but this requires a different squeeze notation in the tag.
//! 2. Do you see any advantage in providing a byte-oriente squeeze interface such that:
//!    `squeeze(1); squeeze(1)` is the same to `squeeze(2)` in Fiat-Shamir?
//! 4. SHA2 implementation: Is there a paper behind the FS implementation of sha2 in poksho and available in legacy.rs?
//! 5. Secret sponge design: is it reasonable?
//!    Functioning is easy: every time the public sponge squeezes, we absorb and reseed with
//!    operating system randomness.
//!    Absorptions are not needed (after all, they are deterministically derived from the sponge itself)
//! 5. Ergonomics: do you see a way to avoid having `Result`s everywhere? Maybe with attributes?
//!
//! [Merlin]: https://github.com/dalek-cryptography/merlin
//! [`digest::Digest`]: https://docs.rs/digest/latest/digest/trait.Digest.html

use ark_std::cmp::Ordering;
use ark_std::collections::VecDeque;
use ark_std::rand::{CryptoRng, RngCore};

mod arthur;
/// Extension for the public-coin transcripts.
pub mod ext;

/// Support for legacy hash functions (SHA2).
pub mod legacy;

use arthur::Arthur;

/// A Lane is the basic unit a sponge function works on.
/// We need only two things from a lane: the ability to convert it to bytes and back.
pub trait Lane: Sized + Default + Copy {
    fn to_bytes(a: &[Self]) -> Vec<u8>;
    fn pack_bytes(bytes: &[u8]) -> Vec<Self>;
}

/// A Sponge is a stateful object that can absorb and squeeze data.
pub trait Sponge: Clone {
    type L: Lane;
    fn new() -> Self;
    fn absorb_unsafe(&mut self, input: &[Self::L]) -> &mut Self;
    fn squeeze_unsafe(&mut self, output: &mut [Self::L]) -> &mut Self;
    fn ratchet_unsafe(&mut self) -> &mut Self;
    fn finish(self);
}

/// A [`crate::sponge::fs::Sponge8`] additionally provides a way to squeeze uniformly-random bytes.
/// While this is natural for common cryptographic sponges,
/// this operation is non-trivial for algebraic hashes: there is no guarantee that the output
/// $\pmod p$ is uniformly distributed over $2^{\lfloor log p\rfloor}$.
pub trait Sponge8: Sponge {
    fn squeeze_bytes_unsafe(&mut self, output: &mut [u8]);
}

#[derive(Debug, Clone)]
pub struct TagError(String);

impl From<&str> for TagError {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<String> for TagError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Sponge operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    /// Indicates absorption of `usize` lanes.
    ///
    /// In a tag, absorption is indicated with an alphabetic string,
    /// most commonly 'A'.
    Absorb(usize),
    /// Indicates squeezing of `usize` lanes.
    ///
    /// In a tag, squeeze is indicated with 'S'.
    Squeeze(usize),
    /// Indicates a ratcheting operation.
    /// Ratchetng here means setting
    ///  state = H(state)
    /// and absorbing new elements from here.
    /// More formally, for sponge functions, we squeeze sizeof(capaticy) lanes
    /// and initialize a new state filling the capacity.
    /// This allows for a more efficient preprocessing, and for removal of the secrets.
    ///
    /// In a tag, ratcheting is indicated with ','
    /// XXX. does anybody see a problem with this?
    Ratchet,
}

impl Op {
    /// Create a new OP from the portion of a tag.
    fn new(id: char, count: Option<usize>) -> Result<Self, TagError> {
        match (id, count) {
            ('S', Some(c)) if c > 0 => Ok(Op::Squeeze(c)),
            (x, Some(c)) if x.is_alphabetic() && c > 0 => Ok(Op::Absorb(c)),
            (',', None) | (',', Some(0)) => Ok(Op::Ratchet),
            _ => Err("Invalid tag".into()),
        }
    }
}

/// A (slightly modified) SAFE API for sponge functions.
///
/// Operations in the SAFE API provide a secure interface for using sponges.
#[derive(Clone)]
pub struct Safe<S: Sponge> {
    sponge: S,
    stack: VecDeque<Op>,
}

impl<S: Sponge8> Safe<S> {
    fn parse_tag(tag: &str) -> Result<VecDeque<Op>, TagError> {
        let (_domain_sep, io_pattern) = tag.split_once(" ").ok_or("Invalid tag string")?;
        let mut stack = VecDeque::new();

        let mut i: usize = 0;
        let io_pattern = io_pattern.as_bytes();
        while i != io_pattern.len() {
            let next_id = io_pattern[i] as char;
            let mut j = i + 1;
            let mut next_length = 0;
            while j != io_pattern.len() && io_pattern[j].is_ascii_digit() {
                next_length = next_length * 10 + (io_pattern[j] - b'0') as usize;
                j += 1;
            }
            i = j;

            // check that next_length != 0 is performed internally on Op::new
            let next_op = Op::new(next_id, Some(next_length))?;
            stack.push_back(next_op);
        }

        // consecutive calls are merged into one
        match stack.pop_front() {
            None => Err("Empty stack".into()),
            Some(x) => Self::simplify_stack(VecDeque::from([x]), stack),
        }
    }

    fn simplify_stack(
        mut dst: VecDeque<Op>,
        mut stack: VecDeque<Op>,
    ) -> Result<VecDeque<Op>, TagError> {
        if stack.is_empty() {
            Ok(dst)
        } else {
            // guaranteed never to fail
            // since simplified.len() > 0 and !stack.is_empty()
            assert!(dst.len() > 0 && !stack.is_empty());
            let previous = dst.pop_back().unwrap();
            let next = stack.pop_front().unwrap();

            match (previous, next) {
                (Op::Ratchet, Op::Ratchet) => Err("Consecutive ratchets?".into()),
                (Op::Squeeze(a), Op::Squeeze(b)) => {
                    dst.push_back(Op::Squeeze(a + b));
                    Self::simplify_stack(dst, stack)
                }
                (Op::Absorb(a), Op::Absorb(b)) => {
                    dst.push_back(Op::Absorb(a + b));
                    Self::simplify_stack(dst, stack)
                }
                (a, b) => {
                    dst.push_back(a);
                    dst.push_back(b);
                    Self::simplify_stack(dst, stack)
                }
            }
        }
    }

    /// Initialise a SAFE sponge,
    /// setting up the state of the sponge function and parsing the tag string.
    pub fn new(tag: &str) -> Result<Self, TagError> {
        let stack = Self::parse_tag(tag)?;
        let mut sponge = S::new();
        // start off absorbing the tag information
        sponge.absorb_unsafe(&S::L::pack_bytes(tag.as_bytes()));
        sponge.ratchet_unsafe();
        Ok(Self { sponge, stack })
    }

    /// Perform secure ratcheting.
    pub fn ratchet(&mut self) -> Result<(), TagError>{
        if self.stack.pop_front().unwrap() != Op::Ratchet {
            Err("Invalid tag".into())
        } else {
            self.sponge.ratchet_unsafe();
            Ok(())
        }
    }

    /// Perform secure absorption of the elements in `input`.
    pub fn absorb(&mut self, input: &[S::L]) -> Result<(), TagError> {
        let op = self.stack.pop_front().unwrap();
        if let Op::Absorb(length) = op {
            match length.cmp(&input.len()) {
                Ordering::Less => Err(format!("Not enough input for absorb: requested {}", input.len()).into()),
                Ordering::Equal => {
                    self.sponge.absorb_unsafe(input);
                    Ok(())
                }
                Ordering::Greater => {
                    self.stack.push_front(Op::Absorb(length - input.len()));
                    self.sponge.absorb_unsafe(input);
                    Ok(())
                }
            }
        } else {
            Err("Invalid tag".into())
        }
    }

    /// Perform a secure squeeze operation, filling the output buffer with uniformly random bytes.
    ///
    /// For byte-oriented sponges, this operation is equivalent to the squeeze operation.
    /// However, for algebraic hashes, it requires proper implementation.
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
    pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), TagError> {
        let op = self.stack.pop_front().unwrap();
        if let Op::Squeeze(length) = op {
            match length.cmp(&output.len()) {
                Ordering::Greater => Err("Not enough output for squeeze".into()),
                Ordering::Equal => {
                    self.sponge.squeeze_bytes_unsafe(output);
                    Ok(())
                }
                Ordering::Less => {
                    self.stack.push_front(Op::Squeeze(length - output.len()));
                    self.sponge.squeeze_bytes_unsafe(output);
                    Ok(())
                }
            }
        } else {
            Err("Invalid tag".into())
        }
    }

    /// Destroyes the sponge state.
    pub fn finish(self) -> Result<(), TagError> {
        if self.stack.is_empty() {
            Ok(())
        } else {
            Err("Tag Mismatch".into())
        }
    }
}

/// Builder for the prover state.
pub struct TranscriptBuilder<S: Sponge8, FS: Sponge8<L = u8>> {
    merlin: Merlin<S>,
    fsponge: FS,
}

impl<S: Sponge8, FS: Sponge8<L = u8>> TranscriptBuilder<S, FS> {
    // rekey the private sponge with some additional secrets (i.e. with the witness)
    // and ratchet
    pub fn rekey(mut self, data: &[u8]) -> Self {
        self.fsponge.absorb_unsafe(data);
        self.fsponge.ratchet_unsafe();
        self
    }

    // Finalize the state integrating a cryptographically-secure
    // random number generator that will be used to seed the state before future squeezes.
    pub fn finalize_with_rng<R: RngCore + CryptoRng>(self, csrng: R) -> Transcript<S, FS, R> {
        let arthur = Arthur {
            sponge: self.fsponge,
            csrng,
        };

        Transcript {
            merlin: self.merlin,
            arthur,
        }
    }
}

/// Merlin is wrapper around a sponge that provides a secure
/// Fiat-Shamir implementation for public-coin protocols.
#[derive(Clone)]
pub struct Merlin<S: Sponge8>(Safe<S>);

impl<S: Sponge8> Merlin<S> {
    pub fn new(tag: &str) -> Result<Self, TagError> {
        let safe_sponge = Safe::new(tag)?;
        Ok(Self(safe_sponge))
    }

    pub fn absorb(&mut self, input: &[S::L]) -> Result<(), TagError> {
        self.0.absorb(input)
    }

    pub fn ratchet(&mut self) -> Result<(), TagError>{
        self.0.ratchet()
    }

    pub fn finish(self) -> Result<(), TagError> {
        self.0.finish()
    }

    pub fn challenge_bytes(&mut self, mut dest: &mut [u8]) -> Result<(), TagError> {
        self.0.squeeze(&mut dest)
    }

    /// Convert this Merlin instance into an Arthur instance.
    pub fn into_transcript<FS: Sponge8<L = u8>>(self) -> TranscriptBuilder<S, FS> {
        let fsponge = FS::new();
        let merlin = self;

        TranscriptBuilder { merlin, fsponge }
    }
}

/// The state of an interactive proof system.
/// Holds the state of the verifier, and provides the random coins for the prover.
pub struct Transcript<S: Sponge8, FS: Sponge<L = u8>, R: RngCore + CryptoRng> {
    /// The randomness state of the prover.
    arthur: Arthur<FS, R>,
    merlin: Merlin<S>,
}

impl<S: Sponge8, FS: Sponge<L = u8>, R: RngCore + CryptoRng> Transcript<S, FS, R> {
    #[inline]
    pub fn absorb(&mut self, input: &[S::L]) -> Result<(), TagError> {
        self.merlin.absorb(input)
    }

    /// Get a challenge of `count` bytes.
    pub fn challenge_bytes(&mut self, dest: &mut [u8]) -> Result<(), TagError> {
        self.merlin.challenge_bytes(dest)?;
        self.arthur.sponge.absorb_unsafe(dest);
        Ok(())
    }

    #[inline]
    pub fn ratchet(&mut self) -> Result<(), TagError> {
        self.merlin.ratchet()
    }

    #[inline]
    pub fn rng<'a>(&'a mut self) -> &'a mut (impl CryptoRng + RngCore) {
        &mut self.arthur
    }

    pub fn finish(self) -> Result<(), TagError> {
        self.arthur.sponge.finish();
        self.merlin.finish()
    }
}

impl Lane for u8 {
    fn to_bytes(a: &[Self]) -> Vec<u8> {
        a.to_vec()
    }

    fn pack_bytes(bytes: &[u8]) -> Vec<Self> {
        bytes.to_vec()
    }
}

use crate::sponge::poseidon::PoseidonSponge;
use ark_bls12_377::Fq;
use ark_ff::{BigInteger, PrimeField};
use crate::sponge::CryptographicSponge;

use super::poseidon::PoseidonConfig;
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


impl Sponge for PoseidonSponge<Fq> {
    type L = Fq;

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

    fn ratchet_unsafe(&mut self) -> &mut Self {
        let digest = self.squeeze_field_elements(self.parameters.capacity);
        self.state[self.parameters.rate..].copy_from_slice(&digest);
        self.state[.. self.parameters.rate]
            .iter_mut()
            .for_each(|x| *x = Fq::zero());
        self
    }

    fn finish(self) {
        // TODO: zeroize
    }
}

impl Sponge8 for PoseidonSponge<Fq> {
    fn squeeze_bytes_unsafe(&mut self, output: &mut [u8]) {
        // obtained with the above function
        let n = 251 / 8;
        let len = (output.len() + n-1) / n;
        let mut buf = vec![Self::L::zero(); len];
        self.squeeze_unsafe(buf.as_mut_slice());
        for i in 0 .. len-1 {
            output[i*n .. (i+1)*n].copy_from_slice(&buf[i].into_bigint().to_bytes_le()[.. n]);
        }
        let remainder = output.len() % n;
        output[n*(len-1) ..].copy_from_slice(&buf[len-1].into_bigint().to_bytes_le()[.. remainder]);

    }
}