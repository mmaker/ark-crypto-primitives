//!
//! **This is work in progress, not suitable for production.**
//!
//! This library is a secure construction for zero-knowledge proofs based on SAFE.
//! It enables secure provision of randomness for the prover and secure generation
//! of random coins for the verifier.
//! This allows for the implementation of non-interactive protocols in a readable manner.
//!
//! ```rust
//! use ark_crypto_primitives::fs::legacy::Sha2Bridge;
//! use ark_crypto_primitives::fs::ext::{FieldChallenges, AbsorbSerializable};
//! use ark_crypto_primitives::fs::{Merlin, InvalidTag};
//! use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
//! use ark_crypto_primitives::fs::poseidon_ng::PoseidonSpongeNG;
//! use rand::rngs::OsRng;
//! use rand::RngCore;
//! use ark_bls12_377::{Fr, Fq};
//! use ark_bls12_377::G1Projective as G1;
//! use ark_ec::{AffineRepr, CurveGroup, Group};
//! use ark_std::UniformRand;
//!
//! fn schnorr_proof(sk: Fr, pk: G1) -> Result<(Fr, Fr), InvalidTag> {
//!     // create a new verifier transcript for the protocol identified by the tag.
//!     // the tag string indicates that:
//!     // - the statement will absorb 48 * 2 elements
//!     // - the protocol will: absorb two elements, squeeze 16 bytes.
//!     // utilities for creating tag strings automatically will be added in the future.
//!     let mut merlin = Merlin::<PoseidonSpongeNG<Fq>>::new("example.com A48A48,A2S16")?;
//!     // Absorb the statement.
//!     merlin.absorb_serializable(pk)?
//!           .absorb_serializable(G1::generator())?
//!           .ratchet()?;
//!     // At this point the state can be cloned, or exported
//!     // so that the proof can be verified inside another sponge.
//!     // let mut verifier_state = merlin.clone();
//!
//!     // Build an RNG that is tied to the protocol transcript.
//!     // Using a fast sponge, rekeying it with some witness data,
//!     // and seeding it with a cryptographically-secure random number generator.
//!     let mut transcript = merlin.into_transcript::<Sha2Bridge>()
//!         .rekey(b"witness data")
//!         .finalize_with_rng(OsRng);
//!
//!     // Actual proof.
//!     let k = Fr::rand(&mut transcript.rng());
//!     let K = G1::generator().into_affine() * k;
//!     // Absorptions can be streamed:
//!     // transcript.absorb(&[K.x])?; transcript.absorb(&[K.y])?;
//!     transcript.absorb(&[K.x, K.y])?;
//!
//!     // Get a challenge from the verifier.
//!     let challenge = transcript.get_field_challenge::<Fr>(16)?;
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
//! To build a secure Fiat-Shamir transform, a permutation function is required.
//! You can choose from SHA3, Poseidon, Anemoi, instantiated over
//! $\mathbb{F}_{2^8}$ or any large-characteristic field $\mathbb{F}_p$.
//! - Provides retro-compatibility with Sha2 and MD hashes.
//! We have a legacy interface for Sha2 that can be easily extended to Merkle-Damgard hashes
//! and any hash function that satisfies the [`digest::Digest`] trait.
//! - Provides an API for preprocessing.
//! In recursive SNARKs, minimizing the number of invocations of the permutation
//! while maintaining security is crucial. We offer tools for preprocessing the Transcript (i.e., the state of the Fiat-Shamir transform) to achieve this.
//!
//! - Enables secure randomness generation for the prover.
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
//! # Questions during calls
//!
//! 1. Can you name a proof system (_actual, legit implementations_)
//!    that uses challenges in the same domain it absorbs?
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
//! 5. Ergonomics: do you see a way to avoid having `Result`s everywhere?
//!     Should we just panic at runtime?
//! 6. Scoping: is this composability idea used anywhere?
//!     One easy and secure way for composition is to squeeze `capacity` elements from the sponge
//!     and provide them to the user upon finishing a transcript.
//!     They can be used to re-seed a new sponge with a new stack.
//!     Is this a good idea?
//! 7. Forcing input of statements in the transcript:
//!    The call to `ratchet` is currently what separates the statement from the rest of the protocol.
//!    This is not so intuitive, and it would be nicer to have an API that explicits
//!    where the statement is.
//! 8. Easier protocol composition: there are two approaches. the latter seems more reasonable?
//!     - upon finish, ratchet and return a seed.
//!         This makes a wasteful call to the permutation function most of the time.
//!     - statically chain the tags.
//!         This requires a larger overhead on the side of the engineer.
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
/// Support for sponge functions.
pub mod sponge;

/// New implementation of the poseidon sponge function.
pub mod poseidon_ng;

use arthur::Arthur;

/// A Lane is the basic unit a sponge function works on.
/// We need only two things from a lane: the ability to convert it to bytes and back.
pub trait Lane: Sized + Default + Copy {
    fn to_bytes(a: &[Self]) -> Vec<u8>;
    fn pack_bytes(bytes: &[u8]) -> Vec<Self>;
}

/// A Sponge is a stateful object that can absorb and squeeze data.
pub trait Sponge {
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
    /// Securely destroys the sponge and its internal state.
    fn finish(self);
}

/// A [`crate::fs::SpongeExt`] additionally provides
/// squeezing uniformly-random bytes and ratcheting.
/// While squeezing bytes is natural for common cryptographic sponges,
/// this operation is non-trivial for algebraic hashes: there is no guarantee that the output
/// $\pmod p$ is uniformly distributed over $2^{\lfloor log p\rfloor}$.
pub trait SpongeExt: Sponge {
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
    fn export_unsafe(&self) -> Vec<Self::L>;
    fn ratchet_unsafe(&mut self) -> &mut Self;
}

#[derive(Debug, Clone)]
pub struct InvalidTag(String);

impl From<&str> for InvalidTag {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<String> for InvalidTag {
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
    fn new(id: char, count: Option<usize>) -> Result<Self, InvalidTag> {
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

impl<S: SpongeExt> Safe<S> {
    fn parse_tag(tag: &str) -> Result<VecDeque<Op>, InvalidTag> {
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
    ) -> Result<VecDeque<Op>, InvalidTag> {
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
    pub fn new(tag: &str) -> Result<Self, InvalidTag> {
        let stack = Self::parse_tag(tag)?;
        let mut sponge = S::new();
        // start off absorbing the tag information
        sponge.absorb_unsafe(&S::L::pack_bytes(tag.as_bytes()));
        sponge.ratchet_unsafe();
        Ok(Self { sponge, stack })
    }

    /// Perform secure ratcheting.
    pub fn ratchet(&mut self) -> Result<&mut Self, InvalidTag> {
        if self.stack.pop_front().unwrap() != Op::Ratchet {
            Err("Invalid tag".into())
        } else {
            self.sponge.ratchet_unsafe();
            Ok(self)
        }
    }

    /// Perform secure absorption of the elements in `input`.
    /// Absorb calls can be batched together, or provided separately for streaming-friendly protocols.
    pub fn absorb(&mut self, input: &[S::L]) -> Result<&mut Self, InvalidTag> {
        let op = self.stack.pop_front().unwrap();
        if let Op::Absorb(length) = op {
            match length.cmp(&input.len()) {
                Ordering::Less => {
                    Err(format!("Not enough input for absorb: requested {}", input.len()).into())
                }
                Ordering::Equal => {
                    self.sponge.absorb_unsafe(input);
                    Ok(self)
                }
                Ordering::Greater => {
                    self.stack.push_front(Op::Absorb(length - input.len()));
                    self.sponge.absorb_unsafe(input);
                    Ok(self)
                }
            }
        } else {
            Err("Invalid tag".into())
        }
    }

    /// Perform a secure squeeze operation, filling the output buffer with uniformly random bytes.
    ///
    /// For byte-oriented sponges, this operation is equivalent to the squeeze operation.
    /// However, for algebraic hashes, this operation is non-trivial.
    /// This function provides no guarantee of streaming-friendliness.
    pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), InvalidTag> {
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
    pub fn finish(self) -> Result<(), InvalidTag> {
        if self.stack.is_empty() {
            Ok(())
        } else {
            Err("Tag Mismatch".into())
        }
    }
}

/// Builder for the prover state.
pub struct TranscriptBuilder<S: SpongeExt, FS: SpongeExt<L = u8>> {
    merlin: Merlin<S>,
    fsponge: FS,
}

impl<S: SpongeExt, FS: SpongeExt<L = u8>> TranscriptBuilder<S, FS> {
    pub(crate) fn new(mut fsponge: FS, merlin: Merlin<S>) -> Self {
        let merlin_state = merlin.0.sponge.export_unsafe();
        let encoded_state = &<S as Sponge>::L::to_bytes(&merlin_state);
        fsponge.absorb_unsafe(encoded_state);
        Self { fsponge, merlin }
    }

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
pub struct Merlin<S: SpongeExt>(Safe<S>);

impl<S: SpongeExt> Merlin<S> {
    pub fn new(tag: &str) -> Result<Self, InvalidTag> {
        let safe_sponge = Safe::new(tag)?;
        Ok(Self(safe_sponge))
    }

    pub fn absorb(&mut self, input: &[S::L]) -> Result<&mut Self, InvalidTag> {
        self.0.absorb(input)?;
        Ok(self)
    }

    pub fn ratchet(&mut self) -> Result<&mut Self, InvalidTag> {
        self.0.ratchet()?;
        Ok(self)
    }

    pub fn finish(self) -> Result<(), InvalidTag> {
        self.0.finish()
    }

    pub fn challenge_bytes(&mut self, mut dest: &mut [u8]) -> Result<(), InvalidTag> {
        self.0.squeeze(&mut dest)
    }

    /// Convert this Merlin instance into an Arthur instance.
    pub fn into_transcript<FS: SpongeExt<L = u8>>(self) -> TranscriptBuilder<S, FS> {
        let fsponge = FS::new();
        let merlin = self;

        TranscriptBuilder::new(fsponge, merlin)
    }
}

/// The state of an interactive proof system.
/// Holds the state of the verifier, and provides the random coins for the prover.
pub struct Transcript<S: SpongeExt, FS: Sponge<L = u8>, R: RngCore + CryptoRng> {
    /// The randomness state of the prover.
    arthur: Arthur<FS, R>,
    merlin: Merlin<S>,
}

impl<S: SpongeExt, FS: Sponge<L = u8>, R: RngCore + CryptoRng> Transcript<S, FS, R> {
    #[inline]
    pub fn absorb(&mut self, input: &[S::L]) -> Result<&mut Self, InvalidTag> {
        self.merlin.absorb(input)?;
        Ok(self)
    }

    /// Get a challenge of `count` bytes.
    pub fn challenge_bytes(&mut self, dest: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.challenge_bytes(dest)?;
        self.arthur.sponge.absorb_unsafe(dest);
        Ok(())
    }

    #[inline]
    pub fn ratchet(&mut self) -> Result<&mut Self, InvalidTag> {
        self.merlin.ratchet()?;
        Ok(self)
    }

    #[inline]
    pub fn rng<'a>(&'a mut self) -> &'a mut (impl CryptoRng + RngCore) {
        &mut self.arthur
    }

    pub fn finish(self) -> Result<(), InvalidTag> {
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
