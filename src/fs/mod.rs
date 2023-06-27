//!
//! **This is work in progress, not suitable for production.**
//!
//! This library is a secure construction for zero-knowledge proofs based on [SAFE].
//! It enables secure provision of randomness for the prover and secure generation
//! of random coins for the verifier.
//! This allows for the implementation of non-interactive protocols in a readable manner.
//!
//! ```rust
//! use ark_crypto_primitives::fs::{legacy::Sha2Bridge, poseidon_ng::PoseidonSpongeNG};
//! use ark_crypto_primitives::fs::ark_plugins::{RekeySerializable};
//! use ark_crypto_primitives::fs::plugins::FieldChallenges;
//! use ark_crypto_primitives::fs::{IOPattern, InvalidTag};
//! use rand::rngs::OsRng;
//! use ark_ed_on_bls12_381::{Fr, Fq, EdwardsAffine as GG};
//! use ark_ec::{AffineRepr, CurveGroup, Group};
//! use ark_std::UniformRand;
//!
//! fn schnorr_proof(sk: Fr, g: GG, pk: GG) -> Result<(Fr, Fr), InvalidTag> {
//!     // create a new verifier transcript for the protocol that will perform
//!     // the operations below. Alternatively, one can just invoke the `Merlin` API
//!     // directly via Merlin::new("example.com A2A2,A2S16");
//!     let mut merlin = IOPattern::new("example.com")?
//!                 // the generator
//!                 .absorb(2)
//!                 // the public-key
//!                 .absorb(2)
//!                 // marker for end of statement
//!                 // (also allows for precomputation)
//!                 .ratchet()
//!                 // the commitment
//!                 .absorb(2)
//!                 // the challenge
//!                 .squeeze(16)
//!                 .into_merlin::<PoseidonSpongeNG<Fq>>();
//!     // Absorb the statement.
//!     merlin.absorb_points(&[g, pk])?
//!           .ratchet()?;
//!     // The state can be exported
//!     // and the proof can be verified inside another sponge.
//!
//!     // Build an RNG that is tied to the protocol transcript,
//!     // seeding it with the witness (optional) and
//!     // a cryptographically-secure random number generator.
//!     let mut transcript = merlin.into_transcript()
//!         .rekey_serializable(sk)
//!         .finalize_with_rng(OsRng);
//!
//!     // Commitment: use the prover transcript to seed randomness.
//!     let k = Fr::rand(&mut transcript.rng());
//!     let K = GG::generator() * k;
//!     // Absorptions can be streamed:
//!     // transcript.absorb(&[K.x])?; transcript.absorb(&[K.y])?;
//!     transcript.absorb(&[K.x, K.y])?;
//!
//!     // Get a challenge of 16 bytes and map it into the field Fr.
//!     let challenge = transcript.get_field_challenge::<Fr>(16)?;
//!     let response = k + challenge * sk;
//!     let proof = (challenge, response);
//!     Ok(proof)
//! }
//!
//! let sk = Fr::rand(&mut OsRng);
//! let generator = GG::generator();
//! let pk = (generator * sk).into();
//! let proof = schnorr_proof(sk, generator, pk).expect("Valid proof");
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
//! [SAFE]: https://eprint.iacr.org/2023/522
//! [Merlin]: https://github.com/dalek-cryptography/merlin
//! [`digest::Digest`]: https://docs.rs/digest/latest/digest/trait.Digest.html

/// Support for legacy hash functions (SHA2).
pub mod legacy;
/// Extensions for arkworks types.
pub mod plugins;
/// Extension for arkworks sponge functions.
pub mod poseidon_ng;

/// API for building a sponge from a permutation function.
mod duplex;
/// Error types.
mod errors;
/// SHA3 sponge function.
pub mod keccak;

/// Basic units over which a sponge operates.
mod lane;
/// Support for sponge functions.
mod sponge;
/// SAFE API for sponge functions (with ratcheting).
mod safe;
/// Verifier transcript.
mod merlin;
/// Prover's internal state.
mod arthur;

pub use arthur::{Transcript, TranscriptBuilder};
pub use duplex::{DuplexSponge, SpongeConfig};
pub use errors::InvalidTag;
pub use lane::Lane;
pub use merlin::Merlin;
pub use safe::{IOPattern, Safe};
pub use sponge::Sponge;

pub type DefaultRng = rand::rngs::OsRng;
pub type DefaultHash = keccak::Keccak;
pub type DefaultTranscript = Transcript<DefaultHash>;
