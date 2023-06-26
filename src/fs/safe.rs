
use super::{InvalidTag, Lane, Sponge, SpongeExt};
use ark_std::collections::VecDeque;
use ::core::cmp::Ordering;
use ::core::num::NonZeroUsize;

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
    /// Ratcheting here means setting
    ///  state = H(state)
    /// and absorbing new elements from here.
    /// For sponge functions, we squeeze sizeof(capacity) lanes
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


/// A builder for tag strings to be used within the SAFE API,
/// to construct the verifier transcript.
pub struct IOPattern(String);

const SEP_BYTE : u8 = b'\x00';

impl IOPattern {
    pub fn new(domsep: &str) -> Self {
        let mut tag_base = domsep.to_string();
        tag_base.push(SEP_BYTE as char);
        Self(tag_base)
    }

    pub fn absorb(self, count: NonZeroUsize) -> Self {
        Self(self.0 + &format!("A{}", count))
    }

    pub fn squeeze(self, count: NonZeroUsize) -> Self {
        Self(self.0 + &format!("S{}", count))
    }

    pub fn ratchet(self) -> Self {
        Self(self.0 + &",")
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}


/// A (slightly modified) SAFE API for sponge functions.
///
/// Operations in the SAFE API provide a secure interface for using sponges.
#[derive(Clone)]
pub struct Safe<S: SpongeExt> {
    sponge: S,
    stack: VecDeque<Op>,
}

impl<S: SpongeExt> Safe<S> {
    fn parse_io(io_pattern: &IOPattern) -> Result<VecDeque<Op>, InvalidTag> {
        let mut stack = VecDeque::new();

        // remove the domain separator.
        let mut index = 0;
        for (i, &b) in io_pattern.as_bytes().iter().enumerate() {
            if b == SEP_BYTE {
                index = i;
            }
        }
        let io_pattern = &io_pattern.as_bytes()[index..];

        let mut i: usize = 0;
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
            None => Ok(VecDeque::new()),
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
    pub fn new(io_pattern: &IOPattern) -> Self {
        // Guaranteed to succeed as IOPattern is always a valid tag.
        let stack = Self::parse_io(io_pattern)
            .expect("Internal error. Please submit issue to m@orru.net");
        let mut sponge = S::new();

        // start off absorbing the tag information
        sponge.absorb_unsafe(&S::L::pack_bytes(io_pattern.as_bytes()));
        sponge.ratchet_unsafe();
        Self { sponge, stack }
    }

    /// Perform secure ratcheting.
    ///
    /// Ratcheting allows for a more efficient preprocessing,
    /// and removes information of past absorptions from the state.
    pub fn ratchet(&mut self) -> Result<&mut Self, InvalidTag> {
        if self.stack.pop_front().unwrap() != Op::Ratchet {
            Err("Invalid tag".into())
        } else {
            self.sponge.ratchet_unsafe();
            Ok(self)
        }
    }

    pub fn ratchet_and_export(mut self) -> Result<Vec<<S as Sponge>::L>, InvalidTag> {
        self.ratchet()?;
        Ok(self.sponge.export_unsafe())
    }

    /// Perform secure absorption of the elements in `input`.
    /// Absorb calls can be batched together, or provided separately for streaming-friendly protocols.
    pub fn absorb(&mut self, input: &[S::L]) -> Result<&mut Self, InvalidTag> {
        let op = self.stack.pop_front().ok_or::<InvalidTag>("Stack is already empty".into())?;
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
}

impl<S: SpongeExt> Drop for Safe<S> {
        /// Destroyes the sponge state.
        fn drop(&mut self) {
            if !self.stack.is_empty() {
                panic!("Invalid tag. Remaining operations: {:?}", self.stack);
            }
            self.sponge.zeroize();
        }
}
