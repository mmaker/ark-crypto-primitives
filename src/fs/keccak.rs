//! Keccak sponge function, stolen from Merlin in dalek-cryptography

use core::ops::{Deref, DerefMut};

use keccak::f1600 as keccak_f1600;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Sponge;

/// Strobe R value; security level 128 is hardcoded
const STROBE_R: u8 = 166;

fn transmute_state(st: &mut AlignedKeccakState) -> &mut [u64; 25] {
    unsafe { &mut *(st as *mut AlignedKeccakState as *mut [u64; 25]) }
}

/// This is a wrapper around 200-byte buffer that's always 8-byte aligned
/// to make pointers to it safely convertible to pointers to [u64; 25]
/// (since u64 words must be 8-byte aligned)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
struct AlignedKeccakState([u8; 200]);

/// A Strobe context for the 128-bit security level.
///
/// Only `meta-AD`, `AD`, `KEY`, and `PRF` operations are supported.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keccak {
    state: AlignedKeccakState,
    pos: u8,
    pos_begin: u8,
    cur_flags: u8,
}

impl Sponge for Keccak {
    type L = u8;

    fn new() -> Self {
        let initial_state = {
            let mut st = AlignedKeccakState([0u8; 200]);
            keccak_f1600(transmute_state(&mut st));
            st
        };

        let strobe = Keccak {
            state: initial_state,
            pos: 0,
            pos_begin: 0,
            cur_flags: 0,
        };
        strobe
    }

    fn absorb_unchecked(&mut self, input: &[Self::L]) -> &mut Self {
        for byte in input {
            self.state[self.pos as usize] ^= byte;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
        self
    }

    fn squeeze_unchecked(&mut self, output: &mut [Self::L]) -> &mut Self {
        for byte in output {
            *byte = self.state[self.pos as usize];
            self.state[self.pos as usize] = 0;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
        self
    }

    fn from_capacity(_input: &[Self::L]) -> Self {
        todo!()
    }

    fn export_unchecked(&self) -> Vec<Self::L> {
        todo!()
    }

    fn ratchet_unchecked(&mut self) -> &mut Self {
        self.run_f();
        self.state[0..STROBE_R as usize].zeroize();
        self.pos = 0;
        self
    }
}

impl Keccak {
    fn run_f(&mut self) {
        self.state[self.pos as usize] ^= self.pos_begin;
        self.state[(self.pos + 1) as usize] ^= 0x04;
        self.state[(STROBE_R + 1) as usize] ^= 0x80;
        keccak::f1600(transmute_state(&mut self.state));
        self.pos = 0;
        self.pos_begin = 0;
    }
}

impl Deref for AlignedKeccakState {
    type Target = [u8; 200];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlignedKeccakState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
