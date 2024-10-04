//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha3::{Digest, Keccak256};
use sp1_zkvm::lib::syscall_keccak_permute;
use tiny_keccak::{Hasher, Keccak};

fn raw_keccak(input: &[u8]) -> [u8; 32] {
    const KECCAK_ROUNDS: usize = 24;
    const KECCAK_RATE: usize = 1088 / 8;
    const KECCAK_CAPACITY: usize = 512 / 8;
    const KECCAK_STATE_SIZE: usize = KECCAK_RATE + KECCAK_CAPACITY;

    let mut state = [0u64; 25];
    let mut input_offset = 0;

    // Absorb input
    while input_offset < input.len() {
        for i in 0..KECCAK_RATE {
            if input_offset < input.len() {
                state[i / 8] ^= (input[input_offset] as u64) << ((i % 8) * 8);
                input_offset += 1;
            } else if i == input.len() % KECCAK_RATE {
                state[i / 8] ^= 0x01u64 << ((i % 8) * 8);
            } else if i == KECCAK_RATE - 1 {
                state[i / 8] ^= 0x80u64 << ((i % 8) * 8);
            }
        }

        // Keccak-f[1600] permutation
        unsafe { syscall_keccak_permute(state.as_mut_ptr() as *mut [u64; 25]) };
    }

    // Squeeze output
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = (state[i / 8] >> ((i % 8) * 8)) as u8;
    }
    output
}

pub fn main() {
    // Read an input vector
    let input = sp1_zkvm::io::read::<Vec<u8>>();

    // Hash using tiny_keccak
    println!("cycle-tracker-start: tiny_keccak");
    let tiny_keccak_hash = {
        let mut hasher = Keccak::v256();
        hasher.update(&input);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        output
    };
    println!("cycle-tracker-end: tiny_keccak");

    // Hash using rust-crypto sha3
    println!("cycle-tracker-start: rust-crypto sha3");
    let rust_crypto_hash = {
        let mut hasher = Keccak256::new();
        hasher.update(&input);
        hasher.finalize()
    };
    println!("cycle-tracker-end: rust-crypto sha3");

    // Raw Keccak implementation
    println!("cycle-tracker-start: raw keccak");
    let raw_keccak_hash = { raw_keccak(&input) };
    println!("cycle-tracker-end: raw keccak");

    // Print the results
    println!("tiny_keccak hash: {:?}", tiny_keccak_hash);
    println!("rust-crypto sha3 hash: {:?}", rust_crypto_hash);
    println!("raw keccak hash: {:?}", raw_keccak_hash);
}
