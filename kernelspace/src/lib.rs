#![no_std]

// Import macros from the `proptest` crate. These are used for property tests in `mod.rs`.
#[cfg(test)]
#[macro_use]
extern crate proptest;

pub mod probe;
