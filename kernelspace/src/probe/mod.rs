//! Shared types between kernel space and userspace.
//!
//! # Explanation of feature flags
//! Many features of the Rust standard library require memory allocation, which is not available
//! in eBPF code. So, the eBPF code is marked with the `#![no_std]` attribute to disable those
//! features.
//!
//! The userspace code, however, is allowed to allocate memory and therefore can make full use of
//! the Rust standard library (`std`). To share types between our eBPF and userspace code, we use
//! the `std` feature flag to enable conditional compilation. Code blocks marked with
//! `#[cfg(feature="std")]` will only be compiled when producing the userspace binary; they will
//! be ignored when producing the eBPF binary.
//!
//! In this module, we use the `std` feature flag to add a conversion implementation from
//! `BeIpv4Addr` into `std::net::Ipv4Addr` only from userspace.
#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::net::Ipv4Addr;

/// Big-endian representation of an IPv4 address.
///
/// We are using the [newtype pattern] to ensure that conversions to the builtin
/// `std::net::Ipv4Addr` type correctly account for the Big Endian byte order.
///
/// [newtype pattern]: https://rust-lang.github.io/api-guidelines/type-safety.html#c-newtype
#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct BeIpv4Addr(u32);

impl BeIpv4Addr {
    /// Conversion from `BeIpv4Addr` to `std::net::Ipv4Addr`.
    #[cfg(feature = "std")]
    pub fn to_ip(self) -> Ipv4Addr {
        // Network order for the IP address will represent `127.0.0.1` as `[1, 0,  0, 127]`. We
        // need to reverse the byte order before creating the `Ipv4Addr`.
        self.0.swap_bytes().into()
    }
}

/// Conversion from `u32` to `BeIpv4Addr`.
impl From<u32> for BeIpv4Addr {
    fn from(be: u32) -> Self {
        Self(be)
    }
}

/// Conversion from `Ipv4Addr` to `BeIpv4Addr`
#[cfg(feature = "std")]
impl From<Ipv4Addr> for BeIpv4Addr {
    fn from(ip: Ipv4Addr) -> Self {
        Self(u32::from_be_bytes(ip.octets()).swap_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Property testing is a test methodology which checks if a property holds when random inputs
    // are provided. In this way, it is similar to fuzzing. However, property testing frameworks
    // often have strategies for input minimization and more granular bounds on the inputs.
    proptest! {
        /// Test that the conversion between `BeIpv4Addr` and `std::net::Ipv4Addr` is a
        /// [bijective function] - i.e., that each input `BeIpv4Addr` is mapped to exactly one
        /// `Ipv4Addr` and that the inverse is also true.
        ///
        /// In other words, we are testing the invertibility of a serilization/deserialization
        /// implementation.
        ///
        /// [bijective function]: https://en.wikipedia.org/wiki/Bijection
        #[test]
        #[cfg(feature="std")]
        fn beipv4addr_u32_roundtrip(be: u32) {
            let original_beaddr = BeIpv4Addr(be);
            let converted_beaddr: BeIpv4Addr = original_beaddr.to_ip().into();
            assert_eq!(original_beaddr, converted_beaddr);
        }
    }
}