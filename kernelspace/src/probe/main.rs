//! This eBPF program counts incoming IPv4 packets by the SRC and DST IP addresses.
//!
//! Counts are stored in two separate `HashMap`s (namely, `SRC_PACKETS` and `DST_PACKETS`). These
//! maps are readable from userspace.

// Many features in the Rust standard library require memory allocation, which makes them unusable
// from eBPF code. We mark this executable as `no_std` to disable the standard library and rely
// only on core language features.
#![no_std]
// eBPF programs do not have a `main` function. Instead, they receive events from the kernel by
// registering various probes. So, we use the `no_main` attribute to indicate that this binary
// will not have a `main` function.
#![no_main]

// Import the XDP prelude which includes bindings for `mmap` datastructures, etc.
use redbpf_probes::xdp::prelude::*;

// Import types that we share with userspace.
use kernelspace::probe::BeIpv4Addr;

// Declare kernel version compatibility and license.
program!(0xFFFFFFFE, "GPL");

/// Count of packets by IPv4 `src` address.
#[map]
static mut SRC_PACKETS: HashMap<BeIpv4Addr, u32> = HashMap::with_max_entries(100);
/// Count of packets by IPv4 `dst` address.
#[map]
static mut DST_PACKETS: HashMap<BeIpv4Addr, u32> = HashMap::with_max_entries(100);
/// IPv4 `src` addresses to abort packets from.
#[map]
static mut SRC_BLOCK: HashMap<BeIpv4Addr, bool> = HashMap::with_max_entries(100);

#[xdp]
fn process(ctx: XdpContext) -> XdpResult {
    // Extract the source and destination IP addresses from the IPv4 header.
    //
    // If an IPv4 header is not found or another `NetworkError` variant is reached, the packet
    // will be allowed through without collecting additional data. Future work could include
    // collecting statistics on malformed packets and exposing that data to userspace.
    let (src_ip, dst_ip): (BeIpv4Addr, BeIpv4Addr) = match ctx.ip() {
        // `unsafe` is used to allow raw pointer dereference.
        Ok(iphdr) => unsafe { ((*iphdr).saddr.into(), (*iphdr).daddr.into()) },
        Err(_) => return Ok(XdpAction::Pass),
    };

    let initial = 0;
    // `unsafe` is used to allow read/write access to a mutable static variable, which is a
    // potential data race in multithreaded programs.
    unsafe {
        let count = SRC_PACKETS.get(&src_ip).unwrap_or(&initial);
        SRC_PACKETS.set(&src_ip, &count.saturating_add(1));
        let count = DST_PACKETS.get(&dst_ip).unwrap_or(&initial);
        DST_PACKETS.set(&dst_ip, &count.saturating_add(1));
    }

    // Check if the `src` address is in the `SRC_BLOCK` map and set to `true`. If it is, abort
    // processing of this packet.
    // `unsafe` is used to dereference a raw pointer to the map value.
    let default = false;
    if unsafe { *SRC_BLOCK.get(&src_ip).unwrap_or(&default) } {
        Ok(XdpAction::Aborted)
    } else {
        Ok(XdpAction::Pass)
    }
}
