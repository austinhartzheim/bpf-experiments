//! Custom build script.
//!
//! This software has separate eBPF and userspace components. To ease distribution, the eBPF code
//! is compiled into the userspace binary with the `include_bytes!` macro. This build script
//! compiles the probes into ELF binaries and tells `cargo` to rerun the build if the eBPF code
//! changes.
use std::env;
use std::path::{Path, PathBuf};

use cargo_bpf_lib as cargo_bpf;

fn main() {
    // Get the path to the `cargo` binary. Also, get the output directory and the directory where
    // the probe source code is.
    let cargo = PathBuf::from(env::var("CARGO").unwrap());
    let target = PathBuf::from(env::var("OUT_DIR").unwrap());
    let probes = Path::new("../kernelspace");

    // Build the probes using `cargo bpf` and place them in `$OUT_DIR/target`.
    cargo_bpf::build(&cargo, &probes, &target.join("target"), Vec::new())
        .expect("failed to compile probes");

    // Tell Cargo to rebuild if the following files have changed.
    //
    // This is necessary because we are compiling the probes to ELF files and including the
    // contents of those files into the userspace binary. Therefore, if the ELF files have
    // changed, we need to rebuild the userspace binary to pick up those changes.
    cargo_bpf::probe_files(&probes)
        .expect("failed to list probe files")
        .iter()
        .for_each(|file| {
            println!("cargo:rerun-if-changed={}", file);
        });
}
