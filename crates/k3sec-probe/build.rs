//! Builds the eBPF kernel crate (`k3sec-probe-ebpf`) into the linkable object
//! that `linux.rs` embeds via `include_bytes_aligned!`.
//!
//! Only runs when the `ebpf` feature is enabled (`CARGO_FEATURE_EBPF`), and only
//! on Linux, a plain host build compiles nothing here. aya-build drives the
//! BPF-target build (nightly, build-std, target, rustflags) itself.

fn main() {
    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() {
        // Probe compiled without eBPF support: nothing to build.
        return;
    }
    build_ebpf();
}

#[cfg(target_os = "linux")]
fn build_ebpf() {
    use std::path::PathBuf;

    use aya_build::{Package, Toolchain};

    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("k3sec-probe-ebpf");
    let root_dir = root_dir
        .to_str()
        .expect("non-UTF-8 path to k3sec-probe-ebpf");

    aya_build::build_ebpf(
        [Package {
            name: "k3sec-probe-ebpf",
            root_dir,
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )
    .expect("eBPF build failed");
}

#[cfg(not(target_os = "linux"))]
fn build_ebpf() {
    panic!("the `ebpf` feature is only supported on Linux");
}
