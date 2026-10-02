use std::env;

fn main() {
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-env-changed=NRF_RTT_BUILD_ID");
    println!("cargo:rustc-link-search={}", env!("CARGO_MANIFEST_DIR"));
    let identity = env::var("NRF_RTT_BUILD_ID").expect("build through build.py");
    assert!(identity.len() == 64 && identity.bytes().all(|byte| byte.is_ascii_hexdigit()));
    println!("cargo:rustc-env=NRF_RTT_BUILD_ID={identity}");
}
