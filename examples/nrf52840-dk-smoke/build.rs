use std::env;

fn main() {
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-env-changed=NRF_SMOKE_BUILD_ID");
    println!("cargo:rustc-link-search={}", env!("CARGO_MANIFEST_DIR"));

    let build_id = env::var("NRF_SMOKE_BUILD_ID").unwrap_or_else(|_| "UNSET".to_string());
    println!("cargo:rustc-env=NRF_SMOKE_BUILD_ID={build_id}");
}
