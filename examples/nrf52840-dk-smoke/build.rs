fn main() {
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rustc-link-search={}", env!("CARGO_MANIFEST_DIR"));
}
