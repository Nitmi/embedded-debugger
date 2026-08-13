# Repository Guidance

- Keep hardware behavior behind backend traits so tests and replay never require attached hardware.
- Preserve the versioned structured JSON contract across CLI and future MCP interfaces.
- Treat target mutation as dangerous: require an immutable plan digest and exact probe/target identity before execution.
- Keep logs on stderr and machine-readable command results on stdout.
- Do not add a backend capability unless unsupported behavior is represented explicitly.
- Commit cohesive, verified checkpoints. Before committing, run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.

