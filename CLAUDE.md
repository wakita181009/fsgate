# fsgate

## Module Organization

Use the Rust 2024 edition module style. Never create `mod.rs` files.

- A module with submodules is a plain file (`auth.rs`) plus a same-named
  directory (`auth/`) holding its children.
- `mod.rs` is legacy (pre-2018 edition) and must not be introduced or
  reintroduced during refactors.
