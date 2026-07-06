# Repository Guidelines

## Project Structure & Module Organization

This repository is a Rust workspace for `lsb`, a local Linux microVM sandbox for macOS and Windows hosts. Core crates live under `crates/`: `lsb-cli`, `lsb-sdk`, `lsb-vm`, `lsb-proxy`, `lsb-store`, `lsb-proto`, `lsb-platform`, and `lsb-guest`. Build automation is in `xtask/`, kernel configuration is in `kernel/`, docs are in `README.md` and `docs/`, and the agent skill is in `skills/lsb/`. Node.js bindings are isolated in `bindings/nodejs/`, with Rust binding code in `src/` and AVA specs in `test/`.

## Build, Test, and Development Commands

- `just build-cli`: build the debug CLI binary at `target/debug/lsb`.
- `just build`: build guest components, build the CLI, and codesign the binary.
- `just check`: run `cargo check --workspace`.
- `just clippy`: run `cargo clippy --workspace`.
- `cargo test --workspace`: run Rust unit tests across all crates.
- `just setup`: prepare rootfs assets and build everything; requires Docker.
- `cd bindings/nodejs && corepack yarn install`: install Node binding dependencies.
- `cd bindings/nodejs && corepack yarn build`: build the native binding.
- `cd bindings/nodejs && corepack yarn test`: build the binding and run AVA.

## Coding Style & Naming Conventions

Use `cargo fmt` for Rust. Keep crate names lowercase with hyphens, and modules, functions, and files in snake_case. The Node binding uses Prettier from `bindings/nodejs/package.json`: 100-column width, no semicolons, single quotes, and trailing commas. TypeScript tests use `*.spec.ts` names. TOML formatting is handled with `taplo format`.

## Testing Guidelines

Place Rust unit tests near the implementation in `mod tests` blocks. Use targeted commands such as `cargo test -p lsb-proxy dns` while developing, then run `cargo test --workspace` before submitting broad changes. Node tests live in `bindings/nodejs/test/**/*.spec.ts`. VM smoke tests may require initialized runtime assets, a codesigned Node binary on macOS, or QEMU/WHPX on Windows; use `corepack yarn test:signed-node` for real macOS VM startup.

Windows hardware testing:

- Use `./scripts/win-gh-test check` after platform or portability changes.
- Use `./scripts/win-gh-test unit` before opening a PR that touches Windows code.
- Use `./scripts/win-gh-test smoke` after QEMU, WHPX, VM lifecycle, transport, or guest-control changes.
- The script requires a clean committed working tree because GitHub Actions can only test pushed commits.
- Do not add automatic `pull_request` triggers for the self-hosted Windows hardware runner.

## Commit & Pull Request Guidelines

Recent history follows conventional commit prefixes such as `fix(dns): ...`, `feat(storage): ...`, `ci: ...`, and `chore(release): ...`. Keep subjects imperative and scoped when practical. Pull requests should include the problem summary, implementation approach, validation commands, linked issues, and screenshots or logs for user-visible changes.

## Security & Configuration Tips

Do not commit local runtime assets, generated native binding outputs, secrets, or codesigned local binaries. Update README examples and tests when changing `lsb.json`, proxy, or secret-handling behavior.
