# Contributing to Tessel

Thanks for your interest! Tessel is a small, security-sensitive tool, so a few ground rules keep it trustworthy.

## Before you start

- For anything beyond a small fix, please open an issue first to discuss the change.
- Report security problems privately — see [SECURITY.md](SECURITY.md).

## Development setup

You need Rust 1.88 or newer.

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

All four must pass before a pull request is merged (CI runs them on Linux and macOS).

## Design rules

These are invariants of the project; changes that break them will not be accepted.

1. **Never execute anything from an inspected project.** No process APIs, no loading of inspected binaries. A test (`crit7b_source_never_spawns_processes`) scans `src/` for them.
2. **Treat every input as hostile.** Package contents, manifests, headers of binaries and project files are untrusted. Use checked access (`get`, `checked_add`), bound reads and sizes, and never panic on malformed input.
3. **Never follow symlinks** in inspected directories, and open files with `open_regular` (`O_NOFOLLOW | O_NONBLOCK`).
4. **Never record or print secret values.** Findings carry path, line and rule only.
5. **Do not assert what was not verified.** The manifest must not claim authorization, approval or restoration that Tessel did not check.
6. **Deterministic output.** Sort everything that is enumerated; honor `SOURCE_DATE_EPOCH`.

## Tests

- Add a test for every behaviour change; prefer integration tests in `crates/tessel-cli/tests/` that drive the real binary.
- Synthetic binaries and builds are built in the tests themselves — please do not commit real game assets or third-party binaries.
- `crit6` relies on `chmod 000` and skips itself when run as root. Run the suite as a regular user at least once before submitting.

## Commit and PR style

- Keep pull requests focused; explain *why* in the description.
- Update `README.md`, `CHANGELOG.md` and `schemas/` when behaviour or the package format changes. Format changes need a new `format_version`.

## License

By contributing you agree that your contributions are dual licensed under MIT and Apache-2.0, as described in the README.
