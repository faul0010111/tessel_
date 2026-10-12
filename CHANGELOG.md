# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.4.0]

### Changed
- Project renamed to **Tessel** (previously *Gamekeep*, and before that *OpenGame Continuity*). The binary is now `tessel`, the package format is **TSP** (`format: "TSP"`, `.tsp.zip`). Packages created by earlier versions must be regenerated.
- All CLI output, report messages, documentation, code comments and tests are now in English.

### Added
- `LICENSE-MIT`, `LICENSE-APACHE`, `CONTRIBUTING.md`, `SECURITY.md` and a GitHub Actions workflow.

## [0.3.0]

### Changed
- Renamed to Gamekeep (`gk`, format `GKP`).

## [0.2.0]

### Added
- Per-component **export policy** (`--policy`): `approved` / `unreviewed` / `not_permitted`, with hashes of omitted files in `integrity/external.json`.
- **Secret scanning** that blocks exports (`--allow-secret-findings` to acknowledge).
- `check` command (dry-run of the export).
- `verify` re-applies the embedded policy and reports `policy_violation`.
- `analyze` command: static classification of PE / ELF / Mach-O / DEX / Wasm binaries and analysis of Unity player builds, with an optional source-vs-build comparison.
- JSON Schema for the manifest and an example policy.

### Security
- Files are opened with `O_NOFOLLOW | O_NONBLOCK`, closing the window in which a file could be swapped for a symlink or FIFO between inventory and read.

## [0.1.0]

### Added
- `inspect`, `package`, `verify`, `diff` and `report` commands.
- Deterministic inventory, verifiable ZIP packages (manifest, integrity inventory, provenance, reports), hostile-input hardening in `verify`.
