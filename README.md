# Tessel

**Inventory, export policy and verifiable packages for game projects — plus static analysis of Unity builds.**

Tessel is a command-line tool (`tessel`, written in Rust) for teams that need to hand a game project to someone else — a publisher, an archive, a second studio — without leaking secrets, without shipping third-party code they have no right to redistribute, and with a way for the receiver to confirm that nothing changed in transit.

It never runs anything from the project it inspects: no editor, no build scripts, no binaries. It only reads files.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

```text
tessel inspect  ./ProjectAtlas                          # inventory (read-only)
tessel check    ./ProjectAtlas --policy policy.json     # dry-run of the export
tessel package  ./ProjectAtlas -o atlas.tsp.zip --policy policy.json
tessel verify   atlas.tsp.zip                           # integrity + policy conformance
tessel diff     ./build-original ./build-reproduced     # compare two directories
tessel analyze  ./build-windows --source ./ProjectAtlas # binaries + Unity build analysis
tessel report   atlas.tsp.zip -o report.json            # human/CI-readable report
```

## Why

Handing over a game project is harder than zipping a folder:

- **Not everything may leave.** Commercial SDKs, middleware and licensed assets often cannot be redistributed. You still want the receiver to know *exactly* which files are missing so they can re-acquire them lawfully.
- **Secrets hide in repos.** Keystores, `.env` files, API keys and private keys end up in project folders.
- **A zip proves nothing.** The receiver needs to know the package is internally consistent and what it contains.
- **Builds are opaque.** When all you have is a shipped build, you want to know what it is made of — platform, scripting backend, engine version, managed assemblies — without launching it.

Tessel addresses each of these with small, composable commands and a documented package format.

## Features

- **Deterministic inventory** — SHA-256 of every regular file; a *logical inventory digest* that does not depend on ZIP layout, timestamps or filesystem order.
- **Per-component export policy** — classify parts of the project as `approved`, `unreviewed` or `not_permitted`. Files marked `not_permitted` are **never** exported.
- **Hashes for what was left out** — omitted files are recorded (path, size, SHA-256) in `integrity/external.json`, so a second team can verify it re-acquired the very same dependency.
- **Secret scanning** — private keys, cloud/API tokens, generic credential assignments and sensitive files (`.pem`, `.env*`, `id_rsa*`, keystores…) block the export until reviewed. Secret values are never printed or stored.
- **Verifiable packages (TSP)** — a ZIP with a manifest, an integrity inventory, provenance, the applied policy and reports. `tessel verify` re-checks everything and re-applies the embedded policy.
- **Static build analysis** — classifies PE/ELF/Mach-O/DEX/Wasm binaries by header, detects managed .NET assemblies, and reads platform, scripting backend (Mono/IL2CPP), IL2CPP metadata version and Editor version from Unity player builds.
- **Source ↔ build comparison** — compare the Editor version and assembly names of a Unity project against a build.
- **CI-friendly** — `--json` on query commands and stable exit codes.

## Installation

Requires Rust **1.88 or newer** (edition 2024).

```sh
git clone <this repository>
cd tessel
cargo install --path crates/tessel-cli      # installs the `tessel` binary
# or, without installing:
cargo build --release                       # binary at target/release/tessel
```

Tested on Linux. The code is plain Rust with Unix-specific hardening behind `cfg(unix)`; macOS is expected to work and is covered by CI, Windows is not supported yet.

## Quick start

### 1. Inspect a project

```text
$ tessel inspect ProjectAtlas
Directory: ProjectAtlas
Files: 5   Content: 4.1 KiB
Logical inventory (sha256): b645d4183f94…
Unity: Editor 6000.3.0f1 declared; 1 package(s) in Packages/manifest.json
```

Unity projects are detected through `ProjectSettings/ProjectVersion.txt` and `Packages/manifest.json`. Any other directory works as a generic inventory.

### 2. Describe what may leave (the export policy)

```json
{
  "version": 1,
  "components": [
    { "id": "game-source", "kind": "source", "path": "Assets/Scripts",
      "redistribution": "approved", "license": "MIT" },
    { "id": "commercial-sdk", "kind": "dependency", "path": "Assets/Plugins/Vendor",
      "version": "7.0", "redistribution": "not_permitted",
      "availability": "external_authorized_acquisition",
      "license": "LicenseRef-Vendor-EULA" }
  ]
}
```

A complete example lives in [`docs/examples/policy.example.json`](docs/examples/policy.example.json).

### 3. Dry-run the export

```text
$ tessel check ProjectAtlas --policy policy.json
Policy applied (sha256 372265b355a8…)
Components:
  commercial-sdk                   not_permitted  OMITTED         1 files    4.0 KiB   Assets/Plugins/Vendor
  component-project-source         unreviewed     INCLUDED        3 files      102 B   (root)
  game-source                      approved       INCLUDED        1 files       23 B   Assets/Scripts
Will be exported: 4 file(s), 125 B
Omitted by policy: 1 file(s), 4.0 KiB (hashes recorded in integrity/external.json)
Secret scan: 4 text file(s) scanned, 0 binary and 0 large file(s) not scanned
Result: EXPORT ALLOWED
```

If a secret shows up, the export is blocked:

```text
BLOCKING FINDINGS (1):
  - Assets/Config/cloud.txt:1 [aws_access_key_id]
Result: EXPORT BLOCKED
  - 1 blocking secret finding(s)
```

(The matched value is never shown — only path, line and rule.)

### 4. Create and verify the package

```text
$ tessel package ProjectAtlas -o ProjectAtlas.tsp.zip --policy policy.json
Package created and verified: ProjectAtlas.tsp.zip
  4 file(s), 125 B of content; ZIP: 4.9 KiB
  logical inventory (sha256): 20f14b885f22…
  ZIP (sha256):               fca1ecefc0b2…
  OMITTED by policy: 1 file(s), 4.0 KiB (components: commercial-sdk); hashes in integrity/external.json

$ tessel verify ProjectAtlas.tsp.zip
Status: VALID (internal integrity confirmed)
Files checked: 10
Signature: none (verification does not prove authorship).
```

`package` writes to `<output>.partial`, **verifies the bytes at the destination**, and only then renames. Any failure removes the partial file, so a package built from a failed read never exists. With `SOURCE_DATE_EPOCH` set, the ZIP itself is byte-for-byte reproducible.

### 5. Analyze a build

```text
$ tessel analyze build --source ProjectAtlas
Static analysis of build
  5 file(s), 3.1 KiB
  formats: other=2, pe=3
Unity build:
  platform: windows
  scripting backend: mono
  Editor version: 6000.3.0f1
  app.info: company=Acme Studio product=Project Atlas
  project assemblies: Assembly-CSharp.dll
Comparison with source (by name only):
  Editor version: project=6000.3.0f1 build=6000.3.0f1 -> match
  assemblies: applicable
Binaries (3):
  - Game.exe [pe x86_64 executable]
  - Game_Data/Managed/Assembly-CSharp.dll [pe x86 shared_library, managed .NET]
  - UnityPlayer.dll [pe x86_64 shared_library]
```

## Commands

| Command | What it does |
| --- | --- |
| `inspect <dir>` | Inventories a directory: file count, size, SHA-256 digest, Unity detection and warnings. |
| `check <dir>` | Dry-runs the export: per-component decisions, omissions and secret findings. Writes nothing. |
| `package <dir> -o <zip>` | Creates a verifiable TSP package. Refuses to overwrite without `--force`. |
| `verify <zip>` | Verifies a package: structure, hashes, inventory and conformance with the embedded policy. |
| `diff <a> <b>` | Compares two directories by inventory (added / removed / modified / unchanged). |
| `analyze <dir>` | Static analysis of binaries and Unity player builds, optionally against a source project (`--source`). |
| `report <zip>` | JSON report: verification, manifest summary, export decisions and known limitations. |

Common options: `--exclude <path>` (repeatable, anchored at the root: `--exclude Library` does **not** exclude `Assets/Library`), `--json` on `inspect`, `check`, `verify`, `diff` and `analyze`. Run `tessel <command> --help` for the rest.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (valid package, identical directories, no findings, export allowed). |
| `1` | Findings: integrity failure, policy violation, invalid package, differences, blocked export, read errors, analysis findings. |
| `2` | Usage or execution error (missing path, unreadable output, output already exists…). |

## The export policy

A policy maps project paths to **components**. Each file belongs to the component with the most specific matching path; files without a component inherit `default_redistribution` (default `unreviewed`).

| `redistribution` | Exported by default | Meaning |
| --- | --- | --- |
| `approved` | yes | Reviewed and cleared for sharing. Tessel warns if no license is declared. |
| `unreviewed` | yes | Nobody has decided yet. This is the default — Tessel never assumes approval. |
| `not_permitted` | **never** | Must not be redistributed. Hashes are kept in `integrity/external.json`. |

`include` (default `["approved", "unreviewed"]`) selects which states may enter a package; `not_permitted` can never be added to it. A license declared in the policy is documentation, not proof of permission — the `redistribution` field decides.

The policy used is copied byte-for-byte into the package (`policy/policy.json`) and `tessel verify` re-applies it, reporting a `policy_violation` if the package contains something its own policy forbids.

## Secret scanning

Before anything is written, every file that would be exported is scanned with linear-time regular expressions (no backtracking, safe against ReDoS):

| Severity | Examples | Effect |
| --- | --- | --- |
| High | private key blocks, AWS access key IDs, GitHub / Slack / Google tokens, sensitive files (`.pem`, `.p12`, `.jks`, `.keystore`, `.env*`, `id_rsa*`…) | blocks the export |
| Medium | generic `password` / `secret` / `api_key` assignments | blocks the export |
| Low | e-mail addresses, CPF numbers (Brazilian taxpayer ID) | reported, does not block |

`--allow-secret-findings` lets you proceed after human review; the acknowledgement is recorded in the package (`reports/export.json`). The scan reads exactly the bytes that will be packaged (checked against the inventory hash) and skips omitted components, which never leave the machine. It is a heuristic filter: **no findings does not prove there are no secrets.**

## Package format (TSP 1.0.0)

A TSP package is a ZIP file:

```text
manifest.json                 root of trust (what a future signature will cover)
integrity/files.json          path, size, sha256 of every file under source/
integrity/external.json      files omitted by the policy (path, size, sha256)
policy/policy.json            byte-for-byte copy of the applied policy
provenance/components.jsonl   one provenance record per component
reports/inventory.json        exclusions, skipped entries, warnings, Unity info
reports/export.json           per-component decisions and secret-scan summary
environments/unity.json       Unity projects only (declared values)
source/...                    the project files, relative paths with "/"
```

The manifest stores the SHA-256 of `integrity/files.json` and of every other metadata file, so there are no circular references. The JSON Schema for the manifest is in [`schemas/tsp-v1.schema.json`](schemas/tsp-v1.schema.json).

The manifest **does not claim what was not verified**: `authorization.status` is `unspecified`/`unverified`, `approved_operations` is empty, redistribution is `unreviewed` unless the policy says otherwise, and `restoration.status` is `not_tested`.

`tessel verify` reports one of four states, with this precedence: `invalid_package` (schema problems) → `failed_integrity` (hashes/counts do not match) → `policy_violation` → `valid`.

## Static analysis (`tessel analyze`)

`analyze` reads small headers only and hashes just the binaries it identifies, so it stays fast on large builds.

- **Binaries:** PE (architecture, 32/64-bit, EXE/DLL, managed .NET assembly via the CLR directory), ELF, Mach-O (including universal), DEX, WebAssembly, Java `.class`; ZIP/APK/AAB are recognized but never opened. Companion symbol files (`.pdb`, `.mdb`, `.dSYM`, `.debug`) are listed.
- **Findings:** `extension_mismatch` (e.g. a `.dll` whose header is not a PE — encrypted, packed or corrupted), `truncated_header`, `il2cpp_metadata_unrecognized`, `unity_version_mismatch`.
- **Unity builds:** platform (Windows, macOS, Linux, Android, WebGL), scripting backend (Mono vs IL2CPP), IL2CPP metadata version, Editor version (from `data.unity3d` UnityFS or `globalgamemanagers` headers), `app.info` and managed assemblies.
- **`--source`:** compares the Editor version declared by the project and the assembly names the source should produce (`Assembly-CSharp*` and runtime `.asmdef` assemblies; Editor-only and test assemblies are ignored) with what the build contains.

## Security model

- **Nothing is executed.** The crate uses no process APIs (a test scans `src/` for them), and another test plants an executable script inside a project to prove it never runs.
- **Symlinks are never followed or included**; they are recorded as skipped. Every file is opened with `O_NOFOLLOW | O_NONBLOCK`, so a file swapped for a link or FIFO between inventory and read is refused.
- **Package verification treats everything as hostile:** unsafe entry names (`..`, absolute paths, backslashes, drive letters, duplicates), symlink entries, oversized entries (ZIP bombs) and references without hash protection are rejected. Entries are streamed and never extracted. `zip` is compiled with `deflate` only.
- **Exclusions are root-anchored**, so a stray `--exclude Library` cannot silently drop `Assets/Library`. Exclusions that match nothing produce a warning.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Limitations

Being explicit about what Tessel does **not** do:

- **No signatures yet.** `verify` proves *internal* consistency. Someone who regenerates the whole package (manifest + inventory + files) passes verification. It does not prove authorship.
- **No legal assessment.** Licenses and redistribution rights are declared by you, not evaluated. Authorization is recorded, never verified by the offline CLI.
- **No restoration or build testing.** `restoration.status` stays `not_tested`.
- Unix permission bits (such as the executable flag) and empty directories are not preserved.
- Concurrent modification: content changes between inventory and copy are detected and a final-path-component swap for a symlink is refused, but replacing an *intermediate directory* with a symlink is not covered.
- `analyze` is heuristic. A recognized format does not mean a file is intact or safe; APK/AAB contents are not opened; IL2CPP builds have no managed DLLs to compare with the source; the source/build comparison is **by name only** and does not prove the source produced the build.
- Secret scanning is pattern-based and can produce false positives and false negatives.

## Development

```sh
cargo build
cargo test                                   # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The integration tests live in `crates/tessel-cli/tests/`:

- `acceptance.rs` — end-to-end CLI behaviour and TSP validation rules (tests `crit1_…` to `crit8_…` cover the eight acceptance criteria: package round-trip, flipped byte, missing file, unexpected file, symlinks, read failures, no code execution, order-independent inventory).
- `policy.rs` — export policy, omissions, `policy_violation` and secret scanning.
- `binary.rs` — `analyze` against synthetic binaries and Unity builds.

One test (`crit6`, unreadable files) relies on `chmod 000`, which has no effect when running as root; it skips itself there and the same logic is covered at library level by `crit6b`. Run the suite as a regular user to exercise it for real.

The core library is the `tessel_core` crate (`crates/tessel-cli/src/lib.rs`) and can be reused independently of the CLI. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and [CHANGELOG.md](CHANGELOG.md) for release notes.

## Project history

Tessel was previously named *OpenGame Continuity* (`ogc`, format `OGP`) and *Gamekeep* (`gk`, format `GKP`). Packages produced by those versions are not accepted by `tessel verify`; regenerate them with `tessel package`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
