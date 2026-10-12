# Security Policy

Tessel parses untrusted input (packages, manifests, binary headers, project files) and is meant to be run on material you do not fully trust, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") on this repository, or contact the maintainers privately.

Helpful details: the Tessel version (`tessel --version`), the command you ran, and a minimal sample (a crafted package or file) if you can share one.

We aim to acknowledge reports within a few days.

## In scope

- Code execution or process spawning triggered by inspected content.
- Reading or copying files outside the inspected root (symlink or path-traversal escapes).
- Panics, unbounded memory or CPU use on crafted packages, manifests or binary headers.
- A package that `tessel verify` reports as valid although its contents violate its own inventory or embedded policy.
- Secret values leaking into reports, packages or terminal output.

## Out of scope (known limitations)

- Tessel packages are **not signed**; `verify` proves internal consistency, not authorship.
- The secret scanner is heuristic and can miss secrets.
- Replacing an intermediate directory with a symlink while a package is being created is not covered.

See the "Limitations" section of the README for the full list.
