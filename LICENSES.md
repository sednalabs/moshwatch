<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Licensing

`moshwatch` is a mixed-license repository.

## First-party code

The original code in these paths is licensed under AGPL-3.0-or-later unless a
file explicitly states otherwise:

- `crates/`
- `xtask/`
- `scripts/`
- `systemd/`
- root documentation files, unless they say otherwise

The AGPL-3.0-or-later license text is in [LICENSE](LICENSE).

## Vendored upstream code

The vendored Mosh source tree in `vendor/mosh/` is not relicensed by the
top-level repository license. It keeps the upstream notices and licenses
shipped with Mosh.

Relevant upstream files:

- [vendor/mosh/COPYING](vendor/mosh/COPYING)
- [vendor/mosh/debian/copyright](vendor/mosh/debian/copyright)
- [vendor/mosh/ocb-license.html](vendor/mosh/ocb-license.html)

## Practical release boundary (AGPL/GPL combined artifacts)

Any packaged artifact that includes `mosh-server-real` also includes upstream
Mosh code. Those artifacts must preserve the first-party AGPL terms for
`moshwatch` components and the upstream GPL-based Mosh terms, notices, and
exceptions for the vendored Mosh components.

For each binary release that includes `mosh-server-real`:

- provide corresponding source for the exact released binaries, including local
  Mosh instrumentation changes and build scripts
- include upstream Mosh license texts and notices from `vendor/mosh/`
- keep first-party AGPL notices (`LICENSE`, `NOTICE`) with the source tree and
  release metadata
- document modified upstream files and release commit references

This policy is about release packaging obligations, not automatic relicensing
of vendored upstream source files in this repository.
