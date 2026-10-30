# Dependency review (2026-10-30)

This is a point-in-time dependency assessment, not a claim that the product has
no vulnerabilities. Re-run the scanners on the final release commit.

## Remediated in the lockfile

- `tokio` 1.54.0 matched RUSTSEC-2026-0384 (Interval race). Updated to the patched
  1.54.1 with Cargo. The native build and both package runtime tests passed in
  https://github.com/KAIKAIKAISER/Sandboxie/actions/runs/41049659514 (commit 4787ecf).
- Cargo also re-resolved a small number of existing dependency edges while
  updating the lockfile; the resulting graph was checked with `cargo tree --locked`.

## Remaining RustSec warnings

`cargo-audit` 0.22.2 completed with no vulnerability errors and five informational
warnings: `glib` 0.18.5 (RUSTSEC-2024-0429, unsound), `proc-macro-error` 1.0.4
(RUSTSEC-2024-0370, unmaintained), `zbus_names` 4.3.5 (RUSTSEC-2026-0371),
`zvariant` 5.15.1 (RUSTSEC-2026-0370), and `zvariant_derive` 5.15.1
(RUSTSEC-2026-0372; the last three are unmaintained).

Each returned no reverse dependencies for the current
`x86_64-pc-windows-msvc` graph. They remain in the cross-platform Tauri lockfile;
this is not evidence that Linux builds are safe or that the upstream issues are
fixed. Do not offer Linux packages without re-evaluating them. No advisory ignore
list or warning-suppression flag was added. CI preserves scanner output and the
Windows graph for continuing review. A successful scan can still contain these
informational warnings; review them rather than equating exit code zero with a
clean report.

## Additional OSV match requiring scope review

OSV also matched GHSA-qwgh-2vcv-g2f7 against `block-buffer` 0.10.4. The advisory
describes an inline cursor overwritten during an unwinding panic in EagerBuffer
or ReadBuffer. The 0.10.4 source stores `pos: u8` separately from the block and
does not have that ReadBuffer API; the release profile also uses panic=abort.
This is a scope discrepancy to track, not a verified exploit in DiskGuard and
not a claim that all older block-buffer versions are patched. A blanket major
version override of a transitive crypto dependency was not introduced.

References:
- https://rustsec.org/advisories/RUSTSEC-2026-0384
- https://rustsec.org/advisories/RUSTSEC-2024-0429
- https://github.com/advisories/GHSA-qwgh-2vcv-g2f7
- https://github.com/RustCrypto/utils/blob/block-buffer-v0.10.4/block-buffer/src/lib.rs

## Frontend and scanner tooling

The updated frontend lockfile reports zero npm audit findings at this date.
Browser regression tooling is lockfile-pinned rather than installed ad hoc in
CI. RustSec client 0.22.2 is pinned because 0.21.2 cannot parse current CVSS 4.0
database entries. A scanner database parse/network failure must fail the job,
not be mistaken for an empty vulnerability report.
