# Local Source Snapshots (Private Cache)

This directory stays empty in the public repository. Third-party advisories,
CVEs, and security write-ups cited in `techniques/*.json` remain the property
of their respective authors and are not redistributed here.

When distilling new local records with `tdb distill --from <artifact> ...`,
GRAFT stages hashed copies of your local source files here under `sources/`
and records their SHA-256 digests in the generated draft's `provenance[]`.
