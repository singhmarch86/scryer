# Scryer

A Java/Spring-focused static analysis (SAST) tool. Scryer wraps
[Semgrep](https://semgrep.dev) (the official Java rule packs) with a
custom Spring-specific rule pack and a CI-friendly CLI — it doesn't
reimplement pattern matching or taint analysis, Semgrep is the proven
engine for that.

## Why

Fortify and Checkmarx dominate enterprise Java/Spring AppSec because SAST
is often compliance-mandated — not because anyone enjoys using them.
They're expensive and infamous for high false-positive rates. Semgrep
proved a faster, cheaper, lower-noise alternative can win; Scryer applies
that same approach specifically to Spring's own vulnerability patterns
(SpEL injection, JPA native query injection, disabled CSRF, exposed
Actuator endpoints, ...) that generic rule packs don't cover deeply.

## Status

Early development. See [docs/ROADMAP.md](docs/ROADMAP.md) and
[docs/FINDINGS.md](docs/FINDINGS.md) for real gaps found in Semgrep's free
registry and the custom rules that close them — verified by actually
running scans, not asserted.

## Quick start

Requires Python 3 and Semgrep (`pip install semgrep`, or use a venv — see
below). Scryer itself is a Go binary that shells out to `semgrep`.

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install semgrep

go build -o bin/scryer ./cmd/scryer
./bin/scryer -target /path/to/your/java/project -config "p/java,rules/"
```

- `-config` is a comma-separated list of Semgrep `--config` values: Semgrep
  registry names (`p/java`, `p/owasp-top-ten`, ...) and/or local paths
  (`rules/` for Scryer's own Spring-specific pack).
- `-format text` (default) or `-format json`.
- `-fail-on ERROR|WARNING|INFO|none` controls the exit code, for CI gating.

## License

Apache 2.0 — see [LICENSE](LICENSE). Same open-core intent as
[Rampart](https://github.com/gauravdeepsingh/rampart): the scanning engine
and rule pack are free and stay free; a hosted dashboard (trend tracking,
triage workflow) is planned as a paid add-on later, not required to run
the core tool.
