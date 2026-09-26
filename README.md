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
- `-format text` (default), `-format json`, or `-format sarif`.
- `-fail-on ERROR|WARNING|INFO|none` controls the exit code, for CI gating.
  With `-format sarif`, this gates on SARIF's own `error`/`warning`/`note`
  levels instead (`INFO` is accepted as an alias for `note`).

### Uploading to GitHub Code Scanning

`-format sarif` produces GitHub's native SARIF format, so findings show up
in a repo's Security tab — free triage UI, without Scryer needing to build
one. See [.github/workflows/scryer.yml](.github/workflows/scryer.yml) for a
working GitHub Actions job: it scans, uploads via
`github/codeql-action/upload-sarif@v3`, and requires `security-events:
write` permission. Adapt the `-target` in that workflow to your own
Java/Spring source when reusing it — as shipped it points at
`testdata/fixtures`, Scryer's own deliberately-vulnerable demo fixture,
since Scryer's own source is Go.

> [!NOTE]
> Semgrep skips any directory literally named `test/` or `tests/` by
> default (see [docs/FINDINGS.md](docs/FINDINGS.md) finding #2) — that's
> why Scryer's fixtures live under `testdata/`, not `test/`.

## License

Apache 2.0 — see [LICENSE](LICENSE). Same open-core intent as
[Rampart](https://github.com/gauravdeepsingh/rampart): the scanning engine
and rule pack are free and stay free; a hosted dashboard (trend tracking,
triage workflow) is planned as a paid add-on later, not required to run
the core tool.
