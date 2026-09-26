# Roadmap

| Phase | Scope |
|---|---|
| 1. Core wrapper | Shell out to Semgrep, parse JSON output, CLI with text/JSON output and CI exit-code gating — **done** |
| 2. Spring rule pack | **Done** — same gap-first methodology as Phase 1, applied to seven candidate Spring vulnerability classes via fixtures under `testdata/fixtures/spring/`. Six turned out to already be covered by the free registry once tested correctly (SpEL injection, JPA/Hibernate query injection, disabled CSRF, exposed Actuator endpoints, XXE, insecure deserialization — via `p/security-audit` + `p/owasp-top-ten`, including genuine taint-mode rules for the first two). Only **permissive CORS** was a real gap, closed by `rules/spring-permissive-cors.yaml`. Scryer's default `-config` was updated to `p/java,p/security-audit,p/owasp-top-ten,rules/` so this coverage is reachable without extra flags. See [docs/FINDINGS.md #3](FINDINGS.md#3-only-permissive-cors-was-a-real-gap-for-phase-2--and-a-shell-bug-nearly-hid-that) for the full methodology, including a shell scripting bug that initially produced a false "zero coverage" reading. |
| 3. Benchmarking | Measured against [OWASP Benchmark](https://owasp.org/www-project-benchmark/) (a Java test suite built specifically to measure SAST true/false-positive rates — the SAST equivalent of GoTestWAF), gaps found and fixed, results published honestly |
| 4. CI integration | SARIF output (`-format sarif`) and a GitHub Actions workflow uploading to GitHub Code Scanning — **done**. PR comment annotations, HTML report, and a reusable public Action are separate, not-yet-started items. |
| 5. Hosted dashboard (paid tier) | Trend tracking across scans, triage workflow (mark false positive, track fixed vs. open). Same open-core model as Rampart. Not started. |

## Known limitations

- **`missing-authorization-check`-style findings aren't in scope for pure pattern matching.** Detecting "this sensitive endpoint has no `@PreAuthorize`" reliably needs a config-driven definition of what counts as sensitive — flagged honestly in the original scoping rather than overclaiming automatic coverage.
- **Scryer's own custom rules (Phase 1's command-injection/hardcoded-secret, Phase 2's permissive-CORS) are intra-procedural pattern matching, not taint tracking.** They catch the common concatenation-at-call-site and assign-then-call patterns, not arbitrary multi-hop data flow across methods. Genuine taint tracking for SpEL and JPA/Hibernate query injection is real in Scryer's default config — but it comes from Semgrep's own `p/security-audit`/`p/owasp-top-ten` registry rules, not from a rule Scryer wrote (see [docs/FINDINGS.md #3](FINDINGS.md#3-only-permissive-cors-was-a-real-gap-for-phase-2--and-a-shell-bug-nearly-hid-that)).
