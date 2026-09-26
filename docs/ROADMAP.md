# Roadmap

| Phase | Scope |
|---|---|
| 1. Core wrapper | Shell out to Semgrep, parse JSON output, CLI with text/JSON output and CI exit-code gating — **done** |
| 2. Spring rule pack | Deeper custom rules: SpEL injection, JPA/Hibernate query injection, disabled CSRF, permissive CORS, exposed Actuator endpoints, insecure deserialization, XXE — validated against a real vulnerable Spring app |
| 3. Benchmarking | Measured against [OWASP Benchmark](https://owasp.org/www-project-benchmark/) (a Java test suite built specifically to measure SAST true/false-positive rates — the SAST equivalent of GoTestWAF), gaps found and fixed, results published honestly |
| 4. CI integration | SARIF output (`-format sarif`) and a GitHub Actions workflow uploading to GitHub Code Scanning — **done**. PR comment annotations, HTML report, and a reusable public Action are separate, not-yet-started items. |
| 5. Hosted dashboard (paid tier) | Trend tracking across scans, triage workflow (mark false positive, track fixed vs. open). Same open-core model as Rampart. Not started. |

## Known limitations

- **`missing-authorization-check`-style findings aren't in scope for pure pattern matching.** Detecting "this sensitive endpoint has no `@PreAuthorize`" reliably needs a config-driven definition of what counts as sensitive — flagged honestly in the original scoping rather than overclaiming automatic coverage.
- **Custom rule pack is intra-procedural pattern matching, not full taint tracking** as of Phase 1. Command-injection/SpEL-injection rules catch the common concatenation-at-call-site and assign-then-call patterns, not arbitrary multi-hop data flow across methods. Semgrep OSS's taint mode could extend this in Phase 2 for genuine Spring request-parameter sources (`@RequestParam`, `HttpServletRequest.getParameter()`) flowing to sinks.
