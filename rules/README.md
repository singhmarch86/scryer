# Scryer custom rules

Standard Semgrep rule YAML — same format as any Semgrep config, so these
compose with the official registry (`p/java`, etc.) via multiple `-config`
flags. See [docs/FINDINGS.md](../docs/FINDINGS.md) for what gap each rule
closes and how it was verified (both that it catches the real case, and
that it doesn't false-positive on safe code).

| Rule | Catches |
|---|---|
| `java-command-injection.yaml` | String concatenation building a command passed to `Runtime.getRuntime().exec()` |
| `java-hardcoded-secret.yaml` | A field named like a credential (`password`/`secret`/`token`/`apikey`) assigned a string literal |
| `spring-permissive-cors.yaml` | `@CrossOrigin` (including the array form) or a global `CorsRegistry.addMapping(...).allowedOrigins(...)` configured with a wildcard `"*"` origin |

**Before adding a rule, test for a real gap first.** Phase 2 originally
scoped custom rules for seven Spring vulnerability classes; six turned out
to already be covered by combining `p/java` + `p/security-audit` +
`p/owasp-top-ten` (including two genuine taint-mode rules, for SpEL and
JPA/Hibernate injection) — see
[docs/FINDINGS.md #3](../docs/FINDINGS.md#3-only-permissive-cors-was-a-real-gap-for-phase-2--and-a-shell-bug-nearly-hid-that).
The fixtures for those six classes stay in
[testdata/fixtures/spring/](../testdata/fixtures/spring/) specifically so
a future contributor can re-run them before writing a rule that would just
duplicate existing coverage. Scryer's default `-config` (in
`cmd/scryer/main.go`) includes those packs precisely so this coverage is
reachable without a custom rule.

## Validating a rule you add or change

```sh
source ../.venv/bin/activate  # or wherever your semgrep venv lives
semgrep --validate --config=rules/
semgrep --config=rules/ --json testdata/fixtures/VulnerableController.java
semgrep --config=rules/ --json testdata/fixtures/spring/
```

When gap-testing a registry config, avoid building `--config` flags from
a shell variable in a loop — a zsh word-splitting bug did exactly this and
produced a false "zero coverage" reading (see FINDINGS.md #3). Use literal,
non-interpolated `--config` flags, and always check the exit code and the
`errors` field in `--json` output, not just the results count.

Check both directions: that it fires on the vulnerable pattern it's meant
to catch, and that it doesn't fire on adjacent safe code (a rule with a 50%
false-positive rate is worse than no rule — it trains people to ignore
Scryer's output, which is exactly the Fortify/Checkmarx problem this
project exists to avoid).
