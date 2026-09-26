# Findings: gaps in Semgrep's free registry, and bugs found in Scryer itself

This is a running log, kept alongside the code as Scryer is built, of every
real detection gap found in Semgrep's free/OSS rule registry (with the
custom rule written to close it) and every real bug or vulnerability found
in Scryer's own code — not hypothetical, verified by actually running the
tool, not asserted. Same standard Rampart's `docs/FINDINGS.md` holds itself
to: a security tool should verify its own claims.

Entries are newest first.

---

## 4. Scryer had never pointed a scanner at its own Go source

**Found:** Same gap as Rampart's docs/FINDINGS.md #8 — every finding above
came from testing Scryer's detection logic (does a rule fire correctly),
never from static analysis or dependency scanning of Scryer's own Go code.
Ran `govulncheck` and `gosec` for the first time.

**govulncheck:** 0 vulnerabilities reachable from Scryer's code (it has no
third-party dependencies — stdlib only). 9 vulnerabilities existed in the
Go standard library itself (`net/url`, `crypto/tls`, `net/http`,
`encoding/xml`, `encoding/asn1`, `golang.org/x/net/dns/dnsmessage`,
`golang.org/x/net/idna`) but weren't reachable from Scryer's call graph —
fixed anyway, same as Rampart, by bumping the toolchain: `go get
go@1.26.6` (auto-upgraded to `go1.26.8`).

**gosec:** 1 finding, a false positive — `internal/semgrep/semgrep.go`'s
`run()` calls `exec.CommandContext(ctx, r.BinaryPath, args...)` (G204,
"subprocess launched with a potential tainted input"). `r.BinaryPath`
defaults to `"semgrep"`; `configs` and `target` come from the `-config`
and `-target` CLI flags the operator (or their own CI job) passes at
invocation — not from scanned file content or any network input. gosec
can't distinguish operator-supplied CLI args from attacker-controlled
input, the same class of false positive as Rampart's G304 findings.
`exec.CommandContext` also passes `args` as an argv array, not through a
shell, so there's no shell-metacharacter injection surface either way.
Suppressed with an inline `#nosec G204` comment naming both reasons.

**The fix:** Toolchain bump (`go.mod`: `go 1.26` → `go 1.26.6`) and one
`#nosec`-annotated false positive. Added a `security` job to a new
`.github/workflows/ci.yml` running both scanners on every push.

**Verified:** `govulncheck ./...` → "No vulnerabilities found." `gosec
./...` → 0 issues, 1 nosec. `go build`, `go vet`, and `go test -race ./...`
all pass unchanged.

---

## 3. Only permissive CORS was a real gap for Phase 2 — and a shell bug nearly hid that

**Found:** Phase 2, scoping the Spring rule pack. The original scope
assumed seven classes needed custom rules: SpEL injection, JPA/Hibernate
query injection, disabled CSRF, permissive CORS, exposed Actuator
endpoints, insecure deserialization, and XXE. Gap-testing each against
Semgrep's free registry (same methodology as finding #1) using fixtures
under [testdata/fixtures/spring/](../testdata/fixtures/spring/) told a very
different story once it was done correctly.

**A false gap, caused by a shell bug, not a Semgrep gap:** The first sweep
built `--config` flags dynamically in a zsh loop
(`args="$args --config $c"`, then `semgrep $args ...`). Unlike bash, zsh
does not word-split an unquoted variable in a simple command's argument
list by default — `$args` was passed to semgrep as a single token
`"--config p/java"` instead of two arguments. Semgrep's argparse didn't
recognize that as `--config` at all and treated the whole string as the
scan target, failing with `Invalid scanning root` — silently reported as
zero results by a script that only checked the results count, not the
exit code or `errors` field. That false "zero coverage" reading was caught
only by re-running with literal, non-interpolated `--config` flags (no
shell variables) and cross-checking against the exit code and the
`errors` array every time — the same "verify, don't just claim" standard
applied to a script that measures a claim to verify.

**The actual, verified gap:** Redone cleanly, `p/java` + `p/security-audit`
+ `p/owasp-top-ten` + `p/secrets` combined catch six of the seven classes:
- SpEL injection and JPA/Hibernate query injection — via genuine
  **taint-mode** rules (`java.spring.security.audit.spel-injection`,
  `java.spring.security.injection.tainted-sql-string`) that track a
  `@RequestParam`/`@PathVariable` source to the sink across statements,
  not just pattern-match a single call site.
- Disabled CSRF (`java.spring.security.audit.spring-csrf-disabled`).
- XXE (`java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing`).
- Insecure deserialization
  (`java.lang.security.audit.object-deserialization`) — a deliberately
  blanket rule with no taint distinction: it flags *any*
  `ObjectInputStream.readObject()` call, including
  `InsecureDeserializationService.handleFixed()`'s fixed, non-request
  byte array, on the reasoning that a gadget-chain exploit only needs an
  exploitable classpath, not attacker-controlled bytes.
- Exposed Actuator endpoints
  (`java.spring.security.audit.spring-actuator-fully-enabled[-yaml]`,
  under `p/owasp-top-ten` specifically) — targeting both `application.yml`
  and `application.properties` (Semgrep's `languages: [yaml]` and
  `languages: [generic]` both work against Spring Boot config files,
  confirmed directly rather than assumed).

Only **permissive CORS** (`@CrossOrigin(origins = "*")` and a global
`CorsRegistry.addMapping(...).allowedOrigins("*")`) had zero hits across
every combination tried, including `--config auto`.

A second, subtler discovery from the same sweep: `--config auto` is
**not** a superset of the named packs — `p/owasp-top-ten` alone caught the
Actuator findings that a 1074-rule `--config auto` run missed entirely.
`auto` is a curated, framework-detected selection, not "everything
registered"; testing named packs individually remains necessary and
`auto` can't be used as a shortcut proxy for "the broadest possible free
coverage."

**The fix:**
- Wrote one custom rule pack, `rules/spring-permissive-cors.yaml`, with
  two rule IDs: the `@CrossOrigin` annotation form (including the array
  form with a wildcard buried among specific origins) and the global
  `CorsRegistry` form.
- Did **not** write rules for the other six classes — they're already
  covered, and duplicating them would violate the same gap-first
  discipline finding #1 established.
- Changed Scryer's own default `-config` flag from `p/java,rules/` to
  `p/java,p/security-audit,p/owasp-top-ten,rules/` in
  [cmd/scryer/main.go](../cmd/scryer/main.go): the README already claimed
  SpEL/JPA/CSRF/Actuator coverage, but the *documented default* only
  included `p/java`, which doesn't carry any of it. Without this change,
  a user following the README's own quick-start command would have gotten
  none of the coverage the README describes.

**Verified:**
- `semgrep --validate --config rules/` passes (4 rules total).
- Both CORS rule IDs fire on their vulnerable fixtures
  (`CorsConfig.java:15`, `:30`, `WebCorsConfig.java:15`) and produce zero
  false positives on the adjacent safe methods in the same files.
- `scryer -target testdata/fixtures -fail-on none` (using the new default
  config, no flags passed) reports all of: SQL injection,
  command injection, hardcoded secret, JPA taint injection, XXE,
  deserialization, CSRF-disabled, SpEL injection, and both CORS findings —
  confirming the new default actually delivers the coverage the README
  claims, not just what a hand-picked `-config` flag can produce.

---

## 2. Semgrep silently skips any directory literally named `test/` or `tests/` by default

**Found:** Phase 4, verifying `-format sarif` actually produces findings
when run against the repo. `scryer -format sarif -target test/fixtures
-config "p/java,rules/"` exited 0 with an *empty* SARIF `results` array —
no error, no warning, just zero findings for a fixture file with three
known, deliberate vulnerabilities.

**The gap:** `semgrep --verbose` on the same target reported "Files
matching .semgrepignore patterns: 1" — Semgrep ships a default
`.semgrepignore` (documented at
https://semgrep.dev/docs/ignoring-files-folders-code/#understand-semgrep-defaults)
that excludes directories named exactly `test` or `tests`, on the
assumption that test code isn't worth scanning. That's a reasonable
default for a real project's `src/test/java`, but it silently ate
Scryer's own fixture directory — and would silently eat any user's fixture
or sample directory that happens to be named `test/`, with zero
indication in the non-verbose output that anything was skipped.

Confirmed by copying the identical fixture file into a directory named
`testdata/` instead (Go's own idiomatic convention, which is *not* on
Semgrep's default-ignore list) in a throwaway git repo: same file, same
rule configs, 3 findings instead of 0.

**The fix:** Renamed `test/fixtures/` to
[testdata/fixtures/](../testdata/fixtures/VulnerableController.java)
throughout the repo. No code change needed — the fix is entirely about
which path the fixture lives at.

**Verified:** `scryer -format sarif -target testdata/fixtures -config
"p/java,rules/"` now reports 3 results (1 SQL injection from `p/java`, plus
the command-injection and hardcoded-secret findings from Scryer's own
rules) instead of 0.

---

## 1. Semgrep's full free registry misses classic Java command injection and hardcoded credentials

**Found:** Phase 1, building the core wrapper. Before writing any custom
rules, ran Semgrep against a small fixture
(`testdata/fixtures/VulnerableController.java`) containing three deliberate,
textbook vulnerabilities: SQL injection via string concatenation, command
injection via `Runtime.exec()` with concatenated input, and a hardcoded
password field.

**The gap:** Tested with increasingly broad configs — `p/java` (60 rules),
`p/owasp-top-ten` + `p/secrets` (99 rules), `p/security-audit` + `p/java` +
`p/command-injection` (88 rules), and finally `--config auto` (165 rules,
Semgrep's broadest free "Community" tier pull). **Every single one** caught
only the SQL injection (via two different rule IDs matching the same
line) — zero findings for the command injection or the hardcoded
credential, across all 165 rules in the broadest free configuration.

This isn't a criticism of Semgrep's SQL-injection coverage, which is
excellent — it's specifically that Java command-injection and
hardcoded-credential coverage in the free registry has real gaps, at least
for these textbook patterns.

**The fix:** Wrote two custom rules:
- `rules/java-command-injection.yaml` — catches string concatenation
  building a command passed to `Runtime.getRuntime().exec()`, both at the
  call site and via a local variable built one statement earlier.
- `rules/java-hardcoded-secret.yaml` — catches a field whose name matches
  `password|secret|token|apikey|credential` (case-insensitive) assigned a
  string literal of 4+ characters.

**Verified:**
- Both rules pass `semgrep --validate` (no config errors).
- Both fire correctly on the fixture: command-injection rule catches line
  16, hardcoded-secret rule catches line 20 (`DB_PASSWORD`).
- False-positive check: ran both rules against a second fixture with a
  non-secret string field (`GREETING = "hello"`), an unrelated field
  (`username`), and a **safe**, non-concatenated `exec("ls -la")` call —
  zero false positives.
- One real bug caught during this process: the hardcoded-secret rule's
  first version used `metavariable-regex` patterns anchored at the start
  of the string (Python `re.match` semantics), so `password` as a regex
  didn't match a field named `DB_PASSWORD` (the match has to start at
  position 0). Fixed by wrapping the pattern in `.*...*.` — worth knowing
  if you write `metavariable-regex` constraints expecting substring
  matching by default.
