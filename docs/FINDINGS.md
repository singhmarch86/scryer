# Findings: gaps found in Semgrep's free registry, and the custom rules that close them

This is a running log, kept alongside the code as Scryer is built, of every
real detection gap found in Semgrep's free/OSS rule registry — not
hypothetical, verified by actually running Semgrep against real vulnerable
code — along with the custom rule written to close it and how that rule
was itself verified (both that it catches the real case and that it
doesn't false-positive on safe code). Same standard Rampart's
`docs/FINDINGS.md` holds itself to: a security tool should verify its own
claims, not just assert them.

Entries are newest first.

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
