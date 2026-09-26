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

## 1. Semgrep's full free registry misses classic Java command injection and hardcoded credentials

**Found:** Phase 1, building the core wrapper. Before writing any custom
rules, ran Semgrep against a small fixture
(`test/fixtures/VulnerableController.java`) containing three deliberate,
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
