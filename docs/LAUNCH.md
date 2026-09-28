# Launch post drafts

Drafts only — nothing here gets posted automatically. Copy, edit to sound
like you, swap `[link]`/`[repo link]` for the real GitHub URL once
public, and post yourself.

---

## LinkedIn — why Scryer exists (the gap-discovery story)

**Body:**

Before writing a single custom rule for Scryer, I ran a test: point
Semgrep — a genuinely good, widely-used open-source static analysis
tool — at three textbook, deliberate Java vulnerabilities (SQL
injection, command injection, a hardcoded password) and see what its
free rule registry actually catches.

Tried increasingly broad configs: `p/java` (60 rules), `p/owasp-top-ten`
+ `p/secrets` (99 rules), all the way up to `--config auto` (165 rules,
the broadest free pull). Every single one caught the SQL injection.

Zero of them caught the command injection or the hardcoded credential.
Across all 165 rules in the broadest configuration.

That's not a knock on Semgrep — its SQL-injection coverage is genuinely
strong. It's specifically that Java command-injection and
hardcoded-credential detection has real, measurable gaps in the free
registry, at least for these textbook patterns. Two targeted custom
rules closed them, verified both for true positives (catches the real
bug) and false positives (doesn't flag a safe, non-concatenated `exec()`
call or an unrelated string field).

Scryer wraps Semgrep rather than reimplementing it — the value isn't a
novel detection engine, it's finding and closing the specific gaps a
proven one leaves open, and being honest about which gaps are real
versus which are already covered.

Full methodology: [link to docs/FINDINGS.md]

Open source, Apache 2.0. [repo link]

#buildinpublic #appsec #opensource #java

---

## LinkedIn — the Spring rule pack that shrank by 86% once I checked

**Body:**

Scoped Phase 2 of Scryer as 7 custom Spring-specific rules: SpEL
injection, JPA query injection, disabled CSRF, permissive CORS, exposed
Actuator endpoints, insecure deserialization, XXE.

Then — same discipline as the gap-discovery post — I tested each one
against the free Semgrep registry before writing a single rule. Turned
out 6 of the 7 were already covered, including genuine taint-mode
detection (tracking a `@RequestParam` source to a sink across statements,
not just pattern-matching) for the two hardest ones, SpEL and JPA
injection.

Only **permissive CORS** was a real gap. So that's the only custom rule
Phase 2 actually shipped.

Writing rules for the other six would have duplicated coverage that
already exists for free — the opposite of the point. Instead, I changed
Scryer's *default config* to actually include the registry packs that
carry that coverage (`p/security-audit` + `p/owasp-top-ten`), since the
gap wasn't in Semgrep's registry — it was in which packs Scryer was
recommending by default.

Side note, because it's a real gotcha: my first pass at this test gave a
false "zero coverage everywhere" reading — a zsh scripting bug (word
splitting an unquoted shell variable differently than bash does) fed
semgrep a garbled `--config` flag, and it failed silently in a way my
script misread as "no findings" instead of catching the actual error.
Redone with literal, non-interpolated flags, the real picture emerged.
Worth knowing if you're scripting gap-tests like this yourself.

[link to docs/FINDINGS.md#3]

#buildinpublic #appsec #java #spring

---

## LinkedIn — SARIF and skipping the UI nobody needed built

**Body:**

Added CI integration to Scryer this week, and the interesting decision
was what I *didn't* build: a custom findings-triage web UI.

GitHub Code Scanning already does that — for free, on any public repo —
once you upload results in SARIF format. So Scryer's Phase 4 is: a
`-format sarif` flag that passes Semgrep's own SARIF output through
unmodified (not reformatted — GitHub relies on fields a naive
round-trip would drop, like finding fingerprints for stable identity
across scans), plus a GitHub Actions workflow that scans and uploads on
every push.

The genuinely interesting bug, found by actually checking the real SARIF
output rather than trusting the schema docs: real Semgrep SARIF never
sets a result's severity level directly — it's resolved by looking up
the matching rule's `defaultConfiguration.level`. A first version of the
severity-parsing code only read the (empty) direct field, which would
have silently made `-fail-on ERROR` a no-op in CI against real output,
despite passing every test against a hand-written fixture.

Fixed once I stopped trusting a fixture I'd written myself and checked
against a real scan instead.

[link to docs/FINDINGS.md#2]

#buildinpublic #appsec #devsecops #github

---

## LinkedIn — pointing a scanner at the scanner

**Body:**

Scryer's whole job is finding vulnerabilities in other people's Java
code. Worth checking: does it have any in its own?

Ran `govulncheck` and `gosec` against Scryer's own Go source — the same
pass I'd already done for a companion project (Rampart, a firewall), for
consistency.

`govulncheck`: clean. Scryer has zero third-party dependencies, so
there's nothing to have a vulnerable dependency in. Bumped the Go
toolchain anyway to clear a handful of stdlib CVEs that existed but
weren't reachable from Scryer's code — free hardening, no reason not to.

`gosec`: one finding, and this time it was a genuine false positive
rather than a real bug — flagged the subprocess call that shells out to
`semgrep` as "tainted input." But the arguments come from Scryer's own
`-config`/`-target` CLI flags, set by whoever's running the tool, not
from scanned file content or any network input. Documented and
suppressed with an inline comment explaining exactly why, rather than
silenced with a blanket rule disable.

Both scanners now run in CI on every push.

[link to docs/FINDINGS.md#4]

#buildinpublic #appsec #golang

---

## LinkedIn — architecture thesis (not a bug post)

**Body:**

The pitch for Scryer in one sentence: don't reimplement pattern matching
or taint analysis, find and close the specific gaps a proven engine
leaves open.

Semgrep is genuinely good — its taint-mode SQL injection detection for
Java is strong, and testing confirmed most of what I'd have hand-written
as custom Spring rules (SpEL injection, JPA query injection, disabled
CSRF, exposed Actuator endpoints, XXE, insecure deserialization) is
already covered by its free registry, once you point it at the right
packs (`p/security-audit` + `p/owasp-top-ten`, not just the commonly
recommended `p/java` alone).

What Scryer actually adds is small and specific: a curated default config
that surfaces coverage the registry already has but doesn't default to,
plus a handful of custom rules for the real, verified gaps (Java command
injection, hardcoded credentials, permissive CORS) — each one tested
against the broadest free config first to confirm it's an actual gap, not
assumed.

Fortify and Checkmarx dominate enterprise Java/Spring AppSec largely
because SAST is compliance-mandated, not because anyone likes using them
— expensive, noisy, high false-positive rates. Semgrep already proved a
faster, cheaper alternative can win on the general case. Scryer's bet is
that the same approach — proven engine, targeted gap-closing, honest
about what's actually missing — wins for Spring specifically too.

[repo link]

#buildinpublic #appsec #softwarearchitecture #java

---

## LinkedIn — try it yourself

**Body:**

Scryer is a Java/Spring static analysis tool that wraps Semgrep instead
of reinventing it — closing the specific, verified gaps the free registry
leaves open (Java command injection, hardcoded credentials, permissive
CORS) rather than duplicating coverage that already exists for free.

Try it against the deliberately vulnerable fixtures in the repo:

```
git clone https://github.com/singhmarch86/scryer
cd scryer
pip install semgrep   # or pipx install semgrep
go build -o bin/scryer ./cmd/scryer
./bin/scryer -target testdata/fixtures
```

Point `-target` at your own Java/Spring source to run it for real, or
`-format sarif` to wire it into GitHub Code Scanning (`.github/workflows/scryer.yml`
in the repo is a working example, not a hypothetical one — see it run in
Actions on every push).

Every real gap this project found and closed is logged with root cause,
fix, and how it was verified — not just asserted: [link to docs/FINDINGS.md]

Open source, Apache 2.0: https://github.com/singhmarch86/scryer

#buildinpublic #appsec #opensource #java #devsecops
