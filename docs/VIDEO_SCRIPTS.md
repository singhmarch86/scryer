# Video scripts

Outlines for you to record yourself — not videos I can produce directly.
Both are built from what's already verified in this repo. Keep them
short (5-10 min).

---

## 1. Scryer end to end — finding what the free registry misses

**Goal:** show the actual gap-discovery methodology live, not just claim
it in a README.

1. `python3 -m venv .venv && source .venv/bin/activate && pip install semgrep`
2. Open `testdata/fixtures/VulnerableController.java` on screen — point
   out the three deliberate bugs: SQL injection, command injection,
   hardcoded password.
3. Run `semgrep --config p/java testdata/fixtures/VulnerableController.java`
   directly (no Scryer yet) — show it catches the SQL injection and
   *only* the SQL injection.
4. `go build -o bin/scryer ./cmd/scryer`
5. `./bin/scryer -target testdata/fixtures/VulnerableController.java` —
   show all three findings now, including the two Semgrep's registry
   alone missed. Point at the finding messages — each names the specific
   registry gap it closes.
6. Briefly open `rules/java-command-injection.yaml` — narrate the
   pattern (concatenation into `Runtime.exec()`), and that it was
   verified both for catching the real bug and *not* flagging a safe
   `exec("ls -la")` call.

**Close:** point at `docs/FINDINGS.md` for the full methodology,
including the Spring rule pack story (video 2, if made) — most of that
scope turned out to already be covered by the registry once tested
properly.

---

## 2. SARIF upload — findings in GitHub's own Security tab

**Goal:** show the CI integration landing in a place GitHub users already
know how to use, with zero custom UI.

1. `./bin/scryer -target testdata/fixtures -format sarif -fail-on none`
   — show the raw SARIF JSON on screen briefly, point out it's Semgrep's
   own output passed through unmodified (not reformatted).
2. Open `.github/workflows/scryer.yml` — walk through the three real
   steps: install semgrep, build scryer, scan-and-upload via
   `github/codeql-action/upload-sarif@v3`.
3. Push (or show a prior run) and open the repo's **Security → Code
   scanning alerts** tab on GitHub — show the findings rendered in
   GitHub's native UI: severity, file, line, description.
4. Click into one finding — show it's the same message Scryer prints
   locally, now with GitHub's own triage controls (dismiss, track,
   assign) around it for free.

**Close:** "That's the whole point of using SARIF here — GitHub already
built a good triage UI, so Scryer's job stops at producing correct
output, not rebuilding one."
