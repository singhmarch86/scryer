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

## Validating a rule you add or change

```sh
source ../.venv/bin/activate  # or wherever your semgrep venv lives
semgrep --validate --config=rules/
semgrep --config=rules/ --json testdata/fixtures/VulnerableController.java
```

Check both directions: that it fires on the vulnerable pattern it's meant
to catch, and that it doesn't fire on adjacent safe code (a rule with a 50%
false-positive rate is worse than no rule — it trains people to ignore
Scryer's output, which is exactly the Fortify/Checkmarx problem this
project exists to avoid).
