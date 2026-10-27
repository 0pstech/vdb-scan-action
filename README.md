# VDB SBOM Scan — GitHub Action

Scan your lockfile or SBOM against **[VDB](https://vdb.ai.kr)** on every push:
known CVEs, slopsquatting, CISA KEV — with copy-pasteable fix commands in the
job summary. One step, no install.

```yaml
# .github/workflows/vdb.yml
name: VDB scan
on: [push, pull_request]
jobs:
  vdb:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 0pstech/vdb-scan-action@v1
        with:
          api-key: ${{ secrets.VDB_API_KEY }}   # free at https://vdb.ai.kr/signup
```

The dependency file is auto-detected (`package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`, `requirements.txt`, `go.sum`, `Cargo.lock`, `Gemfile.lock`,
`composer.lock`, CycloneDX/SPDX SBOMs, …).

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `file` | *(auto-detect)* | Path to the SBOM / dependency file |
| `api-key` | — | `vdb_…` key. **Recommended**: anonymous calls share the runner IP pool's small lifetime trial |
| `fail-on` | `high` | Fail at/above this severity: `critical` / `high` / `medium` / `low` / `never` |
| `api-url` | `https://vdb.ai.kr` | Self-hosted VDB origin |
| `harden` | `false` | Also run call-site hardening on Python code — see below |
| `harden-manifest` | *(auto-detect)* | Lockfile / SBOM for the hardening graph |
| `harden-path` | `.` | Source tree (or one file) to analyze |
| `harden-target` | `0.2` | Project risk the fix combination should get under |
| `harden-fail-on` | `open` | `open` / `incomplete` / `never` |

## Outputs

`critical`, `high`, `medium`, `low`, `kev`, `components-matched` — use them in
later steps:

```yaml
      - uses: 0pstech/vdb-scan-action@v1
        id: vdb
        with:
          api-key: ${{ secrets.VDB_API_KEY }}
          fail-on: never                 # report-only mode
      - if: steps.vdb.outputs.kev != '0'
        run: echo "::warning::KEV finding — patch before release"
```

## Call-site hardening (`harden: true`)

The SBOM scan says which packages have advisories. Hardening answers the
question behind it for Python projects: **can attacker-controlled data
actually reach a dangerous sink through your dependencies?** It runs the
published CLI (`uvx --from vdb-mcp vdb harden`) on the runner, decides the
taint paths, scores the project, and ranks what to fix first. Your source
never leaves the runner as text — the CLI ships an abstracted IR (call
sites and dataflow, literals masked); `vdb harden . --emit-ir` prints
exactly what is sent.

```yaml
# .github/workflows/vdb.yml
name: VDB scan + harden
on: [push, pull_request]
jobs:
  vdb:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 0pstech/vdb-scan-action@v1
        with:
          api-key: ${{ secrets.VDB_API_KEY }}   # optional — see "Keyless" below
          harden: true
          harden-manifest: uv.lock              # omit to auto-detect
          harden-target: 0.2
          harden-fail-on: open
```

| Input | Default | Meaning |
|---|---|---|
| `harden` | `false` | Turn the hardening step on |
| `harden-manifest` | *(auto-detect)* | The lockfile / SBOM the dependency graph is resolved from. Empty = the first of `uv.lock`, `poetry.lock`, `requirements.txt`, `*.cdx.json` in the workspace root. A lockfile gives the sharpest answer; a flat `requirements.txt` works but carries no transitive edges |
| `harden-path` | `.` | Source tree (or one file) to analyze — set it in a monorepo |
| `harden-target` | `0.2` | Project risk (0–1) the ranked combination of fixes should get under |
| `harden-fail-on` | `open` | `open`: fail when a decided dataflow path is open · `incomplete`: also fail when the analysis could not decide the paths (missing summaries) · `never`: report only |

What happens on the runner:

1. `uv` is set up with [`astral-sh/setup-uv`](https://github.com/astral-sh/setup-uv)
   (falls back to `pip install uv` on runners where that step is skipped).
2. `uvx --from vdb-mcp vdb harden <path> --manifest <manifest>` runs and
   its output is printed in full. Its exit code is the verdict:
   `0` clean, `1` open paths, `2` incomplete (nothing could be decided —
   absence is not a safety determination).
3. When paths are open, a second call with `--remediate --target <target>`
   fetches the ranking — each candidate (upgrade a package, harden a call
   site, remove a package) with its risk reduction, cost, and the paths it
   closes, plus the cheapest combination that reaches the target. The
   ranking lands in the job summary. A clean run makes one call, not two.
4. The check fails per `harden-fail-on`. A refused or unreachable call is
   reported as an error (status `error`), never as a verdict.

Outputs: `harden-status` (`clean` / `open` / `incomplete` / `error`),
`harden-risk` (the project score, an interval when incomplete) and
`harden-paths` (open decided paths):

```yaml
      - uses: 0pstech/vdb-scan-action@v1
        id: vdb
        with:
          harden: true
          harden-fail-on: never                # report-only
      - if: steps.vdb.outputs.harden-status == 'open'
        run: echo "::warning::${{ steps.vdb.outputs.harden-paths }} open dataflow path(s), risk ${{ steps.vdb.outputs.harden-risk }}"
```

**Keyless.** The hardening endpoints answer without a key on a per-address
allowance: 3 analyses an hour and 10 a day per address, projects up to
200 dependencies, nothing stored, upgrades estimated rather than
re-composed. The step summary says when a run was keyless and how much of
the hour's allowance is left. GitHub-hosted runners share address pools,
so a busy repository will hit the allowance — a free key
(`api-key:` input, <https://vdb.ai.kr/signup>) lifts it, keeps the
project so it is re-scored when a package on a path changes, and signs
the verification evidence.

Scope: dataflow into your dependencies, plus your own standard-library
calls that run commands, deserialize, decompress or open connections.
File paths and regular expressions in your own code are not examined —
use a static analyser for those. Python only for now.

## What you get

- Red/green gate on the severity threshold you choose.
- Job-summary table: package, advisory link, severity, and the exact upgrade
  command (`npm install lodash@4.17.21`-style) per finding.
- Continuous monitoring without CI: register the same file once at
  <https://vdb.ai.kr/sbom-watch> and get an email when a NEW advisory lands.

## Notes

- Runners only need `python3` + `curl` (preinstalled on all GitHub-hosted images);
  `harden: true` adds `uv`, installed by the action itself.
- Report-only mode: `fail-on: never`.
- About VDB: an AI-aware, OSV-compatible vulnerability database covering
  packages, MCP servers, AI models, and datasets — including slopsquatting
  (LLM-hallucinated package names attackers register). Docs:
  <https://vdb.ai.kr/api>. MCP server for coding agents: `uvx vdb-mcp`.
- This repository's own CI (`.github/workflows/test.yml`) runs the step's
  logic against a fake CLI (`tests/test_harden.py`) and the whole action
  on the example project under `tests/fixture/`.

## License

[Elastic License 2.0](https://www.elastic.co/licensing/elastic-license) —
free to use, including inside commercial organizations and CI. The only
restrictions: you may not offer this software to third parties as a hosted
or managed service, or resell it as a product. Beyond that:
<dev@egdee.com>.
