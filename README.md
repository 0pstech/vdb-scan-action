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

## What you get

- Red/green gate on the severity threshold you choose.
- Job-summary table: package, advisory link, severity, and the exact upgrade
  command (`npm install lodash@4.17.21`-style) per finding.
- Continuous monitoring without CI: register the same file once at
  <https://vdb.ai.kr/sbom-watch> and get an email when a NEW advisory lands.

## Notes

- Runners only need `python3` + `curl` (preinstalled on all GitHub-hosted images).
- Report-only mode: `fail-on: never`.
- About VDB: an AI-aware, OSV-compatible vulnerability database covering
  packages, MCP servers, AI models, and datasets — including slopsquatting
  (LLM-hallucinated package names attackers register). Docs:
  <https://vdb.ai.kr/api>. MCP server for coding agents: `uvx vdb-mcp`.

MIT license.
