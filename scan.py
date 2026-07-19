"""VDB SBOM scan — GitHub Action entrypoint.

Stdlib-only (python3 is preinstalled on every GitHub runner); the multipart
upload itself is delegated to `curl`, which is also preinstalled and saves us
hand-rolling MIME boundaries. Writes a findings table to the job summary,
exposes counts as step outputs, and exits non-zero when the `fail-on`
threshold is met.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

CANDIDATES = [
    "sbom.cdx.json", "bom.json", "sbom.json", "sbom.spdx.json",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile.lock", "pyproject.toml",
    "go.sum", "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock",
    "pubspec.lock",
]

BUCKET_ORDER = ["critical", "high", "medium", "low"]


def log(msg: str) -> None:
    print(msg, flush=True)


def error(msg: str) -> None:
    # ::error:: renders as a red annotation on the workflow run.
    print(f"::error::{msg}", flush=True)


def write_outputs(pairs: dict[str, object]) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as f:
        for k, v in pairs.items():
            f.write(f"{k}={v}\n")


def write_summary(md: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(md + "\n")


def pick_file() -> str:
    explicit = (os.environ.get("VDB_INPUT_FILE") or "").strip()
    if explicit:
        if not os.path.isfile(explicit):
            error(f"input file not found: {explicit}")
            sys.exit(1)
        return explicit
    for c in CANDIDATES:
        if os.path.isfile(c):
            log(f"auto-detected dependency file: {c}")
            return c
    error(
        "no dependency file found — set the `file:` input. Looked for: "
        + ", ".join(CANDIDATES)
    )
    sys.exit(1)


def scan(path: str) -> tuple[int, dict]:
    api = (os.environ.get("VDB_INPUT_API_URL") or "https://vdb.ai.kr").rstrip("/")
    key = (os.environ.get("VDB_INPUT_API_KEY") or "").strip()
    cmd = ["curl", "-sS", "-w", "\n%{http_code}", "-F", f"file=@{path}",
           f"{api}/v1/sbom/scan"]
    if key:
        cmd[1:1] = ["-H", f"Authorization: Bearer {key}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        error(f"could not reach VDB at {api}: {proc.stderr.strip()[:300]}")
        sys.exit(1)
    body, _, status_line = proc.stdout.rpartition("\n")
    try:
        status = int(status_line.strip())
    except ValueError:
        error(f"unexpected response from VDB: {proc.stdout[:300]}")
        sys.exit(1)
    try:
        data = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError:
        data = {"raw": body[:500]}
    return status, data


def main() -> None:
    path = pick_file()
    status, data = scan(path)

    if status in (401, 429):
        detail = data.get("detail") if isinstance(data, dict) else None
        detail = detail if isinstance(detail, dict) else {}
        if detail.get("error") == "free_trial_exhausted":
            error(
                "VDB free trial exhausted for this runner's IP (GitHub runners "
                "share IP pools, so this happens fast for anonymous calls). "
                "Fix: create a free API key at https://vdb.ai.kr/signup, store "
                "it as a repo secret, and pass it via the `api-key:` input."
            )
        else:
            error(f"VDB rejected the request (HTTP {status}): "
                  f"{json.dumps(detail)[:300]}")
        sys.exit(1)
    if status != 200:
        error(f"VDB scan failed (HTTP {status}): {json.dumps(data)[:300]}")
        sys.exit(1)

    summary = data.get("summary") or {}
    findings = data.get("vulnerabilities") or []
    counts = {b: int(summary.get(b, 0)) for b in BUCKET_ORDER}
    kev = int(summary.get("kev", 0))

    write_outputs({
        **counts,
        "kev": kev,
        "components_matched": data.get("components_matched", 0),
    })

    # Console + job-summary report
    log(f"VDB scan of {path} ({data.get('sbom_format')}): "
        f"{data.get('components_total')} components, "
        f"{data.get('components_matched')} with advisories — "
        + ", ".join(f"{b}: {counts[b]}" for b in BUCKET_ORDER)
        + f", KEV: {kev}")

    md = [
        "## VDB SBOM scan",
        "",
        f"**File:** `{path}` ({data.get('sbom_format')}) · "
        f"**Components:** {data.get('components_total')} · "
        f"**With advisories:** {data.get('components_matched')}",
        "",
        "| Severity | Count |",
        "|---|---|",
        *(f"| {b} | {counts[b]} |" for b in BUCKET_ORDER),
        f"| KEV (exploited in the wild) | {kev} |",
    ]
    if findings:
        md += ["", "| Package | Advisory | Severity | Fix |", "|---|---|---|---|"]
        for f in findings[:15]:
            rem = (f.get("remediation") or {}).get("command") \
                  or (", ".join(f.get("fixed_in") or []) or "—")
            ver = f" @ {f.get('version')}" if f.get("version") else ""
            md.append(
                f"| `{f.get('purl')}{ver}` "
                f"| [{f.get('id')}](https://vdb.ai.kr/vuln/{f.get('id')}) "
                f"| {f.get('severity_bucket')}{' · KEV' if f.get('kev') else ''} "
                f"| `{rem}` |"
            )
        if len(findings) > 15:
            md.append(f"\n…and {len(findings) - 15} more — "
                      f"see https://vdb.ai.kr/sbom-scan")
    write_summary("\n".join(md))

    # Threshold gate
    fail_on = (os.environ.get("VDB_INPUT_FAIL_ON") or "high").strip().lower()
    if fail_on == "never":
        return
    if fail_on not in BUCKET_ORDER:
        error(f"invalid fail-on value: {fail_on!r} "
              f"(use critical|high|medium|low|never)")
        sys.exit(1)
    gated = BUCKET_ORDER[: BUCKET_ORDER.index(fail_on) + 1]
    tripped = {b: counts[b] for b in gated if counts[b] > 0}
    if tripped:
        error(
            "VDB gate failed (fail-on=" + fail_on + "): "
            + ", ".join(f"{v} {k}" for k, v in tripped.items())
            + ". Fix commands are in the job summary."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
