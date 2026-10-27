"""VDB call-site hardening — GitHub Action step (`harden: true`).

Stdlib-only, like scan.py. The analysis itself is the published CLI
(`uvx --from vdb-mcp vdb harden`); this file only picks the manifest, runs
it, reads the verdict, and turns the ranking into a job summary.

The CLI is run at most twice. The first run decides the taint paths and
scores the project; its exit code is the gate (0 clean, 1 open paths,
2 incomplete — nothing decided). Only when paths are open does the second
run (`--remediate --target … --json`) fetch the ranked remediation list.
A clean run therefore costs one keyless analysis, not two.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys

# Lockfiles first (they carry the resolved graph), a flat requirements file
# next, an SBOM last. pyproject.toml is deliberately absent: it has no
# resolved versions and the VDB parser rejects it.
MANIFEST_ORDER = ["uv.lock", "poetry.lock", "requirements.txt"]
FAIL_ON = ("open", "incomplete", "never")
# -q keeps uv's own install chatter ("Downloading cryptography…") out of
# the report; the CLI's stdout is the report, stderr is only for errors.
CLI = ["-q", "--from", "vdb-mcp", "vdb", "harden"]

# What the CLI prints in each state; the exit code alone is not enough,
# because a rejected request (`raise SystemExit("VDB API 429: …")`) also
# exits 1. Without one of these markers the run is an error, not a verdict.
MARK_OPEN = "with a decided dataflow path"
MARK_INCOMPLETE = "No risky dataflow path was decided"
MARK_CLEAN = "No risky dataflow path found"


def log(msg: str) -> None:
    print(msg, flush=True)


def error(msg: str) -> None:
    print(f"::error::{msg}", flush=True)


def warning(msg: str) -> None:
    print(f"::warning::{msg}", flush=True)


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


def env_input(name: str, default: str = "") -> str:
    return (os.environ.get(f"VDB_INPUT_{name}") or default).strip()


# ── inputs ──────────────────────────────────────────────────────────────────

def pick_manifest(explicit: str, root: str = ".") -> str:
    if explicit:
        if not os.path.isfile(explicit):
            error(f"harden-manifest not found: {explicit}")
            sys.exit(1)
        return explicit
    for name in MANIFEST_ORDER:
        p = os.path.normpath(os.path.join(root, name))
        if os.path.isfile(p):
            log(f"auto-detected manifest for hardening: {p}")
            return p
    cdx = sorted(os.path.normpath(p) for p in glob.glob(os.path.join(root, "*.cdx.json")))
    if cdx:
        log(f"auto-detected manifest for hardening: {cdx[0]}")
        return cdx[0]
    error(
        "no manifest for hardening — set the `harden-manifest:` input. Looked for: "
        + ", ".join(MANIFEST_ORDER) + ", *.cdx.json"
    )
    sys.exit(1)


def parse_target(raw: str) -> float:
    try:
        t = float(raw or "0.2")
    except ValueError:
        error(f"invalid harden-target: {raw!r} (a risk between 0 and 1, e.g. 0.2)")
        sys.exit(1)
    if not 0.0 <= t <= 1.0:
        error(f"invalid harden-target: {raw!r} (a risk between 0 and 1, e.g. 0.2)")
        sys.exit(1)
    return t


def parse_fail_on(raw: str) -> str:
    v = (raw or "open").lower()
    if v not in FAIL_ON:
        error(f"invalid harden-fail-on: {raw!r} (use open|incomplete|never)")
        sys.exit(1)
    return v


# ── tooling ─────────────────────────────────────────────────────────────────

def ensure_uvx() -> str:
    """astral-sh/setup-uv normally put `uvx` on PATH already; this is the
    fallback for self-hosted runners that skipped it."""
    found = shutil.which("uvx")
    if found:
        return found
    log("uvx not on PATH — installing uv with pip")
    proc = subprocess.run([sys.executable, "-m", "pip", "install", "--user", "--quiet", "uv"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        error("could not install uv: " + proc.stderr.strip()[:300]
              + " — add a `uses: astral-sh/setup-uv@v10` step before this action.")
        sys.exit(1)
    user_bin = os.path.join(os.path.expanduser("~"), ".local", "bin")
    found = shutil.which("uvx") or shutil.which("uvx", path=user_bin)
    if not found:
        error("uv installed but `uvx` is still not on PATH; "
              "add a `uses: astral-sh/setup-uv@v10` step before this action.")
        sys.exit(1)
    return found


def run_cli(uvx: str, args: list[str], env: dict[str, str]) -> tuple[int, str, str]:
    """Run the CLI, return (exit code, stdout, stderr)."""
    cmd = [uvx, *CLI, *args]
    log("$ uvx " + " ".join(CLI + args))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env,
                              timeout=float(os.environ.get("VDB_HARDEN_STEP_TIMEOUT", "900")))
    except subprocess.TimeoutExpired:
        return 124, "", "the CLI did not finish in time"
    return proc.returncode, proc.stdout, proc.stderr


def last_line(*texts: str) -> str:
    for t in reversed(texts):
        if t.strip():
            return t.strip().splitlines()[-1]
    return ""


# ── reading the text report ─────────────────────────────────────────────────

RISK_RE = re.compile(r"^Project risk: ([0-9.]+(?:[–-][0-9.]+)?)", re.M)
PATHS_RE = re.compile(r"\((\d+) path\(s\) in total", re.M)
KEYLESS_RE = re.compile(r"(\d+ of \d+ left this hour)")


def classify(code: int, text: str) -> str:
    """0/1/2 from the CLI, confirmed by the sentence it prints for that
    state. Anything else — a 429, a dead network, a bad manifest — is an
    error, which is a different thing from a verdict."""
    if code == 0 and MARK_CLEAN in text:
        return "clean"
    if code == 1 and MARK_OPEN in text:
        return "open"
    if code == 2 and MARK_INCOMPLETE in text:
        return "incomplete"
    return "error"


def risk_of(text: str) -> str:
    m = RISK_RE.search(text)
    return m.group(1) if m else ""


def paths_of(text: str) -> int:
    m = PATHS_RE.search(text)
    return int(m.group(1)) if m else 0


def keyless_note(text: str) -> str:
    m = KEYLESS_RE.search(text)
    return m.group(1).strip() if m else ""


# ── the ranking ─────────────────────────────────────────────────────────────

def fmt_risk(x) -> str:
    if isinstance(x, list) and len(x) == 2:
        return f"{x[0]:.2f}–{x[1]:.2f}"
    try:
        return f"{float(x):.2f}"
    except (TypeError, ValueError):
        return "n/a"


def action_label(c: dict) -> str:
    """Same wording as the CLI's own table, minus the file map (the JSON
    output carries call-site ids, not file names)."""
    t = c.get("target") or {}
    k = c.get("kind")
    if k == "upgrade":
        if t.get("from"):
            what = f"upgrade {t.get('package')} {t.get('from')} → {t.get('to')}"
        else:
            what = f"pin {t.get('package')} at {t.get('to')}"
        if c.get("coverage_gain"):
            what += " (unlocks analysis)"
        elif c.get("estimated"):
            what += " (estimated)"
        return what
    if k == "harden":
        if t.get("callsite_id"):
            line = f" line {t['line']}" if t.get("line") else ""
            return f"harden call site {t['callsite_id']}{line}"
        n = len(t.get("callsites") or [])
        if t.get("sink_class"):
            return f"harden all {n} call sites reaching {t['sink_class']}"
        return f"harden {n} call sites into {t.get('package')}"
    if k == "remove":
        return f"remove {t.get('package')}"
    return f"{t.get('policy')} on {t.get('sink_class')} sinks"


def ranking_lines(plan: dict, limit: int = 12) -> list[str]:
    """Console rendering of the ranking: what the CLI prints for --remediate."""
    cands = plan.get("candidates") or []
    lines = [f"Remediation ranking — risk {fmt_risk(plan.get('score_before'))}, "
             f"target {fmt_risk(plan.get('target_risk'))}"]
    if not cands:
        lines.append("  nothing to rank: no open path.")
        return lines
    lines.append(f"  {'#':>2}  {'action':<52} {'Δrisk':>9} {'cost':>5} {'value':>6}  closes")
    for c in cands[:limit]:
        delta = c.get("delta_interval") or c.get("delta")
        closes = f"{c.get('paths_closed', 0)}"
        if c.get("closed_risk"):
            closes += f" (mass {c['closed_risk']:.1f})"
        lines.append(f"  {c.get('rank', 0):>2}  {action_label(c)[:52]:<52} {fmt_risk(delta):>9} "
                     f"{c.get('cost', 0):>5.2f} {c.get('value', 0):>6.3f}  {closes}")
    if len(cands) > limit:
        lines.append(f"  … {len(cands) - limit} more candidate(s)")
    lines.extend(combination_lines(plan))
    return lines


def combination_lines(plan: dict) -> list[str]:
    combo = plan.get("combination") or {}
    steps = combo.get("steps") or []
    if not steps:
        return []
    head = steps[:6]
    chain = ", ".join(f"#{s.get('rank')} → {fmt_risk(s.get('score_after'))}" for s in head)
    if len(steps) > 6:
        chain += f", … {len(steps) - 6} more step(s) → {fmt_risk(steps[-1].get('score_after'))}"
    mark = "reaches" if combo.get("reached") else "does not reach"
    return [f"  Combination: {chain}  ({mark} the target; {len(steps)} step(s), "
            f"cost {combo.get('cumulative_cost', 0):.2f})"]


def ranking_md(plan: dict, limit: int = 12) -> list[str]:
    cands = plan.get("candidates") or []
    md = [f"**Remediation ranking** — risk {fmt_risk(plan.get('score_before'))}, "
          f"target {fmt_risk(plan.get('target_risk'))}", ""]
    if not cands:
        md.append("Nothing to rank: no open path.")
        return md
    md += ["| # | Action | Δrisk | Cost | Value | Closes |", "|---|---|---|---|---|---|"]
    for c in cands[:limit]:
        delta = c.get("delta_interval") or c.get("delta")
        closes = f"{c.get('paths_closed', 0)}"
        if c.get("closed_risk"):
            closes += f" (mass {c['closed_risk']:.1f})"
        md.append(f"| {c.get('rank', 0)} | {action_label(c)} | {fmt_risk(delta)} "
                  f"| {c.get('cost', 0):.2f} | {c.get('value', 0):.3f} | {closes} |")
    if len(cands) > limit:
        md.append(f"\n…and {len(cands) - limit} more — run "
                  f"`uvx --from vdb-mcp vdb harden . --remediate` locally for the full list.")
    combo = combination_lines(plan)
    if combo:
        md += ["", combo[0].strip()]
    return md


# ── main ────────────────────────────────────────────────────────────────────

def main() -> None:
    manifest = pick_manifest(env_input("HARDEN_MANIFEST"))
    path = env_input("HARDEN_PATH", ".")
    if not os.path.exists(path):
        error(f"harden-path not found: {path}")
        sys.exit(1)
    target = parse_target(env_input("HARDEN_TARGET", "0.2"))
    fail_on = parse_fail_on(env_input("HARDEN_FAIL_ON", "open"))
    key = env_input("API_KEY")
    api = env_input("API_URL", "https://vdb.ai.kr").rstrip("/")

    env = dict(os.environ)
    env["VDB_API_URL"] = api
    if key:
        env["VDB_API_KEY"] = key
    else:
        # The CLI would also fall back to VDB_API_TOKEN from the runner's
        # environment; the action's own input is the only key it honours.
        env.pop("VDB_API_KEY", None)
        env.pop("VDB_API_TOKEN", None)
        log("no api-key input: keyless run (3 analyses an hour per address, nothing stored)")

    uvx = ensure_uvx()

    # 1. decide + score; the exit code is the verdict
    base = [path, "--manifest", manifest]
    code, report, err = run_cli(uvx, base, env)
    if report:
        print(report, end="" if report.endswith("\n") else "\n", flush=True)
    status = classify(code, report)

    if status == "error":
        write_outputs({"harden-status": "error", "harden-risk": "", "harden-paths": 0})
        if err.strip():
            print(err, end="" if err.endswith("\n") else "\n", flush=True)
        tail = last_line(report, err) or f"exit code {code}"
        if "VDB API 429" in report + err:
            error("VDB refused the hardening call: the keyless allowance for this "
                  "runner's address is used up (GitHub runners share address pools). "
                  "Fix: create a free key at https://vdb.ai.kr/signup, store it as a "
                  "repo secret, and pass it via the `api-key:` input.")
        else:
            error(f"vdb harden did not complete (exit {code}): {tail[:300]}")
        write_summary("\n".join([
            "## VDB harden", "",
            f"**Status:** error · **Manifest:** `{manifest}`", "",
            "```", (report + err).strip()[-3000:], "```",
        ]))
        sys.exit(1)

    risk = risk_of(report)
    n_paths = paths_of(report)
    write_outputs({"harden-status": status, "harden-risk": risk, "harden-paths": n_paths})

    # 2. only an open path has something to rank
    plan: dict | None = None
    if status == "open":
        rcode, rout, rerr = run_cli(uvx, base + ["--remediate", "--target", str(target), "--json"], env)
        try:
            plan = json.loads(rout) if rcode == 0 else None
        except json.JSONDecodeError:
            plan = None
        if plan is None:
            warning("the remediation ranking could not be fetched: "
                    + (last_line(rout, rerr)[:200] or f"exit {rcode}"))
        else:
            print("\n".join(ranking_lines(plan)), flush=True)

    # 3. job summary
    label = {"clean": "clean — no decided path",
             "open": f"open — {n_paths} decided path(s)",
             "incomplete": "incomplete — nothing decided; absence is not a safety determination"}[status]
    head = [
        "## VDB harden",
        "",
        f"**Status:** {label} · **Project risk:** {risk or 'n/a'} · "
        f"**Manifest:** `{manifest}` · **Gate:** `harden-fail-on: {fail_on}`",
    ]
    if not key:
        left = keyless_note(report)
        head += ["", "Keyless run: 3 analyses an hour per address, nothing stored, upgrades "
                     "estimated. A free key (`api-key:` input, https://vdb.ai.kr/signup) "
                     "keeps the project and lifts the allowance."
                     + (f" This address: {left}." if left else "")]
    md = head + [""]
    if plan is not None:
        md += ranking_md(plan) + [""]
    md += ["<details><summary>Full report</summary>", "", "```", report.strip()[-6000:], "```",
           "", "</details>"]
    write_summary("\n".join(md))

    # 4. gate
    if fail_on == "never":
        return
    if status == "open":
        error(f"VDB harden gate failed (harden-fail-on={fail_on}): {n_paths} decided "
              "dataflow path(s) are open. The ranked fixes are in the job summary.")
        sys.exit(1)
    if status == "incomplete" and fail_on == "incomplete":
        error("VDB harden gate failed (harden-fail-on=incomplete): the analysis could "
              "not decide the paths — re-run shortly, or widen the manifest.")
        sys.exit(2)


if __name__ == "__main__":
    main()
