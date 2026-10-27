"""harden.py against a fake `uvx`: the shell logic without the network.

The fake prints what the real CLI prints in each state and exits with the
same code, so these tests pin the contract the action relies on: manifest
pick order, the three verdicts, the error-vs-verdict distinction, the gate,
the outputs file, and the summary's ranking table.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARDEN_PY = HERE.parent / "harden.py"

ANALYZE_OPEN = textwrap.dedent("""\
    2 call site(s) with a decided dataflow path (3 path(s) in total, independently of whether any CVE exists)
    4 dependencies on the graph · 4 analysed · taint reached 2
    scope: dataflow into your dependencies …

    Project risk: 0.61
      keyless run: not stored, not watched, upgrades estimated; 2 of 3 left this hour. A free key keeps the project: VDB_API_KEY, from /v1/auth/request-key.

    * app.py:17  requests.get  [requests@2.31.0]
      - ssrf  P-abc123  OPEN
    """)

ANALYZE_CLEAN = textwrap.dedent("""\
    No risky dataflow path found.
      4 dependencies on the graph · 4 analysed
      scope: dataflow into your dependencies …
    Project risk: 0.00
    """)

ANALYZE_INCOMPLETE = textwrap.dedent("""\
    No risky dataflow path was decided.
      (3 node(s) have no summary yet — queued for building. Re-run shortly for a sharper answer.)
    Project risk: 0.10–0.60  (interval — analysis incomplete)
      Analysis is incomplete; absence is not a safety determination.
    """)

REMEDIATE_JSON = {
    "score_before": 0.61,
    "target_risk": 0.2,
    "candidates": [
        {"rank": 1, "kind": "upgrade", "estimated": True,
         "target": {"package": "requests", "from": "2.31.0", "to": "2.32.4"},
         "delta": 0.31, "cost": 0.2, "value": 0.258, "paths_closed": 2, "closed_risk": 0.7},
        {"rank": 2, "kind": "harden",
         "target": {"callsite_id": "F0000:c3", "line": 17},
         "delta": 0.12, "cost": 1.0, "value": 0.06, "paths_closed": 1},
    ],
    "combination": {"reached": True, "cumulative_cost": 1.2,
                    "steps": [{"rank": 1, "score_after": 0.3}, {"rank": 2, "score_after": 0.18}]},
    "anonymous": {"authenticated": False, "stored": False, "remaining": 1, "limit_per_hour": 3},
}

FAKE_UVX = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, sys
    args = sys.argv[1:]
    with open(os.environ["FAKE_UVX_LOG"], "a") as f:
        f.write(json.dumps({"args": args,
                            "key": os.environ.get("VDB_API_KEY"),
                            "url": os.environ.get("VDB_API_URL")}) + "\\n")
    mode = os.environ.get("FAKE_UVX_MODE", "open")
    if "--remediate" in args:
        if mode == "remediate-fails":
            sys.stderr.write("VDB API 503: {\\"detail\\": \\"retry in a minute\\"}\\n")
            sys.exit(1)
        print(json.dumps(json.loads(os.environ["FAKE_UVX_PLAN"])))
        sys.exit(0)
    if mode in ("open", "remediate-fails"):
        sys.stderr.write("Installed 30 packages in 36ms\\n")
        sys.stdout.write(os.environ["FAKE_UVX_OPEN"]); sys.exit(1)
    if mode == "clean":
        sys.stdout.write(os.environ["FAKE_UVX_CLEAN"]); sys.exit(0)
    if mode == "incomplete":
        sys.stdout.write(os.environ["FAKE_UVX_INCOMPLETE"]); sys.exit(2)
    if mode == "quota":
        sys.stderr.write("VDB API 429: {\\"detail\\": {\\"error\\": \\"anonymous_quota\\"}}\\n"); sys.exit(1)
    sys.stderr.write("cannot reach the VDB API: timed out\\n"); sys.exit(1)
    """)


class HardenStep(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="vdb-harden-"))
        self.work = self.tmp / "work"
        self.work.mkdir()
        (self.work / "requirements.txt").write_text("requests==2.31.0\n")
        bindir = self.tmp / "bin"
        bindir.mkdir()
        fake = bindir / "uvx"
        fake.write_text(FAKE_UVX)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        self.bindir = bindir
        self.log = self.tmp / "uvx.log"
        self.out = self.tmp / "output"
        self.summary = self.tmp / "summary.md"

    def run_step(self, mode: str = "open", **inputs: str) -> subprocess.CompletedProcess:
        env = {
            "PATH": f"{self.bindir}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(self.tmp),
            "GITHUB_OUTPUT": str(self.out),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "FAKE_UVX_MODE": mode,
            "FAKE_UVX_LOG": str(self.log),
            "FAKE_UVX_OPEN": ANALYZE_OPEN,
            "FAKE_UVX_CLEAN": ANALYZE_CLEAN,
            "FAKE_UVX_INCOMPLETE": ANALYZE_INCOMPLETE,
            "FAKE_UVX_PLAN": json.dumps(REMEDIATE_JSON),
            # A runner-wide token must not leak into a keyless run.
            "VDB_API_TOKEN": "vdb_runner_wide_token",
        }
        for k, v in inputs.items():
            env[f"VDB_INPUT_{k.upper()}"] = v
        return subprocess.run([sys.executable, str(HARDEN_PY)], cwd=self.work,
                              env=env, capture_output=True, text=True)

    def calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def outputs(self) -> dict[str, str]:
        if not self.out.exists():
            return {}
        return dict(line.split("=", 1) for line in self.out.read_text().splitlines())

    # ── verdicts and the gate ────────────────────────────────────────────

    def test_open_paths_fail_by_default_and_rank(self) -> None:
        proc = self.run_step("open")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("::error::VDB harden gate failed (harden-fail-on=open)", proc.stdout)
        calls = self.calls()
        self.assertEqual(len(calls), 2, "analyze, then remediate")
        self.assertEqual(calls[0]["args"][:5], ["-q", "--from", "vdb-mcp", "vdb", "harden"])
        self.assertEqual(calls[0]["args"][5:], [".", "--manifest", "requirements.txt"])
        self.assertEqual(calls[1]["args"][-4:], ["--remediate", "--target", "0.2", "--json"])
        self.assertEqual(self.outputs(), {"harden-status": "open", "harden-risk": "0.61",
                                          "harden-paths": "3"})
        # The CLI report is printed, and so is the ranking.
        self.assertIn("2 call site(s) with a decided dataflow path", proc.stdout)
        self.assertIn("upgrade requests 2.31.0 → 2.32.4 (estimated)", proc.stdout)
        md = self.summary.read_text()
        self.assertIn("## VDB harden", md)
        self.assertIn("**Status:** open — 3 decided path(s)", md)
        self.assertIn("| 1 | upgrade requests 2.31.0 → 2.32.4 (estimated) | 0.31 | 0.20 | 0.258 | 2 (mass 0.7) |", md)
        self.assertIn("| 2 | harden call site F0000:c3 line 17 |", md)
        self.assertIn("Combination: #1 → 0.30, #2 → 0.18  (reaches the target; 2 step(s), cost 1.20)", md)
        self.assertIn("<details><summary>Full report</summary>", md)
        self.assertNotIn("Installed 30 packages", md)
        self.assertNotIn("Installed 30 packages", proc.stdout)

    def test_open_paths_with_fail_on_never_pass(self) -> None:
        proc = self.run_step("open", harden_fail_on="never")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("::error::", proc.stdout)
        self.assertEqual(self.outputs()["harden-status"], "open")

    def test_clean_costs_one_call(self) -> None:
        proc = self.run_step("clean")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(len(self.calls()), 1, "no ranking when nothing is open")
        self.assertEqual(self.outputs(), {"harden-status": "clean", "harden-risk": "0.00",
                                          "harden-paths": "0"})
        self.assertIn("**Status:** clean", self.summary.read_text())

    def test_incomplete_passes_on_open_fails_on_incomplete(self) -> None:
        proc = self.run_step("incomplete")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.outputs()["harden-status"], "incomplete")
        self.assertEqual(self.outputs()["harden-risk"], "0.10–0.60")
        self.assertEqual(len(self.calls()), 1)

        proc = self.run_step("incomplete", harden_fail_on="incomplete")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("harden-fail-on=incomplete", proc.stdout)

    # ── errors are not verdicts ──────────────────────────────────────────

    def test_quota_exhausted_is_an_error_with_the_key_hint(self) -> None:
        # Same exit code as "open paths"; the missing report sentence tells them apart.
        proc = self.run_step("quota", harden_fail_on="never")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("keyless allowance", proc.stdout)
        self.assertIn("api-key:", proc.stdout)
        self.assertEqual(self.outputs()["harden-status"], "error")
        self.assertEqual(len(self.calls()), 1, "no ranking after a refused analysis")

    def test_network_failure_is_an_error(self) -> None:
        proc = self.run_step("network")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::vdb harden did not complete (exit 1): cannot reach the VDB API", proc.stdout)
        self.assertEqual(self.outputs()["harden-status"], "error")

    def test_ranking_failure_keeps_the_verdict(self) -> None:
        proc = self.run_step("remediate-fails", harden_fail_on="never")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("::warning::the remediation ranking could not be fetched", proc.stdout)
        self.assertEqual(self.outputs()["harden-status"], "open")
        self.assertNotIn("Remediation ranking", self.summary.read_text())

    # ── inputs ───────────────────────────────────────────────────────────

    def test_key_is_passed_and_keyless_note_otherwise(self) -> None:
        proc = self.run_step("clean", api_key="vdb_test_key", api_url="https://vdb.example.test/")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        call = self.calls()[0]
        self.assertEqual(call["key"], "vdb_test_key")
        self.assertEqual(call["url"], "https://vdb.example.test")
        self.assertNotIn("keyless", proc.stdout)
        self.assertNotIn("Keyless run", self.summary.read_text())

        self.summary.unlink()
        proc = self.run_step("clean")
        self.assertIsNone(self.calls()[-1]["key"])
        self.assertIn("keyless run (3 analyses an hour per address, nothing stored)", proc.stdout)
        self.assertIn("Keyless run: 3 analyses an hour per address", self.summary.read_text())

    def test_keyless_summary_quotes_remaining_allowance(self) -> None:
        self.run_step("open", harden_fail_on="never")
        self.assertIn("This address: 2 of 3 left this hour.", self.summary.read_text())

    def test_manifest_pick_order(self) -> None:
        (self.work / "sbom.cdx.json").write_text("{}")
        (self.work / "poetry.lock").write_text("")
        proc = self.run_step("clean")
        self.assertIn("auto-detected manifest for hardening: poetry.lock", proc.stdout)
        self.assertEqual(self.calls()[0]["args"][-1], "poetry.lock")

        (self.work / "uv.lock").write_text("")
        self.run_step("clean")
        self.assertEqual(self.calls()[-1]["args"][-1], "uv.lock")

        for name in ("uv.lock", "poetry.lock", "requirements.txt"):
            (self.work / name).unlink()
        self.run_step("clean")
        self.assertEqual(self.calls()[-1]["args"][-1], "sbom.cdx.json")

        (self.work / "sbom.cdx.json").unlink()
        (self.work / "pyproject.toml").write_text("[project]\nname='x'\n")
        proc = self.run_step("clean")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::no manifest for hardening", proc.stdout)
        self.assertEqual(len(self.calls()), 3, "nothing was run")

    def test_explicit_manifest_path_and_target(self) -> None:
        sub = self.work / "svc"
        sub.mkdir()
        (sub / "uv.lock").write_text("")
        proc = self.run_step("open", harden_manifest="svc/uv.lock", harden_path="svc",
                             harden_target="0.05", harden_fail_on="never")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.calls()
        self.assertEqual(calls[0]["args"][5:], ["svc", "--manifest", "svc/uv.lock"])
        self.assertEqual(calls[1]["args"][-3:], ["--target", "0.05", "--json"])

        proc = self.run_step("open", harden_manifest="missing.lock")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::harden-manifest not found: missing.lock", proc.stdout)

    def test_invalid_inputs_are_rejected_before_any_call(self) -> None:
        proc = self.run_step("open", harden_fail_on="sometimes")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("invalid harden-fail-on", proc.stdout)
        proc = self.run_step("open", harden_target="1.5")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("invalid harden-target", proc.stdout)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
