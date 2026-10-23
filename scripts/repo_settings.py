#!/usr/bin/env python3
"""repo_settings: check or apply the GitHub settings a public skill repo needs.

Usage:
  repo_settings.py check OWNER/REPO --stage private|public
  repo_settings.py apply OWNER/REPO --stage private|public

Stage "private" (while the repo is still private):
  visibility private, wiki off, Actions token read-only and unable to approve
  pull requests, Dependabot alerts on.
Stage "public" (right after the switch to public), all of the above plus:
  visibility public, secret scanning and push protection on, private
  vulnerability reporting on, the default branch protected against deletion
  and force pushes (a ruleset, or an existing classic rule that does the same).

The script never changes visibility: going public is a separate, explicit
command that the owner approves (see references/github.md).
Needs: gh, logged in. Standard library only, Python 3.9 or newer.
Exit 0 when everything is OK, 1 when something is missing or failed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
RULESET_NAME = "Protect default branch"
RULESET = {
    "name": RULESET_NAME,
    "target": "branch",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
    "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
    "bypass_actors": [],
}


def find_gh():
    return shutil.which("gh") or next(
        (p for p in ("/opt/homebrew/bin/gh", "/usr/local/bin/gh") if os.path.exists(p)), "gh")


def run_gh(args, body=None):
    """Runs `gh api ...`; returns (exit code, stdout text, stderr text)."""
    cmd = [find_gh(), "api", *args]
    if body is not None:
        cmd += ["--input", "-"]
    res = subprocess.run(cmd, input=json.dumps(body).encode() if body is not None else None,
                         capture_output=True, timeout=60)
    return res.returncode, res.stdout.decode("utf-8", "replace"), res.stderr.decode("utf-8", "replace")


class Repo:
    def __init__(self, full_name, gh=run_gh):
        if not REPO_RE.match(full_name):
            raise SystemExit(f"not an OWNER/REPO name: {full_name!r}")
        self.name = full_name
        self.gh = gh
        self._info = None

    def get(self, path):
        code, out, err = self.gh([f"repos/{self.name}{path}"])
        return code, out, err

    def json(self, path):
        code, out, err = self.get(path)
        if code != 0:
            raise RuntimeError(err.strip() or f"gh api repos/{self.name}{path} failed")
        return json.loads(out or "null")

    def info(self, refresh=False):
        if self._info is None or refresh:
            self._info = self.json("")
        return self._info


# Each check returns (ok: bool, detail: str). Each fix returns nothing or raises.

def check_visibility(repo, stage):
    vis = repo.info().get("visibility") or ("private" if repo.info().get("private") else "public")
    return vis == stage, f"visibility is {vis}"


def check_wiki(repo, stage):
    on = bool(repo.info().get("has_wiki"))
    return not on, "wiki on (anyone may be able to edit it)" if on else "wiki off"


def fix_wiki(repo):
    code, _o, err = repo.gh(["-X", "PATCH", f"repos/{repo.name}", "-F", "has_wiki=false"])
    if code != 0:
        raise RuntimeError(err.strip())


def check_workflow_token(repo, stage):
    data = repo.json("/actions/permissions/workflow")
    ok = data.get("default_workflow_permissions") == "read" and not data.get(
        "can_approve_pull_request_reviews")
    return ok, (f"default token {data.get('default_workflow_permissions')}, "
                f"can approve PRs {bool(data.get('can_approve_pull_request_reviews'))}")


def fix_workflow_token(repo):
    code, _o, err = repo.gh(["-X", "PUT", f"repos/{repo.name}/actions/permissions/workflow",
                             "-f", "default_workflow_permissions=read",
                             "-F", "can_approve_pull_request_reviews=false"])
    if code != 0:
        raise RuntimeError(err.strip())


def check_dependabot(repo, stage):
    code, _o, _e = repo.get("/vulnerability-alerts")
    return code == 0, "Dependabot alerts on" if code == 0 else "Dependabot alerts off"


def fix_dependabot(repo):
    code, _o, err = repo.gh(["-X", "PUT", f"repos/{repo.name}/vulnerability-alerts"])
    if code != 0:
        raise RuntimeError(err.strip())


def check_secret_scanning(repo, stage):
    sa = repo.info(refresh=True).get("security_and_analysis") or {}
    s1 = (sa.get("secret_scanning") or {}).get("status")
    s2 = (sa.get("secret_scanning_push_protection") or {}).get("status")
    return s1 == "enabled" and s2 == "enabled", f"secret scanning {s1}, push protection {s2}"


def fix_secret_scanning(repo):
    body = {"security_and_analysis": {"secret_scanning": {"status": "enabled"},
                                      "secret_scanning_push_protection": {"status": "enabled"}}}
    code, _o, err = repo.gh(["-X", "PATCH", f"repos/{repo.name}"], body)
    if code != 0:
        raise RuntimeError(err.strip())


def check_private_reporting(repo, stage):
    data = repo.json("/private-vulnerability-reporting")
    on = bool((data or {}).get("enabled"))
    return on, "private vulnerability reporting " + ("on" if on else "off")


def fix_private_reporting(repo):
    code, _o, err = repo.gh(["-X", "PUT", f"repos/{repo.name}/private-vulnerability-reporting"])
    if code != 0:
        raise RuntimeError(err.strip())


def _ruleset_protects(rs, branch):
    if rs.get("enforcement") != "active" or rs.get("target") != "branch":
        return False
    if rs.get("bypass_actors"):
        return False
    inc = ((rs.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    if not any(p in ("~DEFAULT_BRANCH", "~ALL", f"refs/heads/{branch}") for p in inc):
        return False
    types = {r.get("type") for r in rs.get("rules") or []}
    return {"deletion", "non_fast_forward"} <= types


def check_branch(repo, stage):
    branch = repo.info().get("default_branch") or "main"
    code, out, _e = repo.get("/rulesets?includes_parents=false")
    if code == 0:
        for item in json.loads(out or "[]"):
            c2, o2, _ = repo.get(f"/rulesets/{item.get('id')}")
            if c2 == 0 and _ruleset_protects(json.loads(o2), branch):
                return True, f"{branch} protected by ruleset {item.get('name')!r}"
    code, out, _e = repo.get(f"/branches/{branch}/protection")
    if code == 0:
        prot = json.loads(out or "{}")
        if not (prot.get("allow_force_pushes") or {}).get("enabled") and not (
                prot.get("allow_deletions") or {}).get("enabled"):
            return True, f"{branch} protected by a classic rule"
    return False, f"{branch} can be deleted or force pushed"


def fix_branch(repo):
    code, _o, err = repo.gh(["-X", "POST", f"repos/{repo.name}/rulesets"], RULESET)
    if code != 0:
        raise RuntimeError(err.strip())


# (name, stages, check, fix)
CHECKS = [
    ("visibility", ("private", "public"), check_visibility, None),
    ("wiki", ("private", "public"), check_wiki, fix_wiki),
    ("actions-token", ("private", "public"), check_workflow_token, fix_workflow_token),
    ("dependabot-alerts", ("private", "public"), check_dependabot, fix_dependabot),
    ("secret-scanning", ("public",), check_secret_scanning, fix_secret_scanning),
    ("private-reporting", ("public",), check_private_reporting, fix_private_reporting),
    ("branch-protection", ("public",), check_branch, fix_branch),
]


def run(full_name, stage, apply, gh=run_gh, out=print):
    repo = Repo(full_name, gh)
    try:
        repo.info()
    except RuntimeError as exc:
        out(f"ERROR    repo {full_name}: {exc}")
        return 1
    failed = 0
    for name, stages, check, fix in CHECKS:
        if stage not in stages:
            continue
        try:
            ok, detail = check(repo, stage)
        except (RuntimeError, ValueError) as exc:
            out(f"ERROR    {name}: {exc}")
            failed += 1
            continue
        if ok:
            out(f"OK       {name}: {detail}")
            continue
        if not apply or fix is None:
            hint = " (change it with the command in references/github.md)" if fix is None else ""
            out(f"MISSING  {name}: {detail}{hint}")
            failed += 1
            continue
        try:
            fix(repo)
            repo._info = None
            ok, detail = check(repo, stage)
        except (RuntimeError, ValueError) as exc:
            out(f"ERROR    {name}: fix failed: {exc}")
            failed += 1
            continue
        out(("FIXED    " if ok else "MISSING  ") + f"{name}: {detail}")
        failed += 0 if ok else 1
    out(f"\n{full_name} ({stage}): " + ("all OK" if not failed else f"{failed} not OK"))
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="repo_settings.py", description=__doc__.split("\n")[0])
    ap.add_argument("action", choices=("check", "apply"))
    ap.add_argument("repo", help="OWNER/REPO")
    ap.add_argument("--stage", choices=("private", "public"), required=True)
    args = ap.parse_args(argv)
    return run(args.repo, args.stage, args.action == "apply")


if __name__ == "__main__":
    sys.exit(main())
