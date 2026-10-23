"""Tests for scripts/repo_settings.py with a fake `gh api`."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import repo_settings as rset  # noqa: E402

NAME = "octo/demo-skill"


class FakeGH:
    """Answers `gh api` calls from a small in-memory repo state."""

    def __init__(self, **state):
        self.s = {
            "visibility": "private", "has_wiki": True, "token": "write", "approve": True,
            "dependabot": False, "ss": "disabled", "pp": "disabled", "pvr": False,
            "rulesets": [], "classic": None,
        }
        self.s.update(state)
        self.calls = []

    def __call__(self, args, body=None):
        self.calls.append((tuple(args), body))
        method = "GET"
        a = list(args)
        if a[0] == "-X":
            method, a = a[1], a[2:]
        path = a[0]
        base = f"repos/{NAME}"
        s = self.s
        if path == base and method == "GET":
            return 0, json.dumps({
                "visibility": s["visibility"], "private": s["visibility"] == "private",
                "has_wiki": s["has_wiki"], "default_branch": "main",
                "security_and_analysis": {"secret_scanning": {"status": s["ss"]},
                                          "secret_scanning_push_protection": {"status": s["pp"]}}}), ""
        if path == base and method == "PATCH":
            if "-F" in a and "has_wiki=false" in a:
                s["has_wiki"] = False
            if body:
                sa = body["security_and_analysis"]
                s["ss"] = sa["secret_scanning"]["status"]
                s["pp"] = sa["secret_scanning_push_protection"]["status"]
            return 0, "{}", ""
        if path == base + "/actions/permissions/workflow":
            if method == "PUT":
                s["token"], s["approve"] = "read", False
                return 0, "", ""
            return 0, json.dumps({"default_workflow_permissions": s["token"],
                                  "can_approve_pull_request_reviews": s["approve"]}), ""
        if path == base + "/vulnerability-alerts":
            if method == "PUT":
                s["dependabot"] = True
                return 0, "", ""
            return (0, "", "") if s["dependabot"] else (1, "", "HTTP 404")
        if path == base + "/private-vulnerability-reporting":
            if method == "PUT":
                s["pvr"] = True
                return 0, "", ""
            return 0, json.dumps({"enabled": s["pvr"]}), ""
        if path.startswith(base + "/rulesets"):
            if method == "POST":
                rs = dict(body, id=len(s["rulesets"]) + 1)
                s["rulesets"].append(rs)
                return 0, json.dumps(rs), ""
            if path.startswith(base + "/rulesets?"):
                return 0, json.dumps([{"id": r["id"], "name": r["name"]} for r in s["rulesets"]]), ""
            rid = int(path.rsplit("/", 1)[1])
            return 0, json.dumps(next(r for r in s["rulesets"] if r["id"] == rid)), ""
        if path == base + "/branches/main/protection":
            return (0, json.dumps(s["classic"]), "") if s["classic"] else (1, "", "HTTP 404")
        return 1, "", f"unexpected {method} {path}"


def run(gh, stage, apply):
    lines = []
    code = rset.run(NAME, stage, apply, gh=gh, out=lines.append)
    return code, "\n".join(lines)


class RepoSettings(unittest.TestCase):
    def test_check_private_reports_missing_and_changes_nothing(self):
        gh = FakeGH()
        code, out = run(gh, "private", apply=False)
        self.assertEqual(code, 1)
        self.assertIn("MISSING  wiki", out)
        self.assertFalse([c for c in gh.calls if c[0][0] == "-X"], "check must not write")

    def test_apply_private_fixes_everything_but_visibility(self):
        gh = FakeGH()
        code, out = run(gh, "private", apply=True)
        self.assertEqual(code, 0, out)
        self.assertIn("FIXED    wiki", out)
        self.assertIn("FIXED    actions-token", out)
        self.assertIn("FIXED    dependabot-alerts", out)
        self.assertNotIn("secret-scanning", out)

    def test_visibility_is_never_changed(self):
        gh = FakeGH()
        code, out = run(gh, "public", apply=True)
        self.assertEqual(code, 1)
        self.assertIn("MISSING  visibility", out)
        self.assertEqual(gh.s["visibility"], "private")

    def test_apply_public(self):
        gh = FakeGH(visibility="public")
        code, out = run(gh, "public", apply=True)
        self.assertEqual(code, 0, out)
        self.assertEqual(gh.s["ss"], "enabled")
        self.assertTrue(gh.s["pvr"])
        self.assertEqual(gh.s["rulesets"][0]["rules"], [{"type": "deletion"}, {"type": "non_fast_forward"}])
        code, out = run(gh, "public", apply=False)
        self.assertEqual(code, 0, out)

    def test_ruleset_with_bypass_does_not_count(self):
        rs = dict(rset.RULESET, id=1, bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole"}])
        gh = FakeGH(visibility="public", rulesets=[rs])
        ok, detail = rset.check_branch(rset.Repo(NAME, gh), "public")
        self.assertFalse(ok)

    def test_classic_protection_counts(self):
        gh = FakeGH(visibility="public", classic={"allow_force_pushes": {"enabled": False},
                                                  "allow_deletions": {"enabled": False}})
        ok, _ = rset.check_branch(rset.Repo(NAME, gh), "public")
        self.assertTrue(ok)

    def test_bad_repo_names_rejected(self):
        for bad in ("--paginate", "octo", "octo/demo;rm", "../x/y", "octo/de mo"):
            with self.assertRaises(SystemExit):
                rset.Repo(bad, FakeGH())


if __name__ == "__main__":
    unittest.main()
