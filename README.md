# skill-release

A Claude Code skill that takes one of your skills from a private folder to a
**public GitHub repo** without leaking anything, and without shipping
something that only works on your machine.

It is built around one rule: **nothing becomes public until every check is
green and you say yes** to the go / no-go question, after reading the release
report. Asking it to "publish" starts the process; it is not that yes.

> **Independent project.** Not affiliated with or endorsed by Anthropic,
> GitHub or the gitleaks project.

## What it does

1. **Asks first**: which skill, what inside it is private or not yours, how
   deep the review should be, which launch extras you want.
2. **Builds a clean staging copy** with a fresh git history (your private
   history never ships), drops caches and local files, and lists every file
   with its origin and a keep / rewrite / drop decision.
3. **Makes it public-grade**: real data becomes fictional, other people's
   material is dropped or rewritten from scratch, LICENSE, README,
   SECURITY.md, .gitignore and a pinned CI workflow come from templates.
4. **Runs an automated gate** (`scripts/release_scan.py`) on the files, the
   whole history and the commit messages: secrets, your private terms,
   personal data, photo / PDF / video / office metadata (GPS included),
   invisible Unicode that can hide instructions, symlinks leaving the repo,
   unpinned CI actions, SKILL.md limits, licence and README checks, plus
   gitleaks when installed.
5. **Sends it to independent reviewers**: 4 to 6 fresh agents that never saw
   your work, in parallel (this costs time and usage; a Light mode uses one). Security reviewers try real exploits per attack surface
   (inputs, generated output, commands and network, and the SKILL.md prompt
   itself); a content reviewer checks privacy, licences, brands and claims;
   a cold-start tester installs the skill from a clone with a scratch `HOME`
   and uses it like a stranger. Code from the reviewed skill runs through
   `scripts/run_isolated.py`: no shell, an empty environment, a scratch `HOME`,
   no SSH agent or tokens. That is isolation, not a sandbox. Every finding is reproduced before it is
   fixed, and gets a regression test.
6. **Creates the repo private**, applies the private-stage settings, waits for
   CI, and re-scans a fresh clone from GitHub.
7. **Writes a release report** and asks you: go public or not yet.
8. **Only after your yes**: switches to public, turns on secret scanning and
   push protection, private vulnerability reporting, default branch
   protection (no deletion, no force push), wiki off, read-only Actions token,
   Dependabot alerts, and checks an anonymous clone.
9. **Installs** the released skill from its permanent clone (replacing an
   installed one only if you say so, with a dated backup).
10. Optional launch extras: links in the README of your other skills (pushed
   only after you approve the list), an X post draft, a short video brief.
   Drafts only: nothing is posted for you.

## Install

```bash
git clone https://github.com/Matteoikarieth96/skill-release-skill ~/.claude/skills/skill-release
```

Requirements:

- Python 3.9 or newer (standard library only). Tested on macOS and Linux.
- `git` 2.28 or newer (for `git init -b`) and `rsync`.
- The GitHub CLI `gh`, logged in to your account (the intake already checks the
  repo name with it), recent enough to have
  `gh repo edit --accept-visibility-change-consequences`.
- [gitleaks](https://github.com/gitleaks/gitleaks): the scan FAILs without it
  unless you pass `--no-gitleaks` (the built-in secret rules are a subset).

## Your private settings

Personal settings live outside any repo, in `~/.claude/skill-release/`
(or `$SKILL_RELEASE_HOME`). Create them once:

```bash
mkdir -p ~/.claude/skill-release
cp ~/.claude/skills/skill-release/templates/config.example.json ~/.claude/skill-release/config.json
touch ~/.claude/skill-release/private-terms.txt
```

- `config.json`:
  - `github_owner`, `copyright_holder`: your GitHub name.
  - `author_identities`: the exact `Name <email>` your commits may carry; any
    other identity in the history is a FAIL. Edit the example line: for
    GitHub's private address use `<id>+<name>@users.noreply.github.com`, where
    `gh api user --jq .id` prints your numeric id.
  - `allowed_emails`: addresses that may appear in files (all others WARN).
  - `banned_text`: strings you never want in public copy (WARN).
  - `require_intake`: WARN when a skill does not start by asking questions.
  - `projects_dir`, `reports_dir`, `skills_dir`: where staging copies, release
    reports and installed skills live.
  - `post_publish_commands`: your own checks after going public, each a list
    of arguments, for example `[["python3", "~/bin/my_guard.py", "--check"]]`.
- `private-terms.txt`: names and strings that must never appear in a public
  repo (people, clients, private repo names, your Wi-Fi name, device serials),
  one per line, every spelling you use (`Acme Rossi`, `acme-rossi`,
  `ACME_ROSSI`). Any hit is a FAIL. Without this file the scan says so with a
  WARN.
- `local.md`: your own rules for Claude, read at the start of every release.
  It can add or tighten rules, never relax the hard ones.

## Usage

In Claude Code:

> Make my beer-label skill open source.

> Rendi open source la mia skill delle ricette.

The scanner also works alone:

```bash
python3 ~/.claude/skills/skill-release/scripts/release_scan.py scan path/to/staging
python3 ~/.claude/skills/skill-release/scripts/release_scan.py strip path/to/staging/docs/hero.jpg
python3 ~/.claude/skills/skill-release/scripts/repo_settings.py check OWNER/REPO --stage public
python3 ~/.claude/skills/skill-release/scripts/run_isolated.py /tmp/scratch --cwd path/to/staging -- python3 -m unittest discover -s tests
```

`scan` exits 1 on any FAIL (`--strict` also on WARN), `--json` for machine
output, `--no-history` and `--no-gitleaks` to skip those parts. `strip`
rewrites the files **in place**: run it on the staging copy, naming each file
(a shell glob that matches nothing stops zsh before the script runs).

## Security

The scanner reads untrusted folders: it never follows symlinks, never runs
code from the scanned repo, refuses to run git in a folder whose `.git` config
is not plain, runs gitleaks so that the repo cannot silence it, reads text
hidden under media extensions, in UTF-16 or behind NUL bytes, caps file and
history sizes, guards its image, PDF and archive parsers against malformed and
oversized input, prints file names and messages as single clean lines, and
masks every secret it prints. `strip`
writes atomically and refuses symlinks. `repo_settings.py` validates the repo
name, touches only that repo and never changes its visibility. Details and
residual risks: [SECURITY.md](SECURITY.md).

## Limitations

- Pattern scanning finds known shapes of secrets and personal data, not every
  possible one. The reviewers and your own reading of each file are part of
  the process for that reason.
- Metadata stripping covers JPEG and PNG; other formats are reported and must
  be re-exported.
- The review agents need Claude Code's Agent tool. Without it, Claude works
  through each reviewer prompt itself and writes in the report that the
  review was not independent.
- Isolation is a scratch `HOME`, not a sandbox. To release a skill written by
  someone else, run the cold-start test on a machine or VM you can throw away.
- The GitHub settings assume a personal account on github.com.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite plants secrets, private terms, photos with GPS, hidden Unicode,
symlinks, unpinned CI, history-only leaks and bad commit identities, and
checks that each is caught; it also checks that this repo passes its own scan.

## More skills

- [evm-dd](https://github.com/Matteoikarieth96/evm-dd-skill): investor-angle due diligence on crypto and EVM projects, with a scored report and an A4 one-pager
- [hiring-prep](https://github.com/Matteoikarieth96/hiring-prep-skill): an interview prep page from a company, a role and your resume, with an interactive test
- [whiteboard-video](https://github.com/Matteoikarieth96/whiteboard-video-skill): hand-drawn whiteboard explainer videos with voice-over
- [3d-print-design](https://github.com/Matteoikarieth96/3d-print-design-skill): parametric parts for FDM 3D printing, checked before export
- [beer-can-label](https://github.com/Matteoikarieth96/beer-can-label-skill): print-ready beer can labels with a 3D preview
- [ai-privacy-check](https://github.com/Matteoikarieth96/ai-privacy-check-skill): privacy and AI rules check for a concrete use case (Italian)
- [claude-time-is-relative](https://github.com/Matteoikarieth96/claude-time-is-relative): time estimates for Claude Code tasks from your own past sessions

## Licence

MIT, see [LICENSE](LICENSE).
