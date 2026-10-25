# GitHub steps

All commands use `gh`, logged in as the owner. `OWNER/NAME` is the repo.

## Create, private

```bash
cd "$STAGING"
gh repo create "OWNER/NAME" --private --source . --push --description "One line: what the skill does"
```

If the push dies with "unexpected disconnect", raise the buffer and push again:
`git config http.postBuffer 157286400 && git push -u origin main`.

```bash
python3 "$SKILL/scripts/repo_settings.py" apply "OWNER/NAME" --stage private
run=$(gh run list -R "OWNER/NAME" --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run" -R "OWNER/NAME" --exit-status
```

`--exit-status` makes a red run exit non-zero. If the list is empty, the run
has not started yet: wait a few seconds and list again.

On free plans, rulesets, secret scanning and private vulnerability reporting
are only available on public repos; that is why they are in the public stage.

Fresh clone check (what GitHub holds is what goes public):

```bash
tmp=$(mktemp -d) && gh repo clone "OWNER/NAME" "$tmp/c" -- --quiet
python3 "$SKILL/scripts/release_scan.py" scan "$tmp/c"
(cd "$tmp/c" && <the skill's test command>)
```

## Go public (only after the owner's yes)

```bash
gh repo edit "OWNER/NAME" --visibility public --accept-visibility-change-consequences
python3 "$SKILL/scripts/repo_settings.py" apply "OWNER/NAME" --stage public
python3 "$SKILL/scripts/repo_settings.py" check "OWNER/NAME" --stage public
python3 "$SKILL/scripts/repo_settings.py" post-publish
```

Run the visibility change as its own command (not inside a script): some
owners have hooks that watch for exactly this command. It needs a `gh` recent
enough to know `--accept-visibility-change-consequences` (`gh repo edit --help`
lists it).

What the public stage sets: secret scanning and push protection; private
vulnerability reporting; a ruleset "Protect default branch" that blocks
deletion and force pushes on the default branch with no bypass (direct pushes
and PR merges still work; an existing classic branch rule counts only if it
also applies to admins); wiki off (on public repos it can be open to edits);
Actions token read-only and unable to approve PRs; Dependabot alerts.

Stricter rules (required PRs, required checks, signed commits) block the
owner's direct pushes: add them only if the owner asks.

Anonymous check, no credentials at all:

```bash
tmp=$(mktemp -d)
env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 \
  git -c credential.helper= clone --quiet "https://github.com/OWNER/NAME" "$tmp/anon"
python3 "$SKILL/scripts/release_scan.py" scan "$tmp/anon"
```

Topics and description:

```bash
gh repo edit "OWNER/NAME" --add-topic claude-code --add-topic claude-skills --add-topic agent-skills
```

## If something leaked after going public

1. Make the repo private again at once:
   `gh repo edit "OWNER/NAME" --visibility private --accept-visibility-change-consequences`
   (ask the owner first, but ask fast).
2. Rotate any secret immediately: assume it was copied. Forks and caches keep
   old content even after a history rewrite.
3. Rewrite the history or recreate the repo from a clean staging copy, only
   with the owner's explicit yes (force pushes are blocked by the ruleset on
   purpose: the owner lifts it).
