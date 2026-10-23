# Launch extras

Only the extras chosen at intake. Each one that writes to something public
needs the owner's yes before it happens.

## README cross-links

1. List the owner's other public skill repos:
   `gh repo list OWNER --visibility public --limit 100 --json name,description`
   and keep the ones that are skills (a SKILL.md at the root).
2. In each local clone, add the new skill to the "More skills" list, same
   format as the existing lines: `- [name](https://github.com/OWNER/REPO): one line`.
   Add the other skills to the new repo's README too.
3. Show the owner the list of repos and the one-line diff, ask once for the
   whole batch.
4. For each repo: tests, `release_scan.py scan`, commit, push; then
   `repo_settings.py check OWNER/REPO --stage public`.

## X post draft

- A draft only, saved next to the report. Never posted by you.
- Follow the owner's style guide named in `local.md` if there is one.
  Otherwise: one opening line with what the skill does for the reader, three
  short points (what you ask it, what you get, what it never does), the repo
  link, at most 280 characters per post.
- Every claim in the post must be true of the published repo (tests count,
  formats, requirements). Nothing private, no client names, no numbers you
  cannot point to.
- An infographic is optional: a simple HTML page rendered to PNG, with a
  fictional example and the repo URL.

## 9:16 short

Hand off to the video skill or the shorts engine named in `local.md`, with:
the repo name and URL, a two-sentence pitch, three beats (problem, what the
skill does, the safety point), and the end-card link. The video is a draft
until the owner approves it.
