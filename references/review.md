# Independent review

The author of a change cannot review it impartially, and you have just spent
an hour making this skill look clean. The reviewers start fresh, see only the
staging copy and their own prompt, and work in parallel.

## Splitting the security work

Read the INFO inventory from the scan (`runs-commands`, `network`,
`html-from-strings`, `recursive-delete`, `sudo`) and the file list. Give each
reviewer one surface; skip surfaces the skill does not have; merge small ones.

| Surface | What it covers |
| --- | --- |
| Inputs and files | parsers of user files (images, SVG, PDF, JSON, archives), path traversal, symlinks, size limits, writes outside the output folder, module import hijack from the working folder |
| Generated output | HTML, SVG, Markdown and reports built from user or web text: injection, CDN scripts, local servers |
| Commands and network | subprocess and shell use, downloads, API calls, keys handling, TLS, what leaves the machine |
| The prompt | SKILL.md and references as instructions to Claude: prompt injection paths (files, pages, tool output the skill reads), irreversible actions without a yes, over-broad permissions, secrets asked in chat, hidden text |

Two reviewers is the minimum for Complete: the prompt surface always gets its
own reviewer; the rest can share one.

## Launching

- One message, all agents at once, `subagent_type: general-purpose`.
- Each prompt is the file from `agents/` with the placeholders filled:
  `{{STAGING}}` (absolute path), `{{SCRATCH}}` (a new empty folder for that
  agent), `{{SKILL_SUMMARY}}` (two sentences you write), and per agent:
  `{{SURFACE}}` and `{{INVENTORY}}` (the INFO lines for that surface) for
  security reviewers; `{{TERMS_FILE}}` (path of the owner's private terms) and
  `{{SCANNER}}` (absolute path of `scripts/release_scan.py`) for the content
  reviewer; `{{SAMPLE_REQUEST}}` (a fictional user request) for the tester.
- Do not paste your own conclusions or the scan output into the prompts,
  except the INFO inventory lines for the security reviewer of that surface.
  Reviewers that know what you already checked look where you looked.
- Reviewers never push, open issues, post, or write inside `{{STAGING}}`.
  They copy it into their scratch folder to try exploits there.

## What comes back, and what you do with it

Each reviewer returns findings with: severity (Critical, High, Medium, Low),
file and line, what an attacker or a stranger does, a proof (command, input
file or exact steps), and a suggested fix.

For each finding:
1. Re-run the proof yourself. A finding you cannot reproduce is not real until
   shown otherwise; write down why.
2. Real: fix it, add a regression test that fails before the fix, re-run the
   proof to show it no longer works.
3. Record finding, verdict, fix and test in the report.

After the fixes, run the whole gate again. If the fixes touched more than a few
lines or any security logic, launch one more security reviewer with the diff
(`git diff <before>..HEAD`) and the same rules.

## Cold-start test, what "works for a stranger" means

The tester clones the staging repo into a temp folder, sets `HOME` to an empty
temp folder for every command it runs, follows only the README, runs the tests
and the documented example, then reads SKILL.md and plays through one
fictional request end to end. Anything that needed the author's machine (a
path, a tool not listed, a login, a file outside the repo) is a finding.
