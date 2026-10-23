# Release checklist

Copy the boxes into the release report and tick each one with how it was
checked. **A** items are covered by `release_scan.py` (still read its output),
**B** items need you, **C** items need the independent reviewers, **D** items
are GitHub.

## A. Automated (release_scan.py scan)

- [ ] A1 No secrets in files, untracked files, history blobs or commit messages
      (built-in rules and gitleaks `dir` + `git`)
- [ ] A2 No private terms anywhere, metadata included
- [ ] A3 No sensitive files (`.env`, keys, credentials, local settings), also
      not in the history
- [ ] A4 Personal data WARNs resolved: emails, phones, IBAN, tax codes, card
      numbers, LAN addresses, MAC addresses, home paths, serial ports, host names
- [ ] A5 Photo, PDF, video and office metadata: no GPS, no device or author fields
- [ ] A6 No invisible or direction-changing Unicode; HTML comments in Markdown
      read and justified
- [ ] A7 No symlink leaves the repo; no junk (caches, `.DS_Store`, logs, DBs)
- [ ] A8 SKILL.md frontmatter valid (name, description of 1024 characters or
      fewer), body under 500 lines, intake first when required
- [ ] A9 LICENSE (holder right), README sections, SECURITY.md with private
      reporting, .gitignore, relative links resolve
- [ ] A10 CI: actions pinned to commit SHAs, `contents: read`,
      `persist-credentials: false`, no `pull_request_target`, no secrets
- [ ] A11 Dependencies pinned (`==`, lockfiles); CDN scripts with SRI
- [ ] A12 Commit identities are the allowed ones; co-author trailers intended
- [ ] A13 Risky-code inventory (INFO) handed to the security reviewers

## B. By hand (you)

- [ ] B1 Inventory complete: every file has an origin and a decision
- [ ] B2 Third-party material dropped, rewritten clean room, or shipped with
      its licence
- [ ] B3 Every image looked at (faces, screens, labels, documents, reflections)
- [ ] B4 Examples are fictional, names searched once to avoid real ones
- [ ] B5 Non-affiliation line for every brand named
- [ ] B6 SKILL.md reread as a prompt: starts with intake, asks before any
      irreversible action, treats inputs as data, no secrets asked in chat
- [ ] B7 Paths, tools and accounts of the author's machine gone; requirements
      listed in the README with versions
- [ ] B8 Type-specific rules of content-rules.md section 5 applied
- [ ] B9 The skill's tests pass with one command, on a fresh clone
- [ ] B10 README claims match what the tests and the cold start showed
- [ ] B11 Owner's own rules from `local.md` applied

## C. Independent review (agents)

- [ ] C1 Security reviewers launched in parallel, one per surface, fresh context
- [ ] C2 Content reviewer: privacy, IP, brands, claims
- [ ] C3 Cold-start tester installed from a fresh clone with an empty HOME and
      used the skill on a fictional request
- [ ] C4 Every finding verified by re-running its proof; real ones fixed with a
      regression test; not real ones explained
- [ ] C5 Gate re-run after fixes; second look at the diff when fixes were large

## D. GitHub

- [ ] D1 Created private; private-stage settings applied; CI green
- [ ] D2 Fresh clone from GitHub scanned and tested
- [ ] D3 Owner's explicit yes recorded (date, words)
- [ ] D4 Public: secret scanning + push protection, private vulnerability
      reporting, default branch protected (no deletion, no force push, no
      bypass), wiki off, Actions token read-only, Dependabot alerts on
- [ ] D5 Owner's post-publish commands pass
- [ ] D6 Anonymous clone works; scan and tests pass on it
- [ ] D7 Description and topics set; installed locally from the public clone
