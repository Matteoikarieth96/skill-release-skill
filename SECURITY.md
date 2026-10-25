# Security

## Threat model

- **The scanned folder is untrusted.** It may be a skill written by someone
  else, with files built to crash or mislead the scanner: malformed or huge
  images, PDFs and archives, text hidden under a media extension, UTF-16 or
  NUL bytes, symlinks and FIFOs, file names that forge report lines, a `.git`
  folder with hostile configuration, gitleaks configuration meant to silence
  it, commit messages with control characters.
- **The skill under review is a prompt.** Its SKILL.md, frontmatter,
  references and any file it ships can carry instructions aimed at Claude or
  at the reviewer agents (in plain text, HTML comments, invisible Unicode,
  file names, test output or CI logs).
- **The owner's settings** (`~/.claude/skill-release/`) are sensitive and are
  themselves a target: rewriting `local.md`, `config.json` or the private terms
  would change what the next release checks and which commands run.
- **GitHub changes** are irreversible in practice once a repo is public:
  forks and caches keep content.

## Mitigations

| Risk | Mitigation | File |
| --- | --- | --- |
| Reading your files through symlinks or blocking on FIFOs | Every read opens with `O_NOFOLLOW` and `O_NONBLOCK` and checks for a regular file; symlinks are reported (FAIL when they leave the repo), special files are reported, the non-git walk does not follow links | `scripts/release_scan.py` (`read_regular`, `scan_tree`, `list_files`) |
| Text hidden from the scan | Any file is text-scanned unless it is a recognised binary format; UTF-16 and UTF-32 (with or without BOM) are decoded; NUL bytes do not stop a text scan; files with text extensions are always read as text; binary files are still searched for secrets and long private terms; unknown binaries are a WARN, archives a FAIL | `scripts/release_scan.py` (`decode_text`, `looks_text`, `scan_bytes`, `scan_media`) |
| Office documents | Every XML part of OOXML and ODF files is scanned, tags removed so split words join again; parts and totals are size-capped and unreadable parts reported | `scripts/release_scan.py` (`scan_zip`) |
| Photo, PDF and video metadata | JPEG segments are walked through and after the scans; Exif and XMP anywhere in the file are found; data after the end of the image is reported; PNG private chunks and trailing data are reported; PDF hex strings are decoded and Flate streams inflated (capped) | `scripts/release_scan.py` (`jpeg_walk`, `scan_jpeg`, `scan_png`, `scan_pdf`) |
| Hostile media and archives | Bounds-checked walkers, entry counts capped, decompression capped, per-file errors turned into a FAIL instead of a crash | `scripts/release_scan.py` (`parse_tiff`, `_inflate`, `scan_tree`, `scan`) |
| Hostile `.git` | Before any git command, `.git` must be a plain folder whose config holds only known safe keys (read with `git config --file --no-includes`); otherwise git is never run there and the scan FAILs. git runs with argument lists, `core.fsmonitor=false`, `log.showSignature=false`, no system config, no inherited `GIT_*` variables; commits are read as raw objects, not through `git log` | `scripts/release_scan.py` (`git_config_problem`, `git`, `git_env`, `cat_file_batch`, `parse_commit`) |
| Silencing gitleaks | gitleaks runs with an explicit default config, an empty ignore path and `--ignore-gitleaks-allow`, on a copy that leaves out `.gitleaks*` files; those files and allow comments are reported; a missing gitleaks is a FAIL unless `--no-gitleaks` is passed | `scripts/release_scan.py` (`run_gitleaks`, `check_name`) |
| Forged or unreadable output | Every path and message printed is made single-line, printable and truncated; file names with control or invisible characters are a FAIL | `scripts/release_scan.py` (`print_report`, `clean`, `check_name`) |
| Invisible Unicode | FAIL on every format character (bidi controls, zero-width, tags), line and paragraph separators, variation selectors outside an emoji, invisible fillers, ESC and C1 controls; WARN on private-use and unassigned characters; emoji sequences stay allowed | `scripts/release_scan.py` (`hidden_chars`) |
| Slow-input attacks | Bounded regular expressions, line numbers from a cached index, size caps on workflows and documents | `scripts/release_scan.py` |
| Secrets shown in the report | Only the first 4 characters, the length and a 6-hex fingerprint are printed; email local parts are cut; gitleaks runs with `--redact` | `scripts/release_scan.py` (`mask`, `scan_text`, `run_gitleaks`) |
| Permissions shipped to every user | Frontmatter `hooks` and Claude Code settings, hooks or MCP files are a FAIL; `allowed-tools` and other frontmatter keys are a WARN | `scripts/release_scan.py` (`check_skill`, `check_name`) |
| Metadata stripping damaging files or leaving data | Atomic write in the same folder, symlinks refused, rotated JPEGs refused unless `--force`; JPEG: every APPn except JFIF, ICC and Adobe, every comment and anything after EOI removed, and the result is checked for leftover Exif or XMP; PNG: only standard chunks kept | `scripts/release_scan.py` (`strip_jpeg`, `strip_png`, `strip_file`, `atomic_write`) |
| Argument injection into gh | The repo name must fully match `OWNER/REPO` (no `.` or `..`); gh is called with argument lists; bodies go through stdin; a ruleset that excludes branches or allows bypass does not count as protection, nor a classic rule that admins bypass | `scripts/repo_settings.py` (`REPO_RE`, `run_gh`, `_ruleset_protects`, `check_branch`) |
| Post-publish commands | Run without a shell, as argument lists from the owner's config, each printed first | `scripts/repo_settings.py` (`post_publish`) |
| Accidental publication | `repo_settings.py` never changes visibility; SKILL.md requires the owner's yes to the Step 7 question (the request that started the skill is not that yes) for going public, pushing to public repos, posting, installing over a skill and deleting | `scripts/repo_settings.py`, `SKILL.md` |
| Prompt injection from the reviewed skill | SKILL.md and every agent prompt treat the reviewed files, test output, CI logs, scan lines and reviewer reports as data; reviewer proofs are read before they are run; untrusted code runs only with a scratch `HOME` and `SKILL_RELEASE_HOME`; reviewers get no private terms and no settings path | `SKILL.md`, `references/review.md`, `agents/` |
| Tampering with the owner's settings | `local.md` may tighten rules, never relax a Hard rule; `shasum` of the settings is recorded at intake and checked again before the go | `SKILL.md` |
| Self-inflicted false negatives | The tests build every planted secret and invisible character at run time, replay each finding of the independent review, and assert that the repo passes its own scan | `tests/` |

## Residual risks

- Pattern rules miss secrets and personal data of unknown shapes, and binary
  formats the scanner does not parse are only searched for secrets and long
  private terms. That is why gitleaks, the reviewers and a human read are
  part of the process.
- The scratch `HOME` is isolation, not a sandbox. The cold-start tester and the
  skill's own tests run the reviewed skill's code with your user account. For
  a skill written by someone else, run those parts on a machine or VM you can
  throw away, or skip them and say so in the report.
- Only the last path component is opened with `O_NOFOLLOW`. A folder that
  someone else can change while the scan runs can still swap files; scan a
  staging copy only you can write.
- The reviewer agents run with your Claude Code permissions. Their prompts
  restrict them to their scratch folders, but a prompt is not a sandbox.
- Private terms match whole words, case-insensitive; other spellings must be
  listed separately.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue for security problems.
