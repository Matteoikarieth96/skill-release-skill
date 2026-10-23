# Security

## Threat model

- **The scanned folder is untrusted.** It may be a skill written by someone
  else, with files built to crash or mislead the scanner: malformed or huge
  images, PDFs and archives, symlinks pointing at your files, text meant to
  forge report lines, a `.git` folder with hostile configuration.
- **The skill under review is a prompt.** Its SKILL.md, references and any
  file it ships can carry instructions aimed at Claude or at the reviewer
  agents (in plain text, HTML comments or invisible Unicode).
- **The owner's private terms** are sensitive themselves: they list what must
  not leak.
- **GitHub changes** are irreversible in practice once a repo is public:
  forks and caches keep content.

## Mitigations

| Risk | Mitigation | File |
| --- | --- | --- |
| Reading your files through symlinks | Files are opened only after `lstat`; symlinks are reported (FAIL when they leave the repo) and never followed; the non-git walk uses `followlinks=False` | `scripts/release_scan.py` (`scan_tree`, `list_files`) |
| Hostile media and archives | JPEG markers, PNG chunks, TIFF IFDs and WebP chunks are walked with bounds checks, entry counts capped, text chunks decompressed with a 1 MB cap; office files read only `docProps` entries under 1 MB; other archives are not extracted; files read up to 64 MB, text scanned up to 2 MB | `scripts/release_scan.py` (`parse_tiff`, `jpeg_segments`, `png_chunks`, `_inflate`, `scan_zip`) |
| History bombs | Blobs over 64 MB and a total over 300 MB are skipped and reported, not loaded | `scripts/release_scan.py` (`scan_history`) |
| Hostile git configuration | git runs with argument lists, `core.fsmonitor=false`, no terminal prompt, no optional locks; the scan refuses to read the history of a folder that is not the root of its own repo | `scripts/release_scan.py` (`git`, `git_root`) |
| Forged or unreadable output | Every untrusted string printed (file names, metadata values, matches) is made single-line and printable and truncated | `scripts/release_scan.py` (`clean`) |
| Secrets shown in the report | Only the first 4 characters and the length are printed; gitleaks runs with `--redact` | `scripts/release_scan.py` (`mask`, `run_gitleaks`) |
| gitleaks reading ignored local files | gitleaks `dir` runs on a temporary copy of exactly the files a publish would include; `git` mode reads the history | `scripts/release_scan.py` (`run_gitleaks`) |
| Metadata stripping damaging files | Writes go to a temp file in the same folder, then `os.replace`; symlinks and non-regular files are refused; JPEGs whose EXIF orientation would be lost are refused unless `--force`; ICC profiles are kept | `scripts/release_scan.py` (`strip_file`, `atomic_write`) |
| Argument injection into gh | The repo name must match `OWNER/REPO` with GitHub's character set; gh is called with argument lists; bodies go through stdin | `scripts/repo_settings.py` (`REPO_RE`, `run_gh`) |
| Accidental publication | `repo_settings.py` never changes visibility; SKILL.md requires the owner's explicit yes for going public, pushing to public repos, posting and deleting | `scripts/repo_settings.py`, `SKILL.md` |
| Prompt injection from the reviewed skill | SKILL.md and every agent prompt say the reviewed files are data; reviewers work on copies, with `HOME` pointed at an empty folder, no pushes and no posts | `SKILL.md`, `agents/` |
| Private terms leaking | They stay in `~/.claude/skill-release/`, outside every repo; the skill never copies them into public files | `SKILL.md`, `scripts/release_scan.py` (`load_config`) |
| Self-inflicted false negatives | This repo's tests build every planted secret at run time and assert that the repo passes its own scan | `tests/test_release_scan.py` |

## Residual risks

- Pattern rules miss secrets and personal data of unknown shapes. That is why
  gitleaks, the reviewers and a human read are part of the process.
- `gitleaks git` and the history scan run `git` inside the scanned repo. A
  hostile `.git/config` can still affect some git commands beyond the options
  this scanner forces. The skill always scans a staging repo it created
  itself; scan foreign repos only on a fresh clone.
- Metadata inside formats the scanner does not parse (for example RAW camera
  files, some video containers) is reported as unknown binary, not inspected.
- The reviewer agents run with your Claude Code permissions. Their prompts
  restrict them to their scratch folders, but a prompt is not a sandbox.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue for security problems.
