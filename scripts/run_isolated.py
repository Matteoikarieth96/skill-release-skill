#!/usr/bin/env python3
"""run_isolated: run a command from a skill under review with a clean environment.

Usage:
  run_isolated.py SCRATCH [--cwd DIR] [--timeout SECONDS] -- COMMAND [ARGS ...]

The command runs without a shell and with an empty environment except:
PATH (system folders plus the folder of the python3 running this script),
HOME=SCRATCH/home, SKILL_RELEASE_HOME=SCRATCH/local, TMPDIR=SCRATCH/tmp,
LANG=C.UTF-8, PYTHONDONTWRITEBYTECODE=1, and GIT_CONFIG_NOSYSTEM /
GIT_CONFIG_GLOBAL so git ignores the system and your global config. Your SSH agent, gh, git and cloud
credentials in environment variables are not passed, and HOME points away
from your settings. The working folder defaults to SCRATCH.

This is isolation, not a sandbox: the command still runs as your user and can
reach any file your account can. For code written by someone else, use a
machine or VM you can throw away.
Standard library only, Python 3.9 or newer. Exit code: the command's own.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

SYSTEM_PATH = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]


def clean_env(scratch: str) -> dict:
    py_dir = os.path.dirname(os.path.realpath(sys.executable))
    path = [py_dir] + [p for p in SYSTEM_PATH if p != py_dir]
    return {
        "PATH": os.pathsep.join(path),
        "HOME": os.path.join(scratch, "home"),
        "SKILL_RELEASE_HOME": os.path.join(scratch, "local"),
        "TMPDIR": os.path.join(scratch, "tmp"),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        # git inside the command reads neither the system nor your global config.
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def run(scratch, command, cwd=None, timeout=1800, runner=subprocess.run, out=print):
    if not command:
        raise SystemExit("no command given after --")
    scratch = os.path.abspath(os.path.expanduser(scratch))
    env = clean_env(scratch)
    for key in ("HOME", "SKILL_RELEASE_HOME", "TMPDIR"):
        os.makedirs(env[key], exist_ok=True)
    cwd = os.path.abspath(cwd) if cwd else scratch
    out(f"isolated: {shlex.join(command)}  (cwd {cwd}, HOME {env['HOME']})")
    try:
        return runner(command, cwd=cwd, env=env, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        out(f"isolated: timed out after {timeout} s")
        return 124
    except OSError as exc:
        out(f"isolated: cannot run it: {exc}")
        return 127


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        raise SystemExit("usage: run_isolated.py SCRATCH [--cwd DIR] [--timeout S] -- COMMAND ...")
    i = argv.index("--")
    ap = argparse.ArgumentParser(prog="run_isolated.py")
    ap.add_argument("scratch")
    ap.add_argument("--cwd")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args(argv[:i])
    return run(args.scratch, argv[i + 1:], cwd=args.cwd, timeout=args.timeout)


if __name__ == "__main__":
    sys.exit(main())
