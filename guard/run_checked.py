#!/usr/bin/env python
"""Run project code that has been checked for references to the data.

The single permitted entry point for executing anything from a Claude Code
session. It lives in the guarded directory, so Claude cannot edit it, which
means these restrictions hold even when the guard hook is not running.

    <pinned python> <this file> [--timeout N] <script> [args...]

Options come before the script. Everything after it is passed to the script
untouched, so a script can take a --timeout of its own without confusion.

No folder layout is imposed. Any .py or .R file in the project can be run, as
long as:

  - it resolves to somewhere inside the project, so a symlink or '..' cannot
    reach code that lives elsewhere
  - it does not sit inside a data folder
  - it does not name a data folder anywhere in its own source
  - the run is bounded in time and output

Be clear about the limits. Only the file being run is read, so a sibling it
imports could reach the data. The check is string matching, so code written to
evade it would. And nothing here confines what a running script reads: it runs
as the same user as everything else. This restricts, it does not isolate.

What this is for: simulations, worked examples, checking that code parses and
behaves. Not analysis. Analysis runs in your own environment, as before.
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import data_guard  # noqa: E402  (path must be set first)

DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 600
MAX_OUTPUT_CHARS = 20000
MAX_SCAN_BYTES = 2_000_000


def refuse(message):
    sys.stderr.write("\nREFUSED: %s\n" % message)
    sys.exit(2)


def project_root():
    """The project is wherever the session is. No folder layout is imposed."""
    return os.path.realpath(os.getcwd())


def inside(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False  # Different drives.


def resolve_target(script, root, fragments):
    """Resolve through symlinks, then require the result to be in the project.

    Resolving first is what stops a symlink or a '..' from reaching code that
    lives somewhere else, including inside a protected root.
    """
    target = os.path.realpath(os.path.join(os.getcwd(), script))

    if not os.path.isfile(target):
        refuse("no such file: %s" % target)

    if not inside(target, root):
        refuse("%s resolves outside the project at %s.\nOnly code in the "
               "project can be run." % (target, root))

    if data_guard.check_path_like(target, fragments) is not None:
        refuse("%s sits inside a protected data folder. Nothing there runs, "
               "ever." % target)

    return target


def scan_target(target, root, fragments):
    """Refuse if the file being run names a protected folder.

    Only the target, not the whole project. Data now lives in a subfolder of
    the project, so every real analysis script in it names a protected folder.
    Scanning them all would refuse every run in every genuine project, which
    would make the feature useless rather than safe.

    What that gives up: the target can import a sibling that reads data, and
    the sibling is not read. Stated rather than glossed over.
    """
    try:
        size = os.path.getsize(target)
    except OSError as error:
        refuse("could not read %s to check it (%s)." % (target, error))

    # Refuse rather than check a prefix. Reading the first MAX_SCAN_BYTES and
    # running the file anyway would mean everything past that point is
    # unchecked, which is the one outcome this function exists to prevent.
    if size > MAX_SCAN_BYTES:
        refuse("%s is %d bytes, over the %d byte limit for a file that can be "
               "checked. Nothing that cannot be read in full is run."
               % (os.path.relpath(target, root), size, MAX_SCAN_BYTES))

    try:
        with open(target, "rb") as handle:
            blob = handle.read(MAX_SCAN_BYTES)
    except OSError as error:
        refuse("could not read %s to check it (%s)." % (target, error))

    if b"\0" in blob:
        refuse("%s is not text, so it cannot be checked."
               % os.path.relpath(target, root))

    reason = data_guard.check_path_like(blob.decode("utf-8", errors="replace"),
                                        fragments)
    if reason is not None:
        refuse("%s %s.\nThe file being run may not name a data folder. Code "
               "that reads the data is yours to run, in your own environment."
               % (os.path.relpath(target, root), reason))


def child_environment():
    """The environment for the child, with bytecode writing turned off.

    There used to be a step here that stripped LAB_DATA_ROOT and anything else
    pointing at the data, back when data lived outside the project and code
    found it through that variable. Data now lives in a subfolder of the
    project, reached by a relative path, so there is nothing in the environment
    to strip. Pretending otherwise would be theatre.

    What stands in its place is the scan below: the file being run may not name
    a protected folder.
    """
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def command_for(target):
    extension = os.path.splitext(target)[1].lower()

    if extension == ".py":
        return [sys.executable, target]

    if extension == ".r":
        rscript = shutil.which("Rscript")
        if rscript is None:
            refuse("Rscript is not on PATH, so .R files cannot be run here.")
        return [rscript, "--vanilla", target]

    refuse("only .py and .R files can be run, not '%s'." % extension)


def truncate(text, label):
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return (text[:MAX_OUTPUT_CHARS] +
            "\n...[%s truncated at %d characters]\n" % (label, MAX_OUTPUT_CHARS))


def main():
    parser = argparse.ArgumentParser(
        prog="run_checked.py",
        description="Run a project file, after checking it names no data folder.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="seconds before the run is killed (default %d). "
                             "Must come before the script." % DEFAULT_TIMEOUT)
    parser.add_argument("script", help="path to a .py or .R file in the project")
    parser.add_argument("args", nargs=argparse.REMAINDER,
                        help="arguments passed to the script untouched")
    parsed = parser.parse_args()

    if not 1 <= parsed.timeout <= MAX_TIMEOUT:
        refuse("timeout must be between 1 and %d seconds." % MAX_TIMEOUT)

    try:
        folders = data_guard.load_data_folders()
    except Exception as error:
        refuse("the guard configuration could not be read (%s: %s). Without it "
               "there is no list of protected folders to check against, so "
               "nothing runs." % (type(error).__name__, error))
    fragments = data_guard.fragments_for(folders)

    root = project_root()
    target = resolve_target(parsed.script, root, fragments)
    scan_target(target, root, fragments)
    env = child_environment()

    print("project:  %s" % root)
    print("running:  %s" % os.path.relpath(target, root))
    print("checked:  names no protected folder")
    print("-" * 60)
    sys.stdout.flush()

    try:
        result = subprocess.run(
            command_for(target) + list(parsed.args),
            cwd=root, env=env, capture_output=True, text=True,
            timeout=parsed.timeout,
        )
    except subprocess.TimeoutExpired:
        refuse("the script was still running after %d seconds and was killed. "
               "Pass --timeout to allow longer." % parsed.timeout)

    if result.stdout:
        sys.stdout.write(truncate(result.stdout, "stdout"))
    if result.stderr:
        sys.stdout.write("\n--- stderr ---\n")
        sys.stdout.write(truncate(result.stderr, "stderr"))

    print("-" * 60)
    print("exit code: %d" % result.returncode)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
