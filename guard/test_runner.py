#!/usr/bin/env python
"""Verify that the runner refuses what it should.

    python guard\\test_runner.py                 checks the installed runner
    python guard\\test_runner.py path\\to\\run_checked.py
    python guard\\test_runner.py --essential     only the per machine cases

The guard decides which commands may be typed. This decides what happens once
one of them is. Both matter, and they fail in different ways, so they are
tested separately.

Each case builds a throwaway project in a temporary folder, so nothing here
touches a real one.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

DEFAULT_RUNNER = os.path.join(os.path.expanduser("~"), ".claude", "hooks",
                              "run_checked.py")


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(runner, project, args, timeout=120):
    result = subprocess.run([sys.executable, runner] + args, cwd=project,
                            capture_output=True, text=True, timeout=timeout)
    return result.returncode, (result.stdout + result.stderr)


def write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def make_project(data_folder):
    """A throwaway project with data in a subfolder, as researchers keep it."""
    project = tempfile.mkdtemp(prefix="guardtest-")

    write(os.path.join(project, "clean.py"), "print('simulation ran')\n")
    write(os.path.join(project, "slow.py"), "import time\ntime.sleep(30)\n")

    os.makedirs(os.path.join(project, "analysis"))
    write(os.path.join(project, "analysis", "nested.py"), "print('nested ran')\n")

    # Data where it actually lives, and a script inside it.
    os.makedirs(os.path.join(project, data_folder))
    write(os.path.join(project, data_folder, "inside.py"), "print('should not run')\n")

    return project


CASES = []


def case(name, essential=False):
    """Register a case. essential=True means it is run after every install.

    Two things about the runner are per machine: whether it can execute
    anything at all here, and whether it honours the folder names this user
    typed. Everything else is logic that behaves the same everywhere, so it
    belongs in development rather than on a researcher's laptop.
    """
    def register(function):
        CASES.append((name, function, essential))
        return function
    return register


@case("A script at the project root runs", essential=True)
def _(runner, project, data_folder, outside):
    code, output = run(runner, project, ["clean.py"])
    return code == 0 and "simulation ran" in output, output


@case("A script in a subfolder of the project runs")
def _(runner, project, data_folder, outside):
    code, output = run(runner, project, ["analysis/nested.py"])
    return code == 0 and "nested ran" in output, output


@case("A script outside the project is refused")
def _(runner, project, data_folder, outside):
    code, output = run(runner, project, [os.path.join(outside, "elsewhere.py")])
    return code == 2 and "REFUSED" in output, output


@case("Escaping the project with .. is refused")
def _(runner, project, data_folder, outside):
    code, output = run(runner, project, ["../" + os.path.basename(outside)
                                         + "/elsewhere.py"])
    return code == 2 and "REFUSED" in output, output


@case("A script sitting inside a data folder is refused")
def _(runner, project, data_folder, outside):
    code, output = run(runner, project, [data_folder + "/inside.py"])
    return code == 2 and "REFUSED" in output, output


@case("A script that names a data folder is refused", essential=True)
def _(runner, project, data_folder, outside):
    # The path is embedded in code, so it is not a whitespace token.
    script = os.path.join(project, "reader.py")
    write(script, 'print(open("%s/cohort.xlsx").read())\n' % data_folder)
    try:
        code, output = run(runner, project, ["reader.py"])
        return code == 2 and "REFUSED" in output, output
    finally:
        os.remove(script)


@case("A sibling that names a data folder does NOT block the run")
def _(runner, project, data_folder, outside):
    # Only the target is scanned. Every real analysis script in a project reads
    # the data, so scanning them all would refuse every run in every genuine
    # project. This asserts the limit rather than leaving it undocumented: the
    # target could import this sibling and reach the data through it.
    sibling = os.path.join(project, "loader.py")
    write(sibling, 'PATH = "%s/cohort.xlsx"\n' % data_folder)
    try:
        code, output = run(runner, project, ["clean.py"])
        return code == 0 and "simulation ran" in output, output
    finally:
        os.remove(sibling)


@case("A script naming its own output file is allowed")
def _(runner, project, data_folder, outside):
    writer = os.path.join(project, "writer.py")
    write(writer, "open('results.csv', 'w').write('a,b\\n1,2\\n')\n"
                  "print('wrote results')\n")
    try:
        code, output = run(runner, project, ["writer.py"])
        return code == 0 and "wrote results" in output, output
    finally:
        os.remove(writer)
        stray = os.path.join(project, "results.csv")
        if os.path.exists(stray):
            os.remove(stray)


@case("A script too large to check in full is refused")
def _(runner, project, data_folder, outside):
    # Over MAX_SCAN_BYTES. The point is that it is refused rather than having
    # its first two megabytes checked and the rest run unexamined.
    huge = os.path.join(project, "huge.py")
    write(huge, "# padding\n" * 300000 + "print('should not run')\n")
    try:
        code, output = run(runner, project, ["huge.py"])
        return code == 2 and "REFUSED" in output, output
    finally:
        os.remove(huge)


@case("A script over the timeout is killed")
def _(runner, project, data_folder, outside):
    # Options come before the script, because REMAINDER passes everything
    # after it through to the script untouched.
    code, output = run(runner, project, ["--timeout", "2", "slow.py"])
    return code == 2 and "still running" in output, output


def main(argv):
    essential = "--essential" in argv
    argv = [a for a in argv if a != "--essential"]
    runner = os.path.abspath(argv[1] if len(argv) > 1 else DEFAULT_RUNNER)
    if not os.path.isfile(runner):
        print("No runner at %s" % runner)
        print("Run install.ps1 first, or pass the path to run_checked.py.")
        return 1

    guard_path = os.path.join(os.path.dirname(runner), "data_guard.py")
    if not os.path.isfile(guard_path):
        print("No data_guard.py beside the runner at %s" % guard_path)
        return 1

    guard = load_module(guard_path, "data_guard")
    data_folder = guard.load_data_folders()[0]

    print("Runner:      %s" % runner)
    print("Data folder: %s" % data_folder)
    print("")

    project = make_project(data_folder)
    outside = tempfile.mkdtemp(prefix="guardtest-outside-")
    write(os.path.join(outside, "elsewhere.py"), "print('should not run')\n")

    selected = [c for c in CASES if c[2] or not essential]

    failures = 0
    try:
        for name, function, _is_essential in selected:
            try:
                ok, output = function(runner, project, data_folder, outside)
            except Exception as error:
                ok, output = False, "%s: %s" % (type(error).__name__, error)
            print("[%s] %s" % ("pass" if ok else "FAIL", name))
            if not ok:
                failures += 1
                for line in output.strip().splitlines()[:8]:
                    print("       %s" % line)
    finally:
        shutil.rmtree(project, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)

    print("")
    if failures:
        print("%d of %d cases FAILED." % (failures, len(selected)))
        return 1
    print("All %d cases passed." % len(selected))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
