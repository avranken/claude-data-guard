#!/usr/bin/env python
"""Verify that the data guard blocks what it should and allows what it must.

    python guard\\test_guard.py                 checks the installed guard
    python guard\\test_guard.py path\\to\\data_guard.py
    python guard\\test_guard.py --essential     only the per machine cases

Run the full set after any change to the guard. Run --essential after an
install, which is what install.ps1 does: it checks that the config just written
protects every folder name the user typed, which is the only thing that differs
between one machine and the next.

Cases are generated from the guard's own configured folder names, so they stay
correct when those names change.

The ALLOW cases matter more than the DENY cases. The guard fails closed, so a
completely broken guard denies everything and passes every DENY case. Only an
ALLOW case can tell you the guard is working rather than merely bricked.
"""

import atexit
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

DEFAULT_GUARD = os.path.join(os.path.expanduser("~"), ".claude", "hooks",
                             "data_guard.py")

# A data shaped extension, used to build paths. The guard has no rule about
# extensions, which is what two of the ALLOW cases below check.
DATA_EXT = ".xlsx"

# A folder name nobody would configure, used for the cases that must be allowed.
NEUTRAL_DIR = "notes"


_PROJECTS = {}


def sample_project(data_folder):
    """A throwaway project on disk, because the recursion rule reads the disk.

    Two of them: one with a protected folder in it and one without, so the
    cases can show the rule firing and NOT firing. Built once and reused.
    """
    if data_folder in _PROJECTS:
        return _PROJECTS[data_folder]

    root = tempfile.mkdtemp(prefix="guardcase-")
    atexit.register(shutil.rmtree, root, True)

    withdata = os.path.join(root, "study")
    os.makedirs(os.path.join(withdata, data_folder))
    os.makedirs(os.path.join(withdata, "src"))
    with open(os.path.join(withdata, "src", "analyse.py"), "w") as handle:
        handle.write("print('hi')\n")

    plain = os.path.join(root, "tooling")
    os.makedirs(os.path.join(plain, "src"))

    _PROJECTS[data_folder] = (withdata, plain)
    return _PROJECTS[data_folder]


def load_guard(path):
    spec = importlib.util.spec_from_file_location("data_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_essential_cases(guard):
    """The cases worth running on every machine, not just in development.

    Exactly one thing differs between machines: the folder names the user typed
    during install. So the essential set is built from that list, and covers
    every name in it rather than a sample. Everything else the guard does is
    identical everywhere, and a failure in it is a bug to be found in
    development, not on a researcher's laptop.

    The ALLOW cases are not padding. The guard fails closed, so a completely
    broken guard denies everything and passes every DENY case above. Only an
    ALLOW case can tell the difference between working and bricked.
    """
    folders = guard.load_data_folders()
    interpreter = guard.BLOCKED_PROGRAMS[0]
    runner_python, runner_script = guard.runner_paths()
    installed_hook = os.path.join(os.path.expanduser("~"), ".claude", "hooks",
                                  "data_guard.py")

    cases = []

    # One per configured name. This is the whole point of running these here.
    for name in folders:
        cases.append((True, "Refuses %s/" % name, "Read",
                      {"file_path": "./%s/cohort%s" % (name, DATA_EXT)}))

    cases += [
        (False, "Reads ordinary project code", "Read",
         {"file_path": "./analyse.py"}),
        (False, "Writes ordinary project code", "Write",
         {"file_path": "./analyse.py", "content": "import pandas\n"}),
        (False, "Reads a folder that is not a data folder", "Read",
         {"file_path": "./%s/group_means%s" % (NEUTRAL_DIR, DATA_EXT)}),
        (True, "Refuses to run %s" % interpreter, "Bash",
         {"command": interpreter + " analyse.py"}),
        (True, "Refuses to edit itself", "Edit",
         {"file_path": installed_hook, "old_string": "a", "new_string": "b"}),
    ]

    if runner_python and runner_script:
        cases.append((False, "Allows the one permitted run command", "Bash",
                      {"command": "%s %s sim.py"
                                  % (runner_python, runner_script)}))

    # The recursion rule reads the disk, so it is the one piece of logic that
    # can be broken by something about this machine rather than by the code.
    # One case here, the rest in the full suite.
    withdata, _plain = sample_project(folders[0])
    cases.append((True, "Refuses a search of a project holding one", "Bash",
                  {"command": "grep -r subject_id ."}, withdata))

    return cases


def build_cases(guard, guard_path):
    """Return (should_deny, label, tool_name, tool_input) tuples."""
    folders = guard.load_data_folders()
    first = folders[0]
    last = folders[-1]
    interpreter = guard.BLOCKED_PROGRAMS[0]
    runner_python, runner_script = guard.runner_paths()

    claude_dir = os.path.join(os.path.expanduser("~"), ".claude")
    installed_runner = os.path.join(claude_dir, "hooks", "run_checked.py")
    installed_settings = os.path.join(claude_dir, "settings.json")

    # The essential set first, then everything that only development needs.
    cases = build_essential_cases(guard) + [
        # A data folder inside a project, in every other spelling.
        (True, "Data folder, bare relative", "Read",
         {"file_path": "%s/cohort%s" % (first, DATA_EXT)}),
        (True, "Data folder, capitalised", "Read",
         {"file_path": "./%s/cohort%s" % (first.upper(), DATA_EXT)}),
        (True, "Data folder, nested in the project", "Read",
         {"file_path": "./study/%s/cohort%s" % (first, DATA_EXT)}),
        (True, "Data folder, absolute path", "Read",
         {"file_path": "C:/Users/me/Documents/study/%s/cohort%s"
                       % (first, DATA_EXT)}),
        (True, "Data folder, Windows separators", "Read",
         {"file_path": ".\\study\\%s\\cohort%s" % (first, DATA_EXT)}),
        (True, "cat from a shell", "Bash",
         {"command": "cat %s/cohort%s" % (first, DATA_EXT)}),
        (True, "grep through a data folder", "Bash",
         {"command": "grep -r subject ./%s/" % first}),
        (True, "Glob across a data folder", "Glob",
         {"pattern": "./%s/**/*" % first}),
        (True, "Grep tool pointed at one, no trailing slash", "Grep",
         {"pattern": "id", "path": "./%s" % first}),
        (True, "Listing one from a shell", "Bash",
         {"command": "ls -la %s" % first}),
        (True, "Copy data out of one", "Bash",
         {"command": "cp ./%s/cohort%s ." % (first, DATA_EXT)}),

        # Executing an interpreter, in the spellings that route around a
        # plain name at the start of the command.
        (True, "Interpreter behind an env assignment", "Bash",
         {"command": "ROOT=x " + interpreter + " analyse.py"}),
        (True, "Interpreter after a directory change", "Bash",
         {"command": "cd src && " + interpreter + " analyse.py"}),
        (True, "Interpreter by absolute path", "Bash",
         {"command": "/usr/bin/" + interpreter + " analyse.py"}),
        (True, "Rscript on a project script", "Bash",
         {"command": "Rscript model.R"}),

        # Executing a file, which would otherwise route around the rule above.
        (True, "A batch file written into the project", "Bash",
         {"command": "./run.cmd"}),
        (True, "A shell script written into the project", "Bash",
         {"command": "./build.sh"}),
        (True, "A batch file by Windows relative path", "Bash",
         {"command": ".\\run.bat"}),

        # Handing the script to an interpreter instead of executing it. Only
        # the first token of a segment is examined, so until these programs
        # were blocked by name, every one of these ran.
        (True, "A script handed to powershell", "Bash",
         {"command": "powershell -File run.ps1"}),
        (True, "Arbitrary code through powershell", "Bash",
         {"command": "powershell -NoProfile -Command \"Get-Content secret\""}),
        (True, "A script handed to cmd", "Bash",
         {"command": "cmd /c run.bat"}),
        (True, "A script handed to bash", "Bash",
         {"command": "bash build.sh"}),
        (True, "A script handed to a script host", "Bash",
         {"command": "cscript hidden.vbs"}),
        (True, "Another runtime entirely", "Bash",
         {"command": "node analyse.js"}),

        # The guard protects itself, at its installed location.
        (True, "Overwrite the installed settings file", "Write",
         {"file_path": installed_settings, "content": "{}"}),
        (True, "Edit the installed runner", "Edit",
         {"file_path": installed_runner, "old_string": "a", "new_string": "b"}),

        # Ordinary work, which must keep working.
        (False, "Write code that names a data file", "Write",
         {"file_path": "./load.py",
          "content": "path = os.path.join(ROOT, 'cohort%s')\n" % DATA_EXT}),
        (False, "A plan that describes a data folder", "ExitPlanMode",
         {"plan": "The guard protects any folder called %s" % first}),
        (False, "List a folder", "Bash", {"command": "ls -la ."}),
        (False, "Check version control status", "Bash",
         {"command": "git status"}),
        # A wrapped command is one command. Before the continuation was joined,
        # each line looked like a new command and its first word was treated as
        # a program, so the last line here was refused as an executable script.
        (False, "A command wrapped over several lines", "Bash",
         {"command": "sed -i \\\n  -e 's/a/b/' \\\n  notes.ps1"}),
        # A folder whose name is not a data name is ordinary, even holding a
        # data shaped file. This is the deliberate limit of the whole approach.
        (False, "A data shaped file loose in the project", "Read",
         {"file_path": "./results%s" % DATA_EXT}),
        # 'mydata' is not 'data'. Segment matching, not substring matching.
        (False, "A folder whose name merely contains one", "Read",
         {"file_path": "./my%s/summary%s" % (first, DATA_EXT)}),
    ]

    if not (runner_python and runner_script):
        cases.append((True, "Nothing executes when no runner is configured",
                      "Bash", {"command": interpreter + " sim.py"}))
        return cases

    permitted = "%s %s" % (runner_python, runner_script)

    cases += [
        (False, "The permitted command, quoted, with script arguments", "Bash",
         {"command": '"%s" "%s" sim.py --seed 42'
                     % (runner_python, runner_script)}),

        (True, "The permitted shape with a chained second command", "Bash",
         {"command": permitted + " sim.py && ls"}),
        (True, "The permitted shape with output redirected", "Bash",
         {"command": permitted + " sim.py > out.log"}),
        (True, "The pinned interpreter with no script named", "Bash",
         {"command": permitted}),
        (True, "The pinned interpreter on its own", "Bash",
         {"command": runner_python + " sim.py"}),
        (True, "A copy of the runner planted in the project", "Bash",
         {"command": runner_python + " ./run_checked.py sim.py"}),
    ]

    # The Bash tool is git bash, so the same file is reachable by several
    # spellings. Every one a model might reasonably write has to work.
    def respell(path):
        out = []
        if len(path) > 2 and path[1] == ":":
            out.append("/" + path[0].lower() + path[2:].replace("\\", "/"))
        home = os.path.expanduser("~")
        if path.lower().startswith(home.lower()):
            out.append("~" + path[len(home):].replace("\\", "/"))
        return out

    for spelling in respell(runner_python):
        cases.append((False, "Interpreter spelled %s..." % spelling[:12],
                      "Bash",
                      {"command": "%s %s sim.py" % (spelling, runner_script)}))
    for spelling in respell(runner_script):
        cases.append((False, "Runner spelled %s..." % spelling[:12], "Bash",
                      {"command": "%s %s sim.py" % (runner_python, spelling)}))

    # Recursion, against real folders on disk. 'withdata' holds a protected
    # folder, 'plain' does not. The ALLOW half matters as much as the DENY
    # half: a rule that refuses every recursive command would be unusable and
    # would get switched off.
    withdata, plain = sample_project(first)
    cases += [
        (True, "grep -r over the project", "Bash",
         {"command": "grep -r subject_id ."}, withdata),
        (True, "grep -rn, bundled flags", "Bash",
         {"command": "grep -rn id ."}, withdata),
        (True, "a glob crossing a folder boundary", "Bash",
         {"command": "cat */*.csv"}, withdata),
        (True, "find over the project", "Bash",
         {"command": "find . -name '*.csv'"}, withdata),
        (True, "tar of the project", "Bash",
         {"command": "tar cf backup.tar ."}, withdata),
        (True, "copying the project elsewhere", "Bash",
         {"command": "cp -r . ../copy"}, withdata),
        (True, "the Grep tool with no path", "Grep",
         {"pattern": "patient"}, withdata),
        (True, "the Grep tool pointed at the root", "Grep",
         {"pattern": "patient", "path": "."}, withdata),
        (True, "the Glob tool over everything", "Glob",
         {"pattern": "**/*.csv"}, withdata),

        # Scoped to a folder that holds no data. This is the escape hatch, and
        # without it the rule would simply be turned off by whoever hits it.
        (False, "grep -r scoped to a code folder", "Bash",
         {"command": "grep -r subject_id src/"}, withdata),
        (False, "the Grep tool scoped to a code folder", "Grep",
         {"pattern": "id", "path": "src"}, withdata),
        # Glob carries its scope in the pattern, not in a path field.
        (False, "a Glob scoped by its own pattern", "Glob",
         {"pattern": "src/**/*.py"}, withdata),
        (True, "a Glob whose pattern names the data folder", "Glob",
         {"pattern": "%s/*" % first}, withdata),
        # Cannot leave the folder it starts in, so it is no worse than 'ls'.
        (False, "a Glob of one folder only", "Glob",
         {"pattern": "*.R"}, withdata),

        # Windows spelling of a recursive listing.
        (True, "dir /s over the project", "Bash",
         {"command": "dir /s /b"}, withdata),

        # A project with no protected folder anywhere: recursion is ordinary.
        (False, "grep -r in a project with no data folder", "Bash",
         {"command": "grep -r todo ."}, plain),
        (False, "the Grep tool in a project with no data folder", "Grep",
         {"pattern": "todo", "path": "."}, plain),

        # Not recursive at all, so the rule must not fire.
        (False, "reading one named file", "Bash",
         {"command": "cat src/analyse.py"}, withdata),
        (False, "listing one folder", "Bash",
         {"command": "ls -la src"}, withdata),
    ]

    return cases


def run_guard(guard_path, tool_name, tool_input, cwd=None):
    body = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    if cwd:
        body["cwd"] = cwd
    payload = json.dumps(body)
    result = subprocess.run([sys.executable, guard_path], input=payload,
                            capture_output=True, text=True)
    denied = '"permissionDecision": "deny"' in result.stdout
    return denied, (result.stdout or result.stderr).strip()


def main(argv):
    essential = "--essential" in argv
    argv = [a for a in argv if a != "--essential"]
    guard_path = os.path.abspath(argv[1] if len(argv) > 1 else DEFAULT_GUARD)

    if not os.path.isfile(guard_path):
        print("No guard at %s" % guard_path)
        print("Run install.ps1 first, or pass the path to data_guard.py.")
        return 1

    config = os.path.join(os.path.dirname(guard_path), "guard_config.json")
    if not os.path.isfile(config):
        print("No %s beside the guard." % os.path.basename(config))
        print("The guard cannot resolve its folder names without it and will "
              "deny every call. Run install.ps1.")
        return 1

    guard = load_guard(guard_path)

    print("Guard:   %s" % guard_path)
    print("Config:  %s" % config)
    print("Folders: %s" % ", ".join(guard.load_data_folders()))
    print("")

    cases = (build_essential_cases(guard) if essential
             else build_cases(guard, guard_path))

    failures = 0
    allow_failures = 0
    for case in cases:
        should_deny, label, tool_name, tool_input = case[:4]
        cwd = case[4] if len(case) > 4 else None
        denied, output = run_guard(guard_path, tool_name, tool_input, cwd)
        ok = denied == should_deny
        print("[%s] want %-5s got %-5s  %s" % (
            "pass" if ok else "FAIL",
            "DENY" if should_deny else "ALLOW",
            "DENY" if denied else "ALLOW",
            label))
        if not ok:
            failures += 1
            if not should_deny:
                allow_failures += 1
            if output:
                print("         guard said: %s" % output[:300])

    print("")
    if failures:
        print("%d of %d cases FAILED. Do not rely on the guard until these "
              "pass." % (failures, len(cases)))
        if allow_failures == sum(1 for c in cases if not c[0]):
            print("")
            print("Every ALLOW case failed, which usually means the guard is "
                  "erroring on every call and denying by design. Read the "
                  "message above: it names the exception.")
        return 1

    print("All %d cases passed." % len(cases))
    print("")
    print("This checks the guard's logic, not that Claude Code is calling it.")
    print("For that, ask Claude to read ./%s/__probe__%s and confirm it is "
          "refused." % (guard.load_data_folders()[0], DATA_EXT))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
