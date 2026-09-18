#!/usr/bin/env python
"""PreToolUse guard for Claude Code.

Blocks any tool call that could reach protected research data. Runs before
every tool call, in every permission mode, including auto and bypass. Fails
closed: anything unexpected results in a denial, never in an allowed call.

This file is owned by the researcher, not by Claude. Claude Code is denied
write access to it. If you need to change it, edit it yourself and then run
test_guard.py.

Machine specific settings live in guard_config.json beside this file, written
by install.ps1. Nothing in this file is specific to one machine or one person,
so it can be distributed unchanged.
"""

import json
import os
import re
import sys

CONFIG_FILENAME = "guard_config.json"

# --------------------------------------------------------------------------
# STATIC CONFIGURATION
#
# These apply on every machine. The per machine parts, the protected roots,
# are in guard_config.json.
# --------------------------------------------------------------------------

# Folder names that mean data, always refused on top of whatever the machine
# adds in guard_config.json. Researchers keep data in a subfolder of the
# project, so a name is the whole rule: it covers every project, including ones
# that do not exist yet, without anyone maintaining a list of locations.
#
# The cost is stated plainly rather than hidden. A data folder called something
# not on the list has no protection at all, and neither does a mapped drive.
DEFAULT_DATA_FOLDERS = ["data", "raw", "staging", "patients", "subjects"]

# There is deliberately no rule here about file extensions.
#
# An earlier version refused any data shaped file anywhere in a project unless
# it sat in one of two named folders. That caught one specific accident, a data
# file copied into a project, at the cost of imposing a folder layout on every
# user and refusing a great deal of ordinary work. The decision was to drop it.
#
# What remains: a file under a protected root is refused, and so is any path
# containing one of the folder names above, wherever it appears. So data copied
# into 'myproject/data/' is still refused. A file dropped loose in a project
# root is not. Do not put data in a project.

# Programs Claude must never run. Analysis code can read protected data from a
# path hardcoded inside a script, which no command line inspection can see, so
# the interpreters themselves are off limits. The researcher runs analyses.
BLOCKED_PROGRAMS = [
    "python", "python3", "py", "pythonw", "ipython", "jupyter", "jupyter-lab",
    "jupyter-notebook", "conda", "mamba", "pip", "pip3", "uv", "poetry",
    "r", "rscript", "radian", "rstudio",
    "julia", "matlab", "octave", "stata", "sas", "spss",
    "duckdb", "sqlite3", "psql", "mysql", "mongo", "mongosh",
]

# Fields carrying Claude's own prose or code output rather than a path it
# intends to open. Naming a file is not opening one, so these are not checked.
#
# Path bearing fields are never listed here. If a future tool puts a path in a
# field named like prose, this guard will not see it, which is an argument for
# the protected data living somewhere Claude was never granted access to
# rather than for trying to enumerate every tool that exists.
CONTENT_KEYS = (
    "content", "new_string", "old_string", "new_source", "prompt",
    "description", "body", "message", "text",
    "plan", "todos", "summary", "title", "caption", "reason", "notes",
)

# Tools that modify files. These may never touch the guard itself.
MUTATING_TOOLS = ("Edit", "Write", "NotebookEdit", "MultiEdit")

GUARD_FRAGMENTS = ("/.claude/hooks/", "/.claude/settings")

# The one permitted way to execute code: the pinned interpreter, invoked by
# absolute path, running the installed runner, also by absolute path.
# Both paths are written into guard_config.json at install time and cannot be
# changed from a session, because the config sits in the guarded directory.
#
# There used to be a claude-sandbox.cmd shim here. Group policy on a managed
# machine refuses to execute a .cmd outside an approved folder, which killed
# it. Invoking the interpreter by absolute path costs nothing at the deny rule
# layer either way, because Bash(python:*) matches on a prefix and never
# covered an absolute path to python.exe in the first place. The hook is what
# covers every spelling, and it still refuses all of them but this one.
RUNNER_PYTHON_KEY = "runner_python"
RUNNER_SCRIPT_KEY = "runner_script"

# A command containing any of these can chain a second instruction onto the
# first, so it can never qualify as a runner invocation.
SHELL_METACHARACTERS = ";|&$`<>\n\r"

# Executing a file is not the same as running a known system command. Without
# this, Claude could write run.cmd containing an interpreter call and execute
# that instead, which defeats the interpreter block entirely.
SCRIPT_EXTENSIONS = (".cmd", ".bat", ".ps1", ".sh", ".exe", ".com", ".vbs",
                     ".js", ".jse", ".wsf", ".msi")

RELATIVE_PREFIXES = ("./", ".\\", "../", "..\\")

# --------------------------------------------------------------------------
# IMPLEMENTATION
# --------------------------------------------------------------------------


def deny(reason):
    """Emit a blocking decision and stop. Claude is shown the reason."""
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "DATA GUARD: " + reason,
        }
    }))
    sys.exit(0)


def allow():
    """Emit nothing. The normal permission flow continues."""
    sys.exit(0)


def norm(text):
    """Lowercase with forward slashes, so Windows and POSIX spellings match."""
    return text.replace("\\", "/").lower()


def load_data_folders():
    """Folder names this machine treats as data. Raises on any problem.

    Raising denies the call, which is the right failure: without a list there
    is nothing to protect against, and silently protecting nothing is worse
    than refusing.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        CONFIG_FILENAME)
    with open(path, "r", encoding="utf-8") as handle:
        config = json.load(handle)

    configured = [str(name).strip().strip("/\\").lower()
                  for name in config.get("protected_folders", [])]
    names = list(DEFAULT_DATA_FOLDERS) + [n for n in configured if n]

    ordered = []
    for name in names:
        if name not in ordered:
            ordered.append(name)
    return ordered


def fragments_for(names):
    """Each folder name as a path segment, so it matches only a whole segment.

    Slashes on both sides are what stops 'mydata' matching 'data'.
    """
    return ["/" + name.strip("/") + "/" for name in names]


def walk_strings(obj):
    """Yield every path bearing string inside the tool input."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if key in CONTENT_KEYS:
                continue
            for item in walk_strings(value):
                yield item
    elif isinstance(obj, list):
        for value in obj:
            for item in walk_strings(value):
                yield item


def check_path_like(text, fragments, match_bare=False):
    """Return a refusal reason for this string, or None if it looks fine.

    match_bare also refuses a token that is exactly a folder name, so 'ls data'
    is treated like './data'. The hook turns it on. The runner's source scan
    leaves it off, because 'data' on its own is an ordinary variable name in R
    and would otherwise refuse most scripts ever written.
    """
    low = norm(text)

    for fragment in fragments:
        if fragment in low:
            return "refers to a protected location ('%s')" % fragment.strip("/")

    # A relative path has no leading slash, so 'data/cohort.xlsx' would slip
    # past the check above while './data/cohort.xlsx' is caught. Wrap each
    # path shaped token so its first segment is matched like any other.
    #
    # Only tokens containing a slash are considered. A bare word is not a path,
    # and 'data' on its own is an ordinary variable name in R and would
    # otherwise refuse most scripts ever written.
    # Split on characters that cannot appear inside a path segment, rather than
    # on whitespace. Source code embeds paths in quotes and parentheses, so
    # open("data/cohort.xlsx") is a single whitespace token and slipped through.
    for token in re.split(r"[\s\"'`(),;=\[\]{}<>|&*]+", low):
        if "/" not in token:
            if not (match_bare and ("/" + token + "/") in fragments):
                continue
        # Slashes on both ends, so a path pointing AT the folder is caught as
        # well as one pointing into it. Without the trailing slash, a Grep with
        # path './data' searched it happily.
        candidate = "/" + token.strip("/") + "/"
        for fragment in fragments:
            if fragment in candidate:
                return ("refers to a protected location ('%s')"
                        % fragment.strip("/"))

    return None


def bash_program_tokens(command):
    """Yield the raw program token of each segment of a shell command.

    The token is returned unmodified, because whether it was written as a
    relative path matters as much as what it is called.

    A backslash before a newline continues one command onto the next line, so
    the continuation is joined first. Without this, the second line of a wrapped
    command looks like a new command and its first word is treated as a program.
    That refused ordinary work: 'sed -i \\<newline> -e ... <newline> doctor.ps1'
    yielded 'doctor.ps1' as a program and tripped the script extension rule.
    """
    command = re.sub(r"\\[ \t]*\r?\n", " ", command)
    segments = re.split(r"[;|&\n]+|\$\(|\)|`", command)
    for segment in segments:
        parts = segment.strip().split()
        index = 0
        # Skip leading VAR=value assignments and common wrappers.
        while index < len(parts) and (
            re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", parts[index])
            or parts[index] in ("env", "time", "nohup", "exec", "sudo", "start")
        ):
            index += 1
        if index >= len(parts):
            continue
        token = parts[index].strip("\"'(){}")
        if token:
            yield token


def program_name(token):
    """The bare command name, without directory or executable suffix."""
    name = re.split(r"[/\\]", token)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def norm_exec_path(text):
    """Normalise a path for comparison, accepting every spelling of it.

    The Bash tool here is git bash, so the same file is reachable as
    C:\\Users\\me\\x, /c/Users/me/x and ~/x. All three must compare equal, or
    the runner is unusable for the two thirds of spellings that fail.
    """
    path = norm(os.path.expanduser(text))
    drive = re.match(r"^/([a-z])/", path)
    if drive:
        path = drive.group(1) + ":/" + path[3:]
    return path


def runner_paths():
    """The pinned interpreter and runner, or (None, None) if not configured.

    Never raises. A missing or unreadable config means no runner, which is
    safe. It must not mean a broken guard, because everything else the guard
    does still needs to work.
    """
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            CONFIG_FILENAME)
        with open(path, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        python_path = config.get(RUNNER_PYTHON_KEY) or None
        runner_path = config.get(RUNNER_SCRIPT_KEY) or None
        if python_path and runner_path:
            return python_path, runner_path
    except BaseException:
        pass
    return None, None


def runner_hint():
    """How to actually run something. Every refusal that can, says this.

    A guard whose only documentation is its own refusal is a guard nobody can
    use, so the refusal carries the command.
    """
    python_path, runner_path = runner_paths()
    if not python_path:
        return ("No runner is configured on this machine, so nothing can be "
                "executed from this session at all. That is the intended "
                "state if install.ps1 has not been run.")
    return ("To run a .py or .R file from this project, use this exact "
            "command, both paths in full:\n"
            "  %s %s <script>\n"
            "The file is refused if it names a protected data folder, so this "
            "runs simulations and tests, not analysis." % (python_path, runner_path))


def split_command_tokens(command):
    """Split a command into tokens, keeping quoted paths in one piece."""
    tokens, current, quote = [], "", None
    for character in command:
        if quote:
            if character == quote:
                quote = None
            else:
                current += character
        elif character in "\"'":
            quote = character
        elif character.isspace():
            if current:
                tokens.append(current)
                current = ""
        else:
            current += character
    if current:
        tokens.append(current)
    return tokens


def is_runner_invocation(command):
    """True only for: <pinned interpreter> <installed runner> <script> [args].

    Deliberately narrow. A compound command cannot qualify, an interpreter on
    its own cannot, and neither can a copy of the runner that Claude wrote into
    a project, because both of the first two tokens must match paths recorded
    at install time in a file Claude cannot edit.
    """
    if any(character in command for character in SHELL_METACHARACTERS):
        return False

    python_path, runner_path = runner_paths()
    if not python_path or not runner_path:
        return False

    tokens = split_command_tokens(command)
    if len(tokens) < 3:
        return False  # interpreter, runner, and a script to run.

    return (norm_exec_path(tokens[0]) == norm_exec_path(python_path)
            and norm_exec_path(tokens[1]) == norm_exec_path(runner_path))


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        deny("the hook received no input, so nothing could be checked.")

    payload = json.loads(raw)
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})

    fragments = fragments_for(load_data_folders())
    strings = list(walk_strings(tool_input))

    # 1. The guard cannot be edited by the thing it restricts.
    if tool_name in MUTATING_TOOLS:
        for text in strings:
            if any(f in norm(text) for f in GUARD_FRAGMENTS):
                deny("the guard configuration is owned by the researcher and "
                     "cannot be modified by Claude. Ask the user to make this "
                     "change by hand.")

    # 2. Protected locations and data file types, for every tool.
    for text in strings:
        reason = check_path_like(text, fragments, match_bare=True)
        if reason is not None:
            deny("the request %s. Claude has no access to research data. Ask "
                 "the user to run anything that needs it, and to hand back "
                 "only reviewed, aggregate results." % reason)

    # 3. Execution. Interpreters could read data from a path inside a script,
    #    and so could any file Claude wrote and then ran.
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if isinstance(command, str) and not is_runner_invocation(command):
            for token in bash_program_tokens(command):
                name = program_name(token)

                if name in BLOCKED_PROGRAMS:
                    deny("running '%s' is not permitted. Analysis code is run "
                         "by the researcher in a separate environment.\n\n%s"
                         % (name, runner_hint()))

                # Checked on the raw token, because program_name() strips
                # '.exe' and would otherwise hide it from this rule.
                if norm(token).endswith(SCRIPT_EXTENSIONS):
                    deny("executing '%s' is not permitted. A script file can "
                         "invoke an interpreter from inside itself, so "
                         "allowing it would undo the rule above.\n\n%s"
                         % (token, runner_hint()))

                if norm(token).startswith(RELATIVE_PREFIXES):
                    deny("executing '%s' is not permitted. Running a file from "
                         "the project by relative path is how an interpreter "
                         "block gets bypassed.\n\n%s" % (token, runner_hint()))

    allow()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as error:
        # Fail closed. An error in the guard must never mean an allowed call.
        deny("the guard could not evaluate this call (%s: %s), so it was "
             "refused. This is intentional. If this persists, run doctor.ps1."
             % (type(error).__name__, error))
