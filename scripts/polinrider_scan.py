#!/usr/bin/env python3
"""Read-only scan for PolinRider-style supply-chain droppers.

This never executes repository files. Indicator strings below are split so
this source can sit inside a repository that the scan itself checks.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".gradle",
    ".next",
    ".venv",
    ".yarn",
    "Pods",
    "coverage",
    "node_modules",
    "venv",
}
FONT_DIR_NAMES = {"font", "fonts"}
DOC_SUFFIXES = {".css", ".htm", ".html", ".json", ".map", ".md", ".svg", ".txt"}
DOC_NAMES = re.compile(r"^(readme|license|licence|copying|notice|changelog)(\..*)?$", re.I)
ASSET_EXT = re.compile(
    r"\.(?:woff2?|ttf|otf|eot|llf|lkf|png|jpe?g|gif|webp|ico|wasm|svg)(?=$|[\s\"'`)|;])",
    re.I,
)
INTERPRETER = re.compile(
    r"(?:^|[\s;&|`(])(?:nodejs|node|python3|python|bash|sh|zsh|pwsh|powershell|osascript|curl|wget|ruby|perl|php)(?=$|[\s;&|`)])",
    re.I,
)
FONT_PATH = re.compile(r"(?:^|[/\\])fonts?(?:[/\\]|$)", re.I)
SETTING_KEY = "task.allow" + "AutomaticTasks"
MARKERS = (
    "rmcej" + "%otb%",
    "Cot%3t" + "=shtP",
    "RS" + "260605",
    "tron" + "grid.io",
)
MAX_MARKER_BYTES = 8_000_000


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".git")]
        current = Path(dirpath)
        for name in filenames:
            path = current / name
            if path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            if name == "tasks.json":
                findings.extend(scan_tasks(path, rel))
            if path.suffix.lower() in {".json", ".jsonc"} or path.suffix.lower() == ".code-workspace" or name.endswith(".code-workspace"):
                findings.extend(scan_settings(path, rel))
            if _under_fonts(path, root):
                findings.extend(scan_font_file(path, rel))
            findings.extend(scan_markers(path, rel))
    return findings


def scan_tasks(path: Path, rel: str) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"{rel}: could not read tasks file ({exc})"]
    try:
        data = json.loads(_jsonc_to_json(text))
    except json.JSONDecodeError:
        raw_hits = []
        if re.search(r'"runOn"\s*:\s*"folderOpen"', text, re.I):
            raw_hits.append(f"{rel}: runs a task when the folder opens, and the file is not valid JSON")
        if _line_runs_interpreter_on_asset(text):
            raw_hits.append(f"{rel}: runs an interpreter against an asset file, and the file is not valid JSON")
        if raw_hits:
            return raw_hits
        return [f"{rel}: tasks file could not be parsed"]
    findings = []
    _walk_tasks(data, rel, findings)
    return findings


def scan_settings(path: Path, rel: str) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if SETTING_KEY in text:
        return [f"{rel}: commits {SETTING_KEY}, which can turn editor tasks back on"]
    return []


def scan_font_file(path: Path, rel: str) -> list[str]:
    if DOC_NAMES.match(path.name) or path.suffix.lower() in DOC_SUFFIXES:
        return []
    try:
        sample = path.read_bytes()[:8192]
    except OSError as exc:
        return [f"{rel}: could not read font path ({exc})"]
    if not sample or b"\0" in sample:
        return []
    textish = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in sample)
    if textish / len(sample) > 0.90:
        return [f"{rel}: file under a fonts directory is text, not font data"]
    return []


def scan_markers(path: Path, rel: str) -> list[str]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size == 0 or size > MAX_MARKER_BYTES:
        return []
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    if b"\0" in raw[:8192]:
        return []
    text = raw.decode("utf-8", errors="replace")
    findings = []
    for marker in MARKERS:
        if marker not in text:
            continue
        line_no = text[: text.index(marker)].count("\n") + 1
        findings.append(f"{rel}:{line_no}: contains loader marker {marker}")
    return findings


def _walk_tasks(node, rel: str, findings: list[str]) -> None:
    if isinstance(node, dict):
        if any(key in node for key in ("command", "script", "runOptions")):
            findings.extend(_inspect_task(node, rel))
        for value in node.values():
            _walk_tasks(value, rel, findings)
    elif isinstance(node, list):
        for item in node:
            _walk_tasks(item, rel, findings)


def _inspect_task(task: dict, rel: str) -> list[str]:
    findings = []
    label = task.get("label")
    where = f'{rel} task "{label}"' if isinstance(label, str) and label else rel
    run_options = task.get("runOptions")
    if isinstance(run_options, dict) and str(run_options.get("runOn", "")).strip().lower() == "folderopen":
        findings.append(f"{where}: runs when the folder opens")
    line = _command_line(task)
    if line and _line_runs_interpreter_on_asset(line):
        findings.append(f"{where}: runs an interpreter against an asset or fonts path")
    return findings


def _command_line(task: dict) -> str:
    parts: list[str] = []
    command = task.get("command")
    if isinstance(command, str):
        parts.append(command)
    elif isinstance(command, list):
        parts.extend(str(part) for part in command)
    args = task.get("args")
    if isinstance(args, list):
        parts.extend(arg for arg in args if isinstance(arg, str))
    script = task.get("script")
    if isinstance(script, str):
        parts.append(script)
    return " ".join(parts)


def _line_runs_interpreter_on_asset(line: str) -> bool:
    if not INTERPRETER.search(line):
        return False
    return ASSET_EXT.search(line) is not None or FONT_PATH.search(line) is not None


def _under_fonts(path: Path, root: Path) -> bool:
    return any(part.lower() in FONT_DIR_NAMES for part in path.relative_to(root).parts[:-1])


def _jsonc_to_json(text: str) -> str:
    return _strip_trailing_commas(_strip_json_comments(text))


def _strip_json_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            i += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            i += 1
            continue
        if char == "/" and nxt == "/":
            i += 2
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if char == "/" and nxt == "*":
            i += 2
            while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = min(i + 2, len(text))
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    out: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        char = text[i]
        if in_string:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            i += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            i += 1
            continue
        if char == ",":
            j = i + 1
            while j < len(text) and text[j] in " \t\r\n":
                j += 1
            if j < len(text) and text[j] in "}]":
                i += 1
                continue
        out.append(char)
        i += 1
    return "".join(out)


def self_test() -> int:
    cases = (
        ("clean repo", _clean_repo, True),
        ("folderOpen task", _folder_open_repo, False),
        ("interpreter on font", _interpreter_font_repo, False),
        ("ordinary node task", _ordinary_task_repo, True),
        ("jsonc task", _jsonc_task_repo, True),
        ("text pretending to be a font", _text_font_repo, False),
        ("binary font", _binary_font_repo, True),
        ("readme in fonts", _readme_font_repo, True),
        ("automatic tasks setting", _automatic_tasks_repo, False),
        ("loader marker", _marker_repo, False),
        ("icon named folderOpen", _icon_name_repo, True),
    )
    failed = 0
    for name, builder, expect_clean in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            builder(root)
            findings = scan(root)
        ok = (not findings) if expect_clean else bool(findings)
        print(f"{'ok' if ok else 'FAIL'}  {name}" + ("" if ok else ": " + "; ".join(findings)))
        failed += not ok
    print(f"self-test: {len(cases) - failed} passed, {failed} failed")
    return 1 if failed else 0


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _clean_repo(root: Path) -> None:
    _write(root, "src/app.js", "console.log('ok')\n")


def _folder_open_repo(root: Path) -> None:
    _write(
        root,
        ".vscode/tasks.json",
        json.dumps(
            {
                "version": "2.0.0",
                "tasks": [
                    {
                        "label": "build",
                        "type": "npm",
                        "script": "build",
                        "runOptions": {"runOn": "folder" + "Open"},
                    }
                ],
            }
        ),
    )


def _interpreter_font_repo(root: Path) -> None:
    _write(
        root,
        ".vscode/tasks.json",
        json.dumps(
            {
                "version": "2.0.0",
                "tasks": [
                    {
                        "label": "assets",
                        "type": "shell",
                        "command": "node",
                        "args": ["public/fonts/icon.woff2"],
                    }
                ],
            }
        ),
    )


def _ordinary_task_repo(root: Path) -> None:
    _write(
        root,
        ".vscode/tasks.json",
        json.dumps(
            {
                "version": "2.0.0",
                "tasks": [
                    {"label": "build", "type": "shell", "command": "npm", "args": ["run", "build"]}
                ],
            }
        ),
    )


def _jsonc_task_repo(root: Path) -> None:
    _write(
        root,
        ".vscode/tasks.json",
        '{\n  "version": "2.0.0",\n  // editor helper\n  "tasks": [\n    {"label": "test", "type": "shell", "command": "npm", "args": ["test"],},\n  ],\n}\n',
    )


def _text_font_repo(root: Path) -> None:
    _write(root, "public/fonts/icon.woff2", (" " * 200) + "console.log(1)\n")


def _binary_font_repo(root: Path) -> None:
    path = root / "public/fonts/icon.woff2"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"wOFF\0" + os.urandom(300))


def _readme_font_repo(root: Path) -> None:
    _write(root, "public/fonts/README.md", "These are real font files.\n")


def _automatic_tasks_repo(root: Path) -> None:
    _write(root, ".vscode/settings.json", '{\n  "' + SETTING_KEY + '": "on"\n}\n')


def _marker_repo(root: Path) -> None:
    _write(root, "src/vendor.js", "const x = '" + MARKERS[0] + "';\n")


def _icon_name_repo(root: Path) -> None:
    _write(root, "src/icons.ts", "export const icons = { folderOpen: '<path />' }\n")


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    root = Path(argv[1] if len(argv) > 1 else ".")
    if not root.is_dir():
        print(f"PolinRider scan: {root} is not a directory", file=sys.stderr)
        return 2
    findings = scan(root)
    if findings:
        print("PolinRider scan: fail")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("PolinRider scan: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
