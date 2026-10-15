#!/usr/bin/env python3
"""Scaffold a new skill from skills/_template.

Usage:
  python3 scripts/new_skill.py <name> [--description TEXT] [--root DIR] [--no-marketplace]

Creates:
  skills/<name>/              copy of skills/_template with `name: <name>` set
  evals/<name>/cases.toml     from evals/_template/cases.toml
  evals/<name>/runs/.gitkeep  where raw run logs go
and adds ./skills/<name> to the './' plugin entry in .claude-plugin/marketplace.json
(the explicit list keeps Claude Code from loading skills/_template).

Refuses invalid names (Agent Skills spec: ^[a-z0-9]+(-[a-z0-9]+)*$, max 64 chars) and existing
folders. Exit codes: 0 = created, 1 = refused (already exists), 2 = invalid name / missing template.
Stdlib only (Python 3.9+).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_NAME = 64
PLACEHOLDER = "skill-name"
TEMPLATE_DIR = "_template"
PLACEHOLDER_RE = re.compile(rf"(?<![\w-]){re.escape(PLACEHOLDER)}(?![\w-])")


def name_problem(name: str) -> str | None:
    if not name:
        return "name is empty"
    if len(name) > MAX_NAME:
        return f"name is {len(name)} characters (max {MAX_NAME})"
    if not NAME_RE.match(name):
        return f"name must match {NAME_RE.pattern} (lowercase letters, digits, single hyphens)"
    if name == PLACEHOLDER:
        return f"'{PLACEHOLDER}' is the template placeholder; pick a real name"
    return None


def _yaml_quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_skill_md(text: str, name: str, description: str | None = None) -> str:
    """Set the frontmatter name (and optional description), drop metadata.internal, fill the placeholder."""
    if not text.startswith("---"):
        raise ValueError("template SKILL.md has no frontmatter")
    end = text.find("\n---", 3)
    if end < 0:
        raise ValueError("template SKILL.md frontmatter is not closed")
    fm, rest = text[:end], text[end:]
    fm, n = re.subn(r"(?m)^name:.*$", f"name: {name}", fm, count=1)
    if n != 1:
        raise ValueError("template SKILL.md has no 'name:' line")
    fm = re.sub(r"(?m)\n[ \t]+internal:[ \t]*true[ \t]*(#.*)?$", "", fm)
    if description is not None:
        desc = " ".join(description.split())
        if not desc:
            raise ValueError("description is empty")
        fm, n = re.subn(r"(?m)^description:.*(\n[ \t]+.*)*$", lambda _m: "description: " + _yaml_quote(desc),
                        fm, count=1)
        if n != 1:
            raise ValueError("template SKILL.md has no 'description:' line")
    return fm + PLACEHOLDER_RE.sub(name, rest)


def add_to_marketplace(root: Path, name: str) -> bool:
    """Append ./skills/<name> to the skills list of the './' plugin entry. Returns True if changed."""
    path = root / ".claude-plugin" / "marketplace.json"
    if not path.is_file():
        return False
    data = json.loads(path.read_text("utf-8"))
    changed = False
    for entry in data.get("plugins") or []:
        if isinstance(entry, dict) and entry.get("source") in ("./", ".") and isinstance(entry.get("skills"), list):
            ref = f"./skills/{name}"
            if ref not in entry["skills"]:
                entry["skills"] = sorted(entry["skills"] + [ref])
                changed = True
    if changed:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", "utf-8")
    return changed


def create_skill(root: Path, name: str, description: str | None = None, marketplace: bool = True) -> list[Path]:
    root = Path(root)
    problem = name_problem(name)
    if problem:
        raise ValueError(problem)
    template = root / "skills" / TEMPLATE_DIR
    cases_template = root / "evals" / TEMPLATE_DIR / "cases.toml"
    if not (template / "SKILL.md").is_file():
        raise FileNotFoundError(f"missing template: {template / 'SKILL.md'}")
    if not cases_template.is_file():
        raise FileNotFoundError(f"missing template: {cases_template}")
    dest = root / "skills" / name
    evals_dest = root / "evals" / name
    for p in (dest, evals_dest):
        if p.exists():
            raise FileExistsError(f"{p} already exists")

    created: list[Path] = []
    try:
        shutil.copytree(template, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"))
        created.append(dest)
        skill_md = dest / "SKILL.md"
        skill_md.write_text(render_skill_md(skill_md.read_text("utf-8"), name, description), "utf-8")
        for md in dest.rglob("*.md"):
            if md != skill_md:
                md.write_text(PLACEHOLDER_RE.sub(name, md.read_text("utf-8")), "utf-8")

        (evals_dest / "runs").mkdir(parents=True)
        created.append(evals_dest)
        (evals_dest / "cases.toml").write_text(PLACEHOLDER_RE.sub(name, cases_template.read_text("utf-8")), "utf-8")
        (evals_dest / "runs" / ".gitkeep").write_text("", "utf-8")
        if marketplace and add_to_marketplace(root, name):
            created.append(root / ".claude-plugin" / "marketplace.json")
    except Exception:
        for p in (dest, evals_dest):
            if p in created:
                shutil.rmtree(p, ignore_errors=True)
        raise
    return created


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scaffold skills/<name> and evals/<name> from the templates.")
    ap.add_argument("name", help="skill name (lowercase letters, digits, single hyphens; max 64)")
    ap.add_argument("--description", help="frontmatter description (otherwise the template TODO stays)")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent), help="hub repo root")
    ap.add_argument("--no-marketplace", action="store_true", help="do not touch .claude-plugin/marketplace.json")
    args = ap.parse_args(argv)
    try:
        created = create_skill(Path(args.root), args.name, args.description, marketplace=not args.no_marketplace)
    except ValueError as e:
        print(f"new_skill: invalid name or template: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"new_skill: {e}", file=sys.stderr)
        return 2
    except FileExistsError as e:
        print(f"new_skill: refusing to overwrite: {e}", file=sys.stderr)
        return 1
    root = Path(args.root)
    for p in created:
        print(f"created/updated: {p.relative_to(root) if p.is_relative_to(root) else p}")
    print(f"next: fill skills/{args.name}/SKILL.md (all TODOs), write evals/{args.name}/cases.toml, then run "
          f"python3 scripts/validate_skills.py and add a row to the README skills table.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
