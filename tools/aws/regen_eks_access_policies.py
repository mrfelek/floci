#!/usr/bin/env python3
"""Regenerate src/main/resources/eks/access-policies.json from the Amazon EKS documentation.

EKS publishes its cluster access policies' Kubernetes permissions only in the User Guide: the API
answers ListAccessPolicies with names and ARNs alone ("You can't view the contents of an access
policy using the API"). So the sources are two documentation pages, read as the Markdown AWS serves
at each page's URL with `.md` in place of `.html`:

- PERMISSIONS_URL, the access policy permissions page: one section per policy, headed by the
  policy's name, with its ARN and, for most, a table of the Kubernetes API groups, resources,
  nonResourceURLs and verbs it grants. Its example `aws eks list-access-policies` output names a
  few more policies.
- LIST_URL, the ListAccessPolicies API Reference, whose sample response names policies too.

A policy that either page names is in the catalog. Its rules are its table's rows, in the page's
order, or null when the page describes its permissions in prose only. A row's cells become a
Kubernetes RBAC rule: the code spans of each cell, with a blank API groups cell beside resources
read as the core group (""), as the tables write it. A resources cell may qualify its resources in
parentheses: named resources, "(`argocd-notifications-cm` only)", become the rule's resourceNames;
a description, "(Argo CD CRDs only)", is kept as the rule's note, since the page names no resource.
Nothing is hand-typed.

ARNs are partition-relative (`arn:<partition>:eks::aws:cluster-access-policy/<name>`), so the
catalog keeps names only and Floci builds each ARN in the request's partition.

The pages are live, so a fresh generation follows AWS: `--check` is offline and structural (CI),
`--verify` regenerates and fails when the vendored file differs, exiting 2 when a page can't be read.

Run from anywhere in the repo:
    python3 tools/aws/regen_eks_access_policies.py              # rewrite the vendored file in place
    python3 tools/aws/regen_eks_access_policies.py --check      # offline: the vendored file's shape
    python3 tools/aws/regen_eks_access_policies.py --verify     # online: the vendored file is current
    python3 tools/aws/regen_eks_access_policies.py --source-dir <dir>   # read saved pages instead
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / "src/main/resources/eks/access-policies.json"
PERMISSIONS_URL = "https://docs.aws.amazon.com/eks/latest/userguide/access-policy-permissions.md"
LIST_URL = "https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAccessPolicies.md"
SOURCES = [PERMISSIONS_URL, LIST_URL]
FETCH_TIMEOUT_SECONDS = 30

POLICY_NAME = re.compile(r"[A-Za-z0-9]+")
POLICY_ARN = re.compile(r"arn:aws:eks::aws:cluster-access-policy/([A-Za-z0-9]+)")
SECTION_ARN = re.compile(r"\*\*ARN\*\*[^`\n]*`\s*arn:aws:eks::aws:cluster-access-policy/([A-Za-z0-9]+)\s*`")
CODE = re.compile(r"`([^`]*)`")
QUALIFIER = re.compile(r"\(([^()]*)\)\s*$")
# Each table column the pages use, and the rule field its code spans become.
COLUMNS = {
    "Kubernetes API groups": "apiGroups",
    "Kubernetes resources": "resources",
    "Kubernetes nonResourceURLs": "nonResourceURLs",
    "Kubernetes verbs (permissions)": "verbs",
}
RULE_FIELDS = ["apiGroups", "resources", "resourceNames", "nonResourceURLs", "verbs", "note"]


def sections(markdown: str) -> list[tuple[str, str]]:
    """The page's `## ` sections, as (heading, body)."""
    parts = re.split(r"^## (.+)$", markdown, flags=re.MULTILINE)
    return [(parts[i].strip(), parts[i + 1]) for i in range(1, len(parts), 2)]


def cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def rule(header: list[str], row: list[str]) -> dict:
    if len(row) != len(header):
        raise ValueError(f"a table row has {len(row)} cells under {len(header)} headers: {row}")
    fields: dict = {}
    for column, cell in zip(header, row):
        field = COLUMNS[column]
        if field == "resources":
            qualifier = QUALIFIER.search(cell)
            if qualifier:
                named = CODE.findall(qualifier.group(1))
                if named:
                    fields["resourceNames"] = named
                else:
                    fields["note"] = qualifier.group(1).strip()
                cell = cell[:qualifier.start()]
        values = CODE.findall(cell)
        if values:
            fields[field] = [value.strip() for value in values]
    if "resources" in fields and "apiGroups" not in fields:
        fields["apiGroups"] = [""]
    if "verbs" not in fields or not ("resources" in fields or "nonResourceURLs" in fields):
        raise ValueError(f"a table row grants no verb or names nothing: {row}")
    return {field: fields[field] for field in RULE_FIELDS if field in fields}


def rules(body: str) -> list[dict] | None:
    """The rows of every table in a policy's section, or None when it has no table."""
    found: list[dict] = []
    lines = body.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith("|") and "Kubernetes" in lines[i]:
            header = cells(lines[i])
            unknown = [column for column in header if column not in COLUMNS]
            if unknown:
                raise ValueError(f"unknown table columns {unknown}")
            i += 2  # the header and its separator
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                found.append(rule(header, cells(lines[i])))
                i += 1
        else:
            i += 1
    return found or None


def generate(permissions: str, listing: str) -> dict:
    policies: dict[str, list[dict] | None] = {}
    for heading, body in sections(permissions):
        arn = SECTION_ARN.search(body)
        if arn is None:
            continue
        if arn.group(1) != heading:
            raise ValueError(f"section {heading!r} gives the ARN of {arn.group(1)!r}")
        policies[heading] = rules(body)
    for name in POLICY_ARN.findall(permissions) + POLICY_ARN.findall(listing):
        policies.setdefault(name, None)
    if not policies:
        raise ValueError("no access policy found in the documentation")
    return {"sources": SOURCES,
            "policies": [{"name": name, "rules": policies[name]} for name in sorted(policies)]}


def check(catalog: dict) -> list[str]:
    """What is wrong with the vendored catalog's shape, or nothing."""
    problems = []
    if catalog.get("sources") != SOURCES:
        problems.append(f"sources must be {SOURCES}")
    names = [policy.get("name") for policy in catalog.get("policies", [])]
    if not names:
        problems.append("no policies")
    if names != sorted(set(names)):
        problems.append("policy names must be sorted and unique")
    for policy in catalog.get("policies", []):
        name = policy.get("name")
        if not isinstance(name, str) or not POLICY_NAME.fullmatch(name):
            problems.append(f"invalid policy name {name!r}")
        if set(policy) != {"name", "rules"}:
            problems.append(f"{name}: fields must be name and rules")
        for entry in policy.get("rules") or []:
            if not entry.get("verbs") or not (entry.get("resources") or entry.get("nonResourceURLs")):
                problems.append(f"{name}: a rule needs verbs and resources or nonResourceURLs")
            if set(entry) - set(RULE_FIELDS):
                problems.append(f"{name}: unknown rule fields {sorted(set(entry) - set(RULE_FIELDS))}")
            for field in set(entry) & set(RULE_FIELDS) - {"note"}:
                if not isinstance(entry[field], list) or not all(isinstance(v, str) for v in entry[field]):
                    problems.append(f"{name}: {field} must be a list of strings")
    return problems


def fetch(url: str, source_dir: Path | None) -> str:
    if source_dir is not None:
        return (source_dir / url.rsplit("/", 1)[1]).read_text(encoding="utf-8")
    with urllib.request.urlopen(urllib.request.Request(url), timeout=FETCH_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8")


def render(catalog: dict) -> str:
    return json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="offline: exit 1 when the vendored file is malformed")
    parser.add_argument("--verify", action="store_true", help="online: exit 1 when the vendored file is not current")
    parser.add_argument("--source-dir", type=Path, help="read the two pages, saved under their file names, from here")
    parser.add_argument("--output", type=Path, default=OUTPUT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.check:
        problems = check(json.loads(args.output.read_text(encoding="utf-8")))
        for problem in problems:
            print(f"{args.output.name}: {problem}", file=sys.stderr)
        return 1 if problems else 0

    try:
        pages = fetch(PERMISSIONS_URL, args.source_dir), fetch(LIST_URL, args.source_dir)
    except (urllib.error.URLError, OSError) as e:
        print(f"could not read the EKS documentation: {e}", file=sys.stderr)
        return 2
    fresh = generate(*pages)
    if args.verify:
        vendored = json.loads(args.output.read_text(encoding="utf-8"))
        if vendored == fresh:
            return 0
        old = {policy["name"]: policy for policy in vendored.get("policies", [])}
        new = {policy["name"]: policy for policy in fresh["policies"]}
        changed = sorted(name for name in old.keys() | new.keys() if old.get(name) != new.get(name))
        print(f"{args.output.name} is not current; regenerate it. Changed policies: {', '.join(changed)}",
              file=sys.stderr)
        return 1
    args.output.write_text(render(fresh), encoding="utf-8")
    print(f"wrote {len(fresh['policies'])} access policies to {args.output.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
