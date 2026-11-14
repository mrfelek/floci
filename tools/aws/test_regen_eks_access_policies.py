"""Tests for regen_eks_access_policies.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import json

import pytest

import regen_eks_access_policies as r

PERMISSIONS = """
# Review access policy permissions

## List all policies

```
{
    "accessPolicies": [
        {
            "name": "AmazonExampleOnlyPolicy",
            "arn": "arn:aws:eks::aws:cluster-access-policy/AmazonExampleOnlyPolicy"
        }
    ]
}
```

## AmazonEKSClusterAdminPolicy

 **ARN** – ` arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy`

| Kubernetes API groups | Kubernetes nonResourceURLs | Kubernetes resources | Kubernetes verbs (permissions) |
| --- | --- | --- | --- |
|  `*`  |  |  `*`  |  `*`  |
|  |  `*`  |  |  `*`  |

## AmazonEKSArgoCDClusterPolicy

 **ARN** – ` arn:aws:eks::aws:cluster-access-policy/AmazonEKSArgoCDClusterPolicy`

| Kubernetes API groups | Kubernetes resources | Kubernetes verbs (permissions) |
| --- | --- | --- |
|  |  `configmaps` (`argocd-notifications-cm` only) |  `get`, `list`  |
|  `apiextensions.k8s.io`  |  `customresourcedefinitions` (Argo CD CRDs only) |  `get`  |
|  |  `pods`, `services`  |  `watch`  |

## AmazonEKSAutoNodePolicy

 **ARN** – ` arn:aws:eks::aws:cluster-access-policy/AmazonEKSAutoNodePolicy`

This policy includes permissions described in prose only.

## Access policy updates

Changes to the policies on this page.
"""

LISTING = """
## Response Syntax

```
{ "accessPolicies": [ { "arn": "arn:aws:eks::aws:cluster-access-policy/AmazonApiOnlyPolicy" } ] }
```
"""


def policies(catalog: dict) -> dict:
    return {policy["name"]: policy["rules"] for policy in catalog["policies"]}


def test_each_named_policy_is_listed_once_sorted_with_its_rules_or_none():
    catalog = r.generate(PERMISSIONS, LISTING)

    assert catalog["sources"] == r.SOURCES
    assert [policy["name"] for policy in catalog["policies"]] == [
        "AmazonApiOnlyPolicy", "AmazonEKSArgoCDClusterPolicy", "AmazonEKSAutoNodePolicy",
        "AmazonEKSClusterAdminPolicy", "AmazonExampleOnlyPolicy"]
    assert policies(catalog)["AmazonEKSAutoNodePolicy"] is None
    assert policies(catalog)["AmazonExampleOnlyPolicy"] is None
    assert policies(catalog)["AmazonApiOnlyPolicy"] is None
    assert r.check(catalog) == []


def test_a_row_becomes_an_rbac_rule_with_the_core_group_names_and_notes():
    rules = policies(r.generate(PERMISSIONS, LISTING))

    assert rules["AmazonEKSClusterAdminPolicy"] == [
        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
        {"nonResourceURLs": ["*"], "verbs": ["*"]},
    ]
    assert rules["AmazonEKSArgoCDClusterPolicy"] == [
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["argocd-notifications-cm"],
         "verbs": ["get", "list"]},
        {"apiGroups": ["apiextensions.k8s.io"], "resources": ["customresourcedefinitions"], "verbs": ["get"],
         "note": "Argo CD CRDs only"},
        {"apiGroups": [""], "resources": ["pods", "services"], "verbs": ["watch"]},
    ]


def test_a_section_naming_another_policys_arn_is_refused():
    page = PERMISSIONS.replace("## AmazonEKSAutoNodePolicy", "## AmazonEKSSomethingElse")
    with pytest.raises(ValueError, match="AmazonEKSSomethingElse"):
        r.generate(page, LISTING)


def test_an_unknown_column_is_refused_rather_than_dropped():
    page = PERMISSIONS.replace("| Kubernetes API groups | Kubernetes resources |",
                               "| Kubernetes API groups | Kubernetes scopes |", 1)
    with pytest.raises(ValueError, match="Kubernetes scopes"):
        r.generate(page, LISTING)


def test_check_reports_a_malformed_catalog():
    catalog = r.generate(PERMISSIONS, LISTING)
    catalog["policies"].reverse()
    catalog["policies"][0]["rules"] = [{"apiGroups": [""], "resources": ["pods"]}]

    assert r.check(catalog) == [
        "policy names must be sorted and unique",
        "AmazonExampleOnlyPolicy: a rule needs verbs and resources or nonResourceURLs",
    ]


def test_verify_passes_on_the_current_file_and_fails_once_the_pages_change(tmp_path):
    (tmp_path / "access-policy-permissions.md").write_text(PERMISSIONS, encoding="utf-8")
    (tmp_path / "API_ListAccessPolicies.md").write_text(LISTING, encoding="utf-8")
    output = tmp_path / "access-policies.json"
    output.write_text(r.render(r.generate(PERMISSIONS, LISTING)), encoding="utf-8")

    assert r.main(["--verify", "--source-dir", str(tmp_path), "--output", str(output)]) == 0
    assert r.main(["--check", "--output", str(output)]) == 0

    (tmp_path / "API_ListAccessPolicies.md").write_text(
        LISTING.replace("AmazonApiOnlyPolicy", "AmazonNewPolicy"), encoding="utf-8")
    assert r.main(["--verify", "--source-dir", str(tmp_path), "--output", str(output)]) == 1
    assert json.loads(output.read_text(encoding="utf-8")) == r.generate(PERMISSIONS, LISTING)
