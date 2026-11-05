#!/usr/bin/env python3
"""Review a saved Terraform or OpenTofu plan for loosened access and protection.

Reads the same JSON as plan_review.py: the output of
`terraform show -json <planfile>` (OpenTofu: `tofu show -json <planfile>`).
It compares each resource's value before and after the change and reports
only what the change adds:

  - IAM-style policy documents that gain a wildcard action, Resource "*",
    or Principal "*"
  - broad built-in roles being granted (Azure Owner, Contributor, User Access
    Administrator; Google roles/owner, roles/editor; AWS AdministratorAccess)
    and public members (allUsers, allAuthenticatedUsers)
  - inbound network rules opened to 0.0.0.0/0 or ::/0
  - public-access settings turned on
  - deletion protection and similar guards turned off, and guard resources
    (S3 public access block, Azure management lock) being deleted
  - policy documents, network sources and principals whose value is known
    only after apply, so they could not be reviewed

Examples:
  access_review.py plan.json
  access_review.py plan.json --json
  access_review.py plan.json --fail-on medium
  terraform show -json tfplan | access_review.py -

Exit codes: 0 = no finding at or above --fail-on (default: high),
1 = at least one such finding, 2 = usage or input error.

Standard library only. Reads one file or stdin, writes only to stdout and
stderr, makes no network calls. Imports its plan loader and output code from
plan_review.py, which must sit in the same directory. The resource types and
attributes below are a fixed list: exit code 0 means none of these rules
matched, not that the plan grants nothing new. From the plan it prints only
IAM action names, role names, members, CIDR ranges, ports and the values of
the settings it checks, and none of those when the plan marks them sensitive.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from plan_review import (  # noqa: E402
    KINDS, as_list, finding, fmt_path, make_parser, managed_changes, marked, plan_notes, run)

# attribute -> values that mean the guard is off. Checked on in-place updates.
GUARDS_OFF = {
    "deletion_protection": (False, "INACTIVE"), "deletion_protection_enabled": (False,),
    "enable_deletion_protection": (False,), "disable_api_termination": (False,),
    "skip_final_snapshot": (True,), "force_destroy": (True,),
}
# Deleting one of these resources removes a guard from something else.
GUARD_RESOURCES = {
    "aws_s3_bucket_public_access_block": "the bucket's public access block is removed with it",
    "azurerm_management_lock": "the delete or read-only lock on its scope is removed with it",
}
PUBLIC_ACLS = ("public-read", "public-read-write")
# (type, or prefix ending in *), attribute, values that mean public, and whether
# the provider default is private (so a public value at creation is a choice).
PUBLIC_SETTINGS = (
    ("aws_db_instance", "publicly_accessible", (True,), True),
    ("aws_rds_cluster_instance", "publicly_accessible", (True,), True),
    ("aws_redshift_cluster", "publicly_accessible", (True,), False),
    ("aws_s3_bucket_public_access_block", "block_public_acls", (False,), False),
    ("aws_s3_bucket_public_access_block", "block_public_policy", (False,), False),
    ("aws_s3_bucket_public_access_block", "ignore_public_acls", (False,), False),
    ("aws_s3_bucket_public_access_block", "restrict_public_buckets", (False,), False),
    ("aws_s3_bucket_acl", "acl", PUBLIC_ACLS, True),
    ("aws_s3_bucket", "acl", PUBLIC_ACLS, True),
    ("azurerm_storage_account", "allow_nested_items_to_be_public", (True,), False),
    ("azurerm_storage_container", "container_access_type", ("blob", "container"), True),
    ("azurerm_*", "public_network_access_enabled", (True,), False),
    ("google_storage_bucket", "public_access_prevention", ("inherited",), False),
)
BROAD_ROLES = {
    "role_definition_name": ("Owner", "Contributor", "User Access Administrator"),
    "role": ("roles/owner", "roles/editor"),
}
PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")
WORLD = ("0.0.0.0/0", "::/0")
AZURE_WORLD = WORLD + ("*", "internet", "any")
AWS_SOURCES = ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6")
AZURE_SOURCES = ("source_address_prefix", "source_address_prefixes")
# Types whose network source arguments are checked for unknown values.
UNKNOWN_NETWORK_TYPES = (
    "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
    "azurerm_network_security_group", "azurerm_network_security_rule")


def walk(value, path=()):
    """Yield (path, leaf) for every scalar leaf, in a stable order."""
    if isinstance(value, dict):
        for key in sorted(value):
            for item in walk(value[key], path + (key,)):
                yield item
    elif isinstance(value, list):
        for index, child in enumerate(value):
            for item in walk(child, path + (index,)):
                yield item
    else:
        yield path, value


def policy_grants(text):
    """Broad Allow statements in an IAM-style JSON policy: {description: (rule, severity)}."""
    if not (isinstance(text, str) and text.lstrip().startswith("{") and '"Statement"' in text):
        return {}
    try:
        doc = json.loads(text)
    except ValueError:
        return {}
    grants = {}
    for st in as_list(doc.get("Statement")) if isinstance(doc, dict) else []:
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        actions = sorted(str(a) for a in as_list(st.get("Action")))
        named = "Action " + ", ".join(actions)
        wild = [a for a in actions if a == "*" or a.endswith(":*")]
        broad = "Action " + ", ".join(wild) if wild else ""
        if "NotAction" in st:
            named = broad = "every action except those in NotAction"
        target = ""
        if "*" in as_list(st.get("Resource")):
            target = ' on Resource "*"'
        elif "NotResource" in st:
            target = " on every resource except those in NotResource"
        principal = st.get("Principal")
        holders = principal.values() if isinstance(principal, dict) else [principal]
        if any("*" in as_list(holder) for holder in holders):
            limited = bool(st.get("Condition"))
            grants['Allow Principal "*" (anyone), %s%s' % (
                named, ", limited only by its Condition" if limited else "")] = (
                    "public-principal", "medium" if limited else "high")
        if broad:
            grants["Allow %s%s" % (broad, target)] = ("iam-wildcard", "high")
        elif target:
            grants["Allow %s%s" % (named, target)] = ("iam-wildcard", "medium")
    return grants


def check_policies(index, rc, before, after):
    """Policy documents (JSON strings anywhere in the resource) that gain a broad grant."""
    had = {}
    for _, leaf in walk(before):
        had.update(policy_grants(leaf))
    out = []
    for path, leaf in walk(after):
        for text, (rule, severity) in sorted(policy_grants(leaf).items()):
            if text not in had:
                shown = text if len(text) <= 200 else text[:197] + "..."
                out.append(finding(severity, rule, index, rc, "after." + fmt_path(path),
                                   "policy gains: " + shown))
    return out


def strings(obj, *keys):
    """The string values of several attributes of one resource value, as a set."""
    return set(str(item) for key in keys for item in as_list(obj.get(key)))


def check_roles(index, rc, before, after):
    """Broad built-in roles, public members and wildcard custom roles being granted."""
    out = []
    added = sorted(strings(after, "member", "members") - strings(before, "member", "members"))
    for key, names in sorted(BROAD_ROLES.items()):
        role = after.get(key)
        if isinstance(role, str) and role in names and (before.get(key) != role or added):
            out.append(finding("high", "broad-role", index, rc, "after." + key,
                               "grants the broad built-in role %s%s" % (
                                   role, " to " + ", ".join(added) if added else "")))
    for member in added:
        if member in PUBLIC_MEMBERS:
            key = "member" if "member" in after else "members"
            out.append(finding("high", "public-principal", index, rc, "after." + key,
                               "grants %s to %s, which is not limited to your organisation" % (
                                   after.get("role"), member)))
    arn_keys = ("policy_arn", "managed_policy_arns")
    for arn in sorted(strings(after, *arn_keys) - strings(before, *arn_keys)):
        if arn.endswith(":policy/AdministratorAccess"):
            key = "policy_arn" if "policy_arn" in after else "managed_policy_arns"
            out.append(finding("high", "broad-role", index, rc, "after." + key,
                               "attaches the AWS managed policy AdministratorAccess"))
    if rc["type"] == "azurerm_role_definition":
        def wild(obj):
            return any("*" in as_list(block.get("actions"))
                       for block in as_list(obj.get("permissions")) if isinstance(block, dict))
        if wild(after) and not wild(before):
            out.append(finding("high", "iam-wildcard", index, rc, "after.permissions",
                               'custom role gains the action "*"'))
    return out


def open_ingress(rtype, obj):
    """World-open inbound rules in one resource value: {description: attribute path}."""
    found = {}

    def add(prefix, block, keys, world, protocol, ports):
        for key in keys:
            for source in as_list(block.get(key)):
                if str(source).lower() in world:
                    every = str(protocol) in ("-1", "*", "all")
                    found["%s, %s, ports %s" % (
                        source, "all protocols" if every else "protocol %s" % protocol, ports)] = prefix + key

    def aws(prefix, block):
        low, high = block.get("from_port"), block.get("to_port")
        add(prefix, block, AWS_SOURCES, WORLD, block.get("protocol", block.get("ip_protocol")),
            "all" if low is None else "%s-%s" % (low, high))

    def azure(prefix, block):
        if str(block.get("direction")).lower() == "inbound" and str(block.get("access")).lower() == "allow":
            ports = as_list(block.get("destination_port_range")) + as_list(block.get("destination_port_ranges"))
            add(prefix, block, AZURE_SOURCES, AZURE_WORLD, block.get("protocol"),
                ",".join(str(port) for port in ports))

    def blocks(key):
        return [(i, block) for i, block in enumerate(as_list(obj.get(key))) if isinstance(block, dict)]

    if rtype == "aws_security_group":
        for i, block in blocks("ingress"):
            aws("ingress[%d]." % i, block)
    elif rtype == "aws_security_group_rule" and obj.get("type") == "ingress":
        aws("", obj)
    elif rtype == "aws_vpc_security_group_ingress_rule":
        aws("", obj)
    elif rtype == "azurerm_network_security_rule":
        azure("", obj)
    elif rtype == "azurerm_network_security_group":
        for i, block in blocks("security_rule"):
            azure("security_rule[%d]." % i, block)
    elif rtype == "google_compute_firewall" and obj.get("direction") != "EGRESS" and not obj.get("disabled"):
        for _, block in blocks("allow"):
            add("", obj, ("source_ranges",), WORLD, block.get("protocol"),
                ",".join(str(port) for port in as_list(block.get("ports"))) or "all")
    return found


def check_exposure(index, rc, before, after):
    """Ingress opened to the world and public-access settings turned on."""
    out = []
    rtype = rc["type"]
    was_open = open_ingress(rtype, before)
    for text, where in sorted(open_ingress(rtype, after).items()):
        if text not in was_open:
            out.append(finding("high", "open-ingress", index, rc, "after." + where,
                               "inbound traffic is allowed from " + text))
    for pattern, attr, public, default_private in PUBLIC_SETTINGS:
        if rtype != pattern and not (pattern.endswith("*") and rtype.startswith(pattern[:-1])):
            continue
        old, new = before.get(attr), after.get(attr)
        if new not in public or old in public:
            continue
        if before:
            out.append(finding("high", "public-access", index, rc, "after." + attr,
                               "%s changes from %s to %s, which turns a public-access setting on" % (
                                   attr, json.dumps(old), json.dumps(new))))
        else:
            out.append(finding("high" if default_private else "medium", "public-access", index, rc,
                               "after." + attr, "created with %s = %s, a public-access setting" % (
                                   attr, json.dumps(new))))
    return out


def check_guards(index, rc, kind, before, after):
    """Deletion protection and similar guards turned off or deleted."""
    out = []
    if kind == "delete" and rc["type"] in GUARD_RESOURCES:
        out.append(finding("high", "guard-removed", index, rc, "actions", GUARD_RESOURCES[rc["type"]]))
    for attr, off in sorted(GUARDS_OFF.items()) if kind == "update" else ():
        old, new = before.get(attr), after.get(attr)
        if old is not None and new is not None and new in off and old not in off:
            out.append(finding("high", "guard-removed", index, rc, "after." + attr,
                               "%s changes from %s to %s, which removes a guard against deletion" % (
                                   attr, json.dumps(old), json.dumps(new))))
    return out


def check_unknown(index, rc):
    """Security-relevant arguments whose value is known only after apply."""
    rtype = rc["type"]
    if rtype.startswith("aws_") and (rtype.startswith("aws_iam_") or rtype.endswith("_policy")):
        keys, what = ("policy", "assume_role_policy"), "policy document"
    elif rtype in UNKNOWN_NETWORK_TYPES:
        keys, what = AWS_SOURCES + AZURE_SOURCES, "network source"
    elif rtype.startswith("google_") and "_iam_" in rtype:
        keys, what = ("member", "members"), "principal"
    else:
        return []
    out = []
    for path, leaf in walk(rc["change"].get("after_unknown")):
        names = [step for step in path if isinstance(step, str)]
        if leaf is True and names and names[-1] in keys:
            out.append(finding("medium", "unknown-until-apply", index, rc,
                               "after_unknown." + fmt_path(path),
                               "%s (%s) is known only after apply, so it was not reviewed" % (
                                   fmt_path(path), what),
                               ["read the configuration that produces this value before approving"]))
    return out


def withhold_sensitive(rc, findings):
    """Blank the text of findings that would print a value the plan marks sensitive."""
    marker = rc["change"].get("after_sensitive")
    members = isinstance(marker, dict) and (marker.get("member") or marker.get("members"))
    for item in findings:
        tail = item["evidence"].partition(".change.after.")[2]
        path = [int(number) if number else name
                for name, number in re.findall(r"([^.\[\]]+)|\[(\d+)\]", tail)]
        if tail and (marked(marker, path) or (members and item["rule"] in ("broad-role", "public-principal"))):
            item["message"] = "%s finding on a value the plan marks sensitive; the value is not shown" % item["rule"]
    return findings


def review(plan):
    """Analyse a parsed plan and return counts, notes and findings."""
    counts = dict.fromkeys(KINDS, 0)
    findings = []
    for index, rc, kind, before, after in managed_changes(plan):
        counts[kind] += 1
        found = check_guards(index, rc, kind, before, after)
        if kind in ("create", "update", "replace"):
            found.extend(check_policies(index, rc, before, after))
            found.extend(check_roles(index, rc, before, after))
            found.extend(check_exposure(index, rc, before, after))
            found.extend(check_unknown(index, rc))
        findings.extend(withhold_sensitive(rc, found))
    return {"counts": counts, "notes": plan_notes(plan), "findings": findings}


def main(argv=None):
    parser = make_parser("access_review.py", __doc__)
    args = parser.parse_args(argv)
    return run(parser, args, review)


if __name__ == "__main__":
    sys.exit(main())
