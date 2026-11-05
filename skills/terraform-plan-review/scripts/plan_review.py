#!/usr/bin/env python3
"""Review the blast radius of a saved Terraform or OpenTofu plan before apply.

Reads the JSON printed by `terraform show -json <planfile>` (OpenTofu:
`tofu show -json <planfile>`). It never runs terraform or tofu and never
contacts a provider. It reports:

  - counts by action, and every delete, replacement and forget, with the
    attribute that forces a replacement when the plan records it
  - stateful resources (databases, buckets, disks, keys and similar) being
    destroyed or replaced, as CRITICAL
  - virtual machines and Kubernetes clusters being destroyed or replaced, as HIGH
  - a delete and a create of the same type in one plan, which is often one
    object at a new address that a moved block would keep
  - changes that affect cost (listed only; no prices are estimated)

Permissions, exposure and deletion guards are reviewed by access_review.py.
Examples:
  plan_review.py plan.json
  plan_review.py plan.json --json
  plan_review.py plan.json --fail-on critical
  plan_review.py plan.json --stateful-type mongodbatlas_cluster
  terraform show -json tfplan | plan_review.py -

Exit codes: 0 = no finding at or above --fail-on (default: high),
1 = at least one such finding, 2 = usage or input error.

Standard library only. Reads one file or stdin, writes only to stdout and
stderr, makes no network calls. The resource type and attribute lists below
are finite: exit code 0 means none of these rules matched, not that the plan
is safe. Attribute values marked sensitive in the plan are never printed.
"""
import argparse
import json
import sys

SEVERITIES = ("critical", "high", "medium")
KINDS = ("create", "update", "replace", "delete", "forget", "no-op", "unknown")

# category -> (data impact, resource types). Destroying or replacing one of
# these is CRITICAL. Add types from other providers with --stateful-type.
STATEFUL = {
    "database or cache": (
        "the data it holds is destroyed with it unless a snapshot, backup or export is taken first",
        """aws_db_instance aws_rds_cluster aws_rds_global_cluster aws_dynamodb_table
        aws_redshift_cluster aws_docdb_cluster aws_neptune_cluster aws_opensearch_domain
        aws_elasticsearch_domain aws_elasticache_cluster aws_elasticache_replication_group
        aws_memorydb_cluster azurerm_mssql_server azurerm_mssql_database azurerm_mssql_managed_instance
        azurerm_postgresql_flexible_server azurerm_postgresql_flexible_server_database
        azurerm_mysql_flexible_server azurerm_mysql_flexible_database azurerm_cosmosdb_account
        azurerm_cosmosdb_sql_database azurerm_cosmosdb_sql_container azurerm_redis_cache
        google_sql_database_instance google_sql_database google_bigquery_dataset google_bigquery_table
        google_bigtable_instance google_bigtable_table google_spanner_instance google_spanner_database
        google_firestore_database google_redis_instance google_alloydb_cluster"""),
    "object storage": (
        "the objects stored in it go with it unless they are copied elsewhere first",
        "aws_s3_bucket azurerm_storage_account azurerm_storage_container google_storage_bucket"),
    "disk or file system": (
        "the data on it is destroyed with it unless a snapshot or copy is taken first",
        """aws_ebs_volume aws_efs_file_system aws_fsx_lustre_file_system aws_fsx_windows_file_system
        aws_fsx_ontap_file_system aws_fsx_openzfs_file_system azurerm_managed_disk azurerm_storage_share
        google_compute_disk google_compute_region_disk google_filestore_instance"""),
    "backup or snapshot": (
        "the recovery point it holds is gone, so restores that depend on it stop being possible",
        """aws_db_snapshot aws_db_cluster_snapshot aws_ebs_snapshot aws_backup_vault azurerm_snapshot
        azurerm_recovery_services_vault google_compute_snapshot"""),
    "key or secret": (
        "data encrypted under a deleted key cannot be decrypted, and deleted secret values are "
        "lost once any recovery window ends",
        """aws_kms_key aws_secretsmanager_secret azurerm_key_vault azurerm_key_vault_key
        azurerm_key_vault_secret azurerm_key_vault_certificate google_kms_key_ring google_kms_crypto_key
        google_secret_manager_secret"""),
    "queue or stream": (
        "messages not yet consumed are lost, and producers and consumers must be repointed",
        """aws_sqs_queue aws_kinesis_stream aws_msk_cluster azurerm_eventhub_namespace azurerm_eventhub
        azurerm_servicebus_namespace azurerm_servicebus_queue google_pubsub_topic
        google_pubsub_subscription"""),
    "log store": (
        "the logs it holds are deleted",
        "aws_cloudwatch_log_group azurerm_log_analytics_workspace google_logging_project_bucket_config"),
    "container registry": (
        "the images in it are deleted, so deployments that pull them fail",
        "aws_ecr_repository azurerm_container_registry google_artifact_registry_repository"),
    "DNS zone": (
        "its records are deleted, and a re-created zone can be given different name servers",
        "aws_route53_zone azurerm_dns_zone azurerm_private_dns_zone google_dns_managed_zone"),
    "identity store": (
        "the user accounts and credentials in it are deleted", "aws_cognito_user_pool"),
    "resource container": (
        "everything inside it goes with it, including resources this plan does not list",
        "azurerm_resource_group google_project"),
}
# Destroying or replacing one of these is HIGH.
DISRUPTIVE = {
    "virtual machine": (
        "its boot disk and instance-local data go with it unless they live on separately "
        "managed disks, and it can come back with different addresses",
        """aws_instance azurerm_linux_virtual_machine azurerm_windows_virtual_machine
        azurerm_virtual_machine google_compute_instance"""),
    "Kubernetes cluster": (
        "every workload on it stops, and its volumes follow their own reclaim policy",
        "aws_eks_cluster azurerm_kubernetes_cluster google_container_cluster"),
}
TYPE_INFO = {}
for _severity, _table in (("critical", STATEFUL), ("high", DISRUPTIVE)):
    for _category, (_impact, _types) in _table.items():
        for _type in _types.split():
            TYPE_INFO[_type] = (_severity, _category, _impact)

# Attribute names that usually drive cost when their value changes.
COST_KEYS = frozenset("""
    instance_type instance_class node_type machine_type vm_size size sku sku_name tier
    allocated_storage max_allocated_storage storage_type iops volume_size volume_type disk_size_gb
    storage_mb desired_capacity min_size max_size desired_size desired_count node_count
    num_cache_clusters number_of_nodes capacity read_capacity write_capacity billing_mode
    multi_az""".split())
NO_SAFETY_NET = {
    "skip_final_snapshot": "skip_final_snapshot is true in the current state, so no final snapshot is taken",
    "force_destroy": "force_destroy is true in the current state, so it is destroyed even if it is not empty",
}
REASONS = {
    "replace_because_tainted": "the object is tainted",
    "replace_because_cannot_update": "the provider cannot make this change in place",
    "replace_by_request": "replacement was requested with -replace",
    "replace_by_triggers": "a replace_triggered_by reference changed",
    "delete_because_no_resource_config": "its resource block is no longer in the configuration",
    "delete_because_no_module": "its module is no longer in the configuration",
    "delete_because_wrong_repetition": "count or for_each was added to or removed from its block",
    "delete_because_count_index": "its index is outside the new count",
    "delete_because_each_key": "its key is no longer in for_each",
    "delete_because_no_move_target": "a moved block points at an address with no resource block",
}


class PlanError(Exception):
    """The input is not a usable plan JSON document."""


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def fmt_path(path):
    text = ""
    for step in path:
        text += "[%d]" % step if isinstance(step, int) else ("." if text else "") + str(step)
    return text


def get_path(value, path):
    for step in path:
        if isinstance(value, dict) and step in value:
            value = value[step]
        elif isinstance(value, list) and isinstance(step, int) and 0 <= step < len(value):
            value = value[step]
        else:
            return None
    return value


def marked(marker, path):
    """True if a sensitive or unknown marker object is true at path or above it."""
    for step in path:
        if marker is True:
            return True
        marker = get_path(marker, [step])
    return marker is True


def show(change, side, path):
    """A printable attribute value. Sensitive, long and nested values are withheld."""
    if marked(change.get(side + "_sensitive"), path):
        return "(sensitive)"
    if side == "after" and marked(change.get("after_unknown"), path):
        return "(known after apply)"
    value = get_path(change.get(side), path)
    if value is None or isinstance(value, (bool, int, float)):
        return json.dumps(value)
    if isinstance(value, str) and len(value) <= 40:
        return json.dumps(value)
    return "(long or nested value, not shown)"


def diff_paths(before, after, path=()):
    """Yield the paths at which two values differ. Lists of unequal length differ as a whole."""
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            for item in diff_paths(before.get(key), after.get(key), path + (key,)):
                yield item
    elif isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        for index, (old, new) in enumerate(zip(before, after)):
            for item in diff_paths(old, new, path + (index,)):
                yield item
    elif before != after:
        yield path


def kind_of(actions):
    actions = tuple(actions or ())
    if "forget" in actions:
        return "forget"
    if actions in (("delete", "create"), ("create", "delete")):
        return "replace"
    if len(actions) == 1 and actions[0] in ("no-op", "create", "read", "update", "delete"):
        return actions[0]
    return "unknown"


def finding(severity, rule, index, rc, where, message, details=()):
    return {"severity": severity, "rule": rule, "address": rc["address"], "index": index,
            "message": message, "details": list(details),
            "evidence": "resource_changes[%d].change.%s" % (index, where)}


def managed_changes(plan):
    """Yield (index, entry, kind, before, after) for each managed resource change."""
    for index, rc in enumerate(plan.get("resource_changes") or []):
        change = rc.get("change") if isinstance(rc, dict) else None
        if not (isinstance(change, dict) and isinstance(rc.get("address"), str)
                and isinstance(rc.get("type"), str) and isinstance(change.get("actions"), list)
                and all(isinstance(action, str) for action in change["actions"])):
            raise PlanError("resource_changes[%d] lacks a string address and type, or a change "
                            "object with an actions list" % index)
        if rc.get("mode", "managed") != "managed":
            continue
        kind = kind_of(change["actions"])
        before = change.get("before") if isinstance(change.get("before"), dict) else {}
        after = change.get("after") if isinstance(change.get("after"), dict) else {}
        yield index, rc, "unknown" if kind == "read" else kind, before, after


def plan_notes(plan):
    """Plan-level facts the reader must know before trusting the findings."""
    notes = []
    version = str(plan.get("format_version"))
    if version.split(".")[0] not in ("0", "1"):
        notes.append("format_version %s is newer than this script was written for (1.x); "
                     "check its results by hand" % version)
    if plan.get("errored"):
        notes.append("the plan is marked errored: it is incomplete and cannot be applied as it is")
    if "resource_changes" not in plan:
        notes.append("the plan has no resource_changes key: it changes no resources")
    return notes


def check_removal(index, rc, kind, types, created=()):
    """Findings for a delete, a replacement or a forget."""
    change = rc["change"]
    severity, category, impact = types.get(rc["type"], ("medium", None, None))
    noun = category or "resource"
    if kind == "forget":
        return [finding("medium", "forget", index, rc, "actions",
                        "%s is removed from state without being destroyed" % noun,
                        ["the real object stays in the cloud account, running and unmanaged"])]
    details = []
    if kind == "delete":
        message = "%s is destroyed" % noun
    elif change["actions"][0] == "create":
        message = "%s is replaced: a new object is created, then the old one is destroyed" % noun
    else:
        message = "%s is replaced: the old object is destroyed, then a new one is created" % noun
    if rc.get("deposed"):
        details.append("this is a deposed object left behind by an earlier replacement")
    reason = rc.get("action_reason")
    if reason:
        details.append("reason: %s%s" % (reason, " (%s)" % REASONS[reason] if reason in REASONS else ""))
    where = "actions"
    if kind == "replace":
        paths = [p for p in as_list(change.get("replace_paths")) if isinstance(p, list)]
        if paths:
            where = "replace_paths"
            details.extend("forced by: %s (%s -> %s)" % (
                fmt_path(p), show(change, "before", p), show(change, "after", p)) for p in paths)
        else:
            details.append("forced by: not recorded in this plan (no replace_paths)")
    if category:
        details.append("data impact: " + impact)
    else:
        details.append("this type is not in the script's stateful list; confirm it holds no data")
    for attr, text in sorted(NO_SAFETY_NET.items()):
        if get_path(change.get("before"), [attr]) is True:
            details.append(text)
    if kind == "delete" and created:
        details.append("this plan also creates %s: if that is the same object at a new address, "
                       "a moved block avoids the destroy" % ", ".join(created))
    prefix = {"critical": "stateful-", "high": "disruptive-"}.get(severity, "")
    return [finding(severity, prefix + ("destroy" if kind == "delete" else "replace"),
                    index, rc, where, message, details)]


def review(plan, extra_stateful=()):
    """Analyse a parsed plan and return counts, notes, findings and cost changes."""
    types = dict(TYPE_INFO)
    for name in extra_stateful:
        types[name] = ("critical", "stateful resource (--stateful-type)", STATEFUL["database or cache"][0])
    counts = dict.fromkeys(KINDS, 0)
    findings, resized = [], []
    new, removed = {}, {}
    moved = imported = 0
    changes = list(managed_changes(plan))
    created = {}
    for _, rc, kind, _, _ in changes:
        if kind == "create":
            created.setdefault(rc["type"], []).append(rc["address"])
    for index, rc, kind, before, after in changes:
        change = rc["change"]
        counts[kind] += 1
        moved += bool(rc.get("previous_address")) and rc["previous_address"] != rc["address"]
        imported += bool(change.get("importing"))
        if kind in ("delete", "replace", "forget"):
            findings.extend(check_removal(index, rc, kind, types, created.get(rc["type"], ())))
        elif kind == "unknown":
            findings.append(finding("medium", "unrecognised-action", index, rc, "actions",
                                    "action list %s is not one this script understands; "
                                    "review this resource by hand" % json.dumps(change["actions"])))
        if kind == "create":
            new[rc["type"]] = new.get(rc["type"], 0) + 1
        elif kind == "delete":
            removed[rc["type"]] = removed.get(rc["type"], 0) + 1
        elif kind in ("update", "replace"):
            for path in diff_paths(before, after):
                names = [step for step in path if isinstance(step, str)]
                if names and names[-1] in COST_KEYS:
                    side = ("after" if get_path(after, path) is not None else
                            "after_unknown" if marked(change.get("after_unknown"), path) else "before")
                    resized.append({
                        "address": rc["address"], "attribute": fmt_path(path),
                        "before": show(change, "before", path), "after": show(change, "after", path),
                        "evidence": "resource_changes[%d].change.%s.%s" % (index, side, fmt_path(path))})
    notes = plan_notes(plan)
    drift = [d.get("address", "?") for d in as_list(plan.get("resource_drift")) if isinstance(d, dict)]
    if drift:
        notes.append("%d object(s) changed outside Terraform since the last apply (resource_drift): "
                     "%s%s" % (len(drift), ", ".join(drift[:5]), ", ..." if len(drift) > 5 else ""))
    if moved:
        notes.append("%d resource(s) moved to a new address (previous_address is set)" % moved)
    if imported:
        notes.append("%d resource(s) imported into state by this plan (change.importing is set)" % imported)
    data_reads = sum(1 for rc in plan.get("resource_changes") or []
                     if rc.get("mode") == "data" and kind_of(rc["change"]["actions"]) == "read")
    if data_reads:
        notes.append("%d data source(s) are read during apply" % data_reads)
    return {"counts": counts, "notes": notes, "findings": findings,
            "cost_changes": {"new": new, "removed": removed, "resized": resized}}


def load_plan(path):
    try:
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
    except UnicodeDecodeError:
        raise PlanError("%s is not text. If it is the binary plan file, convert it first: "
                        "terraform show -json %s > plan.json" % (path, path))
    except OSError as exc:
        raise PlanError("cannot read %s: %s" % (path, exc.strerror or exc))
    try:
        plan = json.loads(text)
    except ValueError as exc:
        hint = ""
        if '"@level"' in text[:2000]:
            hint = (". This looks like the line-by-line log from `terraform plan -json`; "
                    "use `terraform show -json <planfile>` instead")
        raise PlanError("%s is not valid JSON (%s)%s" % (path, exc, hint))
    if not isinstance(plan, dict) or "format_version" not in plan:
        raise PlanError("%s has no format_version, so it is not the output of "
                        "`terraform show -json <planfile>`" % path)
    if "resource_changes" not in plan and "planned_values" not in plan:
        raise PlanError("%s has neither resource_changes nor planned_values. It looks like state "
                        "or schema JSON; pass the plan file to `terraform show -json`" % path)
    if not isinstance(plan.get("resource_changes", []), list):
        raise PlanError("resource_changes in %s is not a list" % path)
    return plan


def print_cost(result):
    cost = result["cost_changes"]
    if not (cost["new"] or cost["removed"] or cost["resized"]):
        return
    print("")
    print("changes that can affect cost (no prices estimated; not every type listed is billed):")
    for label in ("new", "removed"):
        if cost[label]:
            print("    %-8s %s" % (label + ":", ", ".join(
                "%s x%d" % pair for pair in sorted(cost[label].items()))))
    for item in cost["resized"]:
        print("    resized: %s  %s: %s -> %s" % (
            item["address"], item["attribute"], item["before"], item["after"]))
    print("    run a cost tool on this plan if you have one")


def make_parser(prog, doc):
    parser = argparse.ArgumentParser(
        prog=prog, description=doc, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("plan", help="plan JSON from `terraform show -json <planfile>`, or - for stdin")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="high",
                        help="lowest severity that makes the exit code 1 (default: high)")
    return parser


def run(parser, args, analyse, print_extra=None):
    """Load the plan, analyse it, print text or JSON, and return the exit code."""
    try:
        plan = load_plan(args.plan)
        result = analyse(plan)
    except PlanError as exc:
        print("%s: error: %s" % (parser.prog, exc), file=sys.stderr)
        return 2
    except (AttributeError, KeyError, TypeError) as exc:
        print("%s: error: %s does not have the documented plan JSON shape (%s: %s)" % (
            parser.prog, args.plan, type(exc).__name__, exc), file=sys.stderr)
        return 2
    findings = sorted(result["findings"], key=lambda f: (
        SEVERITIES.index(f["severity"]), f["index"], f["rule"], f["message"]))
    limit = SEVERITIES.index(args.fail_on)
    result.update({
        "plan": {"path": "(stdin)" if args.plan == "-" else args.plan,
                 "format_version": plan.get("format_version"),
                 "terraform_version": plan.get("terraform_version")},
        "findings": findings, "fail_on": args.fail_on,
        "summary": dict((s, sum(1 for f in findings if f["severity"] == s)) for s in SEVERITIES),
        "blocking": any(SEVERITIES.index(f["severity"]) <= limit for f in findings),
    })
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if result["blocking"] else 0
    print("plan: %s   format_version: %s   terraform_version: %s" % (
        result["plan"]["path"], result["plan"]["format_version"], result["plan"]["terraform_version"]))
    print("actions: " + (", ".join(
        "%s %d" % (kind, result["counts"][kind]) for kind in KINDS if result["counts"][kind]) or "none"))
    for note in result["notes"]:
        print("note: " + note)
    for item in findings:
        print("")
        print("%-8s  %s  %s" % (item["severity"].upper(), item["rule"], item["address"]))
        for line in [item["message"]] + item["details"] + ["evidence: " + item["evidence"]]:
            print("    " + line)
    if print_extra:
        print_extra(result)
    print("")
    print("RESULT: %s   %s   (blocking level: %s)" % (
        "BLOCKING" if result["blocking"] else "no blocking finding",
        ", ".join("%d %s" % (result["summary"][s], s) for s in SEVERITIES), args.fail_on))
    if not result["blocking"]:
        print("This is not an approval. The script checks a fixed list of resource types and rules.")
    return 1 if result["blocking"] else 0


def main(argv=None):
    parser = make_parser("plan_review.py", __doc__)
    parser.add_argument("--stateful-type", action="append", default=[], metavar="TYPE",
                        help="also treat this resource type as stateful (CRITICAL when destroyed "
                             "or replaced); repeatable")
    args = parser.parse_args(argv)
    return run(parser, args, lambda plan: review(plan, args.stateful_type), print_cost)


if __name__ == "__main__":
    sys.exit(main())
