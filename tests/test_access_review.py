import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "terraform-plan-review"
FIXTURES = SKILL / "evals" / "files"
SCRIPT = SKILL / "scripts" / "access_review.py"
sys.path.insert(0, str(SKILL / "scripts"))

import access_review  # noqa: E402


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = access_review.main([str(arg) for arg in argv])
    return code, out.getvalue(), err.getvalue()


def change(address, actions, before=None, after=None, **extra):
    rtype, name = address.split(".")[-2:]
    entry = {"address": address, "mode": "managed", "type": rtype, "name": name,
             "change": {"actions": actions, "before": before, "after": after, "after_unknown": {}}}
    for key in ("after_unknown", "after_sensitive"):
        if key in extra:
            entry["change"][key] = extra.pop(key)
    entry.update(extra)
    return entry


def policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def allow(**fields):
    statement = {"Effect": "Allow"}
    statement.update(fields)
    return statement


def triples(result):
    return [(f["severity"], f["rule"], f["address"]) for f in result["findings"]]


def resolve(document, evidence):
    value = document
    for name, index in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]", evidence):
        value = value[name] if name else value[int(index)]
    return value


class PlanFileCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def review(self, *changes):
        path = self.dir / "plan.json"
        path.write_text(json.dumps({"format_version": "1.2", "resource_changes": list(changes)}),
                        encoding="utf-8")
        code, out, err = run(path, "--json")
        self.assertEqual(err, "")
        return code, json.loads(out)

    def findings(self, *changes):
        return [(f["severity"], f["rule"], f["message"]) for f in self.review(*changes)[1]["findings"]]


class PolicyGrantTests(unittest.TestCase):
    def grants(self, *statements):
        return access_review.policy_grants(policy(*statements))

    def test_full_wildcard_is_high(self):
        self.assertEqual(self.grants(allow(Action="*", Resource="*")),
                         {'Allow Action * on Resource "*"': ("iam-wildcard", "high")})

    def test_service_wildcard_is_high_and_names_only_the_wildcards(self):
        grants = self.grants(allow(Action=["s3:*", "ec2:DescribeInstances"],
                                   Resource="arn:aws:s3:::bucket/*"))
        self.assertEqual(grants, {"Allow Action s3:*": ("iam-wildcard", "high")})

    def test_partial_wildcard_is_not_flagged(self):
        self.assertEqual(self.grants(allow(Action="s3:Get*", Resource="arn:aws:s3:::bucket/*")), {})

    def test_resource_star_with_named_actions_is_medium(self):
        grants = self.grants(allow(Action=["ec2:DescribeInstances"], Resource=["*"]))
        self.assertEqual(grants, {'Allow Action ec2:DescribeInstances on Resource "*"':
                                  ("iam-wildcard", "medium")})

    def test_not_action_and_not_resource_are_wildcards(self):
        grants = self.grants(allow(NotAction="iam:*", NotResource="arn:aws:s3:::audit/*"))
        self.assertEqual(grants, {
            "Allow every action except those in NotAction on every resource except those in NotResource":
            ("iam-wildcard", "high")})

    def test_deny_statements_are_ignored(self):
        self.assertEqual(self.grants({"Effect": "Deny", "Action": "*", "Resource": "*", "Principal": "*"}), {})

    def test_public_principal_forms(self):
        for principal in ("*", {"AWS": "*"}, {"AWS": ["arn:aws:iam::111122223333:root", "*"]}):
            grants = self.grants(allow(Principal=principal, Action="s3:GetObject",
                                       Resource="arn:aws:s3:::bucket/*"))
            self.assertEqual(grants, {'Allow Principal "*" (anyone), Action s3:GetObject':
                                      ("public-principal", "high")})

    def test_public_principal_with_a_condition_is_medium(self):
        grants = self.grants(allow(Principal="*", Action="s3:GetObject", Resource="arn:aws:s3:::b/*",
                                   Condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}}))
        self.assertEqual(list(grants.values()), [("public-principal", "medium")])

    def test_trust_policy_for_a_service_is_not_flagged(self):
        self.assertEqual(self.grants(allow(Principal={"Service": "ec2.amazonaws.com"},
                                           Action="sts:AssumeRole")), {})

    def test_single_statement_object_is_accepted(self):
        text = json.dumps({"Statement": allow(Action="*", Resource="*")})
        self.assertEqual(len(access_review.policy_grants(text)), 1)

    def test_values_that_are_not_policies_give_nothing(self):
        for value in (None, 5, True, "hello", "{not json \"Statement\"", '{"a": 1}', '["Statement"]',
                      '{"Statement": "x"}'):
            self.assertEqual(access_review.policy_grants(value), {})


class PolicyChangeTests(PlanFileCase):
    def test_only_added_grants_are_reported(self):
        wide = allow(Action="*", Resource="*")
        narrow = allow(Action="s3:GetObject", Resource="arn:aws:s3:::b/*")
        unchanged = change("aws_iam_policy.a", ["update"], {"policy": policy(wide)},
                           {"policy": policy(wide, narrow), "description": "new"})
        self.assertEqual(self.findings(unchanged), [])
        added = change("aws_iam_policy.a", ["update"], {"policy": policy(narrow)},
                       {"policy": policy(narrow, wide)})
        self.assertEqual(self.findings(added),
                         [("high", "iam-wildcard", 'policy gains: Allow Action * on Resource "*"')])

    def test_policies_in_nested_blocks_and_other_attributes_are_found(self):
        role = change("aws_iam_role.a", ["create"], None, {
            "assume_role_policy": policy(allow(Principal={"AWS": "*"}, Action="sts:AssumeRole")),
            "inline_policy": [{"name": "x", "policy": policy(allow(Action="iam:*", Resource="*"))}]})
        _, result = self.review(role)
        self.assertEqual([(f["rule"], f["evidence"]) for f in result["findings"]], [
            ("iam-wildcard", "resource_changes[0].change.after.inline_policy[0].policy"),
            ("public-principal", "resource_changes[0].change.after.assume_role_policy")])

    def test_reordered_nested_policies_are_not_new(self):
        first = {"name": "a", "policy": policy(allow(Action="s3:*", Resource="*"))}
        second = {"name": "b", "policy": policy(allow(Action="sqs:*", Resource="*"))}
        role = change("aws_iam_role.a", ["update"], {"inline_policy": [first, second]},
                      {"inline_policy": [second, first]})
        self.assertEqual(self.findings(role), [])

    def test_sensitive_policy_is_reported_without_its_content(self):
        entry = change("aws_iam_policy.a", ["create"], None,
                       {"policy": policy(allow(Action="secretservice:*", Resource="*"))},
                       after_sensitive={"policy": True})
        code, result = self.review(entry)
        self.assertEqual(code, 1)
        self.assertNotIn("secretservice", json.dumps(result))
        self.assertEqual(result["findings"][0]["message"],
                         "iam-wildcard finding on a value the plan marks sensitive; the value is not shown")

    def test_other_values_marked_sensitive_are_not_printed(self):
        entries = [
            change("aws_security_group.a", ["create"], None,
                   {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
                   after_sensitive={"ingress": [{"cidr_blocks": True}]}),
            change("google_project_iam_member.b", ["create"], None,
                   {"role": "roles/owner", "member": "user:hidden@example.com"},
                   after_sensitive={"member": True}),
            change("google_project_iam_binding.c", ["create"], None,
                   {"role": "roles/viewer", "members": ["allUsers"]}, after_sensitive={"members": [True]}),
            change("azurerm_storage_container.d", ["create"], None, {"container_access_type": "blob"},
                   after_sensitive={"container_access_type": True}),
        ]
        code, result = self.review(*entries)
        self.assertEqual(code, 1)
        self.assertEqual([f["rule"] for f in result["findings"]],
                         ["open-ingress", "broad-role", "public-principal", "public-access"])
        for item in result["findings"]:
            self.assertIn("marks sensitive", item["message"])
        text = json.dumps(result)
        for hidden in ("0.0.0.0/0", "hidden@example.com", "allUsers", "blob"):
            self.assertNotIn(hidden, text)

    def test_deleted_resources_are_not_checked_for_grants(self):
        entry = change("aws_iam_policy.a", ["delete"], {"policy": policy(allow(Action="*", Resource="*"))})
        self.assertEqual(self.findings(entry), [])


class IngressTests(PlanFileCase):
    def rule(self, **fields):
        base = {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
        base.update(fields)
        return base

    def test_security_group_ingress_is_reported_and_egress_is_not(self):
        group = change("aws_security_group.a", ["create"], None,
                       {"ingress": [self.rule(cidr_blocks=["10.0.0.0/8"]), self.rule()],
                        "egress": [self.rule(protocol="-1", from_port=0, to_port=0)]})
        _, result = self.review(group)
        self.assertEqual([(f["message"], f["evidence"]) for f in result["findings"]], [
            ("inbound traffic is allowed from 0.0.0.0/0, protocol tcp, ports 22-22",
             "resource_changes[0].change.after.ingress[1].cidr_blocks")])

    def test_ipv6_world_range_and_all_protocols(self):
        group = change("aws_security_group.a", ["create"], None, {"ingress": [self.rule(
            cidr_blocks=[], ipv6_cidr_blocks=["::/0"], protocol="-1", from_port=0, to_port=0)]})
        self.assertEqual(self.findings(group), [
            ("high", "open-ingress", "inbound traffic is allowed from ::/0, all protocols, ports 0-0")])

    def test_existing_open_rule_is_not_reported_again(self):
        before = {"ingress": [self.rule(from_port=443, to_port=443)], "tags": {}}
        after = {"ingress": [self.rule(from_port=443, to_port=443)], "tags": {"a": "b"}}
        self.assertEqual(self.findings(change("aws_security_group.a", ["update"], before, after)), [])

    def test_widening_an_existing_rule_is_reported(self):
        before = {"ingress": [self.rule(cidr_blocks=["10.0.0.0/8"])]}
        after = {"ingress": [self.rule()]}
        self.assertEqual(len(self.findings(change("aws_security_group.a", ["update"], before, after))), 1)

    def test_security_group_rule_direction(self):
        ingress = change("aws_security_group_rule.a", ["create"], None, self.rule(type="ingress"))
        egress = change("aws_security_group_rule.b", ["create"], None, self.rule(type="egress"))
        self.assertEqual(triples(self.review(ingress, egress)[1]),
                         [("high", "open-ingress", "aws_security_group_rule.a")])

    def test_vpc_ingress_rule_resource(self):
        rule = change("aws_vpc_security_group_ingress_rule.a", ["create"], None,
                      {"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1", "from_port": None, "to_port": None})
        self.assertEqual(self.findings(rule), [
            ("high", "open-ingress", "inbound traffic is allowed from 0.0.0.0/0, all protocols, ports all")])
        egress = change("aws_vpc_security_group_egress_rule.a", ["create"], None,
                        {"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1"})
        self.assertEqual(self.findings(egress), [])

    def azure_rule(self, **fields):
        base = {"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                "source_address_prefix": "*", "destination_port_range": "22"}
        base.update(fields)
        return base

    def test_azure_rule_direction_access_and_source(self):
        entries = [
            change("azurerm_network_security_rule.open", ["create"], None, self.azure_rule()),
            change("azurerm_network_security_rule.tag", ["create"], None,
                   self.azure_rule(source_address_prefix="Internet")),
            change("azurerm_network_security_rule.many", ["create"], None, self.azure_rule(
                source_address_prefix=None, source_address_prefixes=["10.0.0.0/8", "0.0.0.0/0"])),
            change("azurerm_network_security_rule.out", ["create"], None, self.azure_rule(direction="Outbound")),
            change("azurerm_network_security_rule.deny", ["create"], None, self.azure_rule(access="Deny")),
            change("azurerm_network_security_rule.vnet", ["create"], None,
                   self.azure_rule(source_address_prefix="VirtualNetwork")),
        ]
        self.assertEqual([f["address"] for f in self.review(*entries)[1]["findings"]], [
            "azurerm_network_security_rule.open", "azurerm_network_security_rule.tag",
            "azurerm_network_security_rule.many"])

    def test_azure_security_group_inline_rules(self):
        group = change("azurerm_network_security_group.a", ["create"], None, {"security_rule": [
            self.azure_rule(direction="Outbound"), self.azure_rule(destination_port_range="3389")]})
        _, result = self.review(group)
        self.assertEqual(result["findings"][0]["evidence"],
                         "resource_changes[0].change.after.security_rule[1].source_address_prefix")
        self.assertIn("ports 3389", result["findings"][0]["message"])

    def test_google_firewall_direction_deny_and_disabled(self):
        base = {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp", "ports": ["22"]}], "deny": []}
        entries = [
            change("google_compute_firewall.open", ["create"], None, base),
            change("google_compute_firewall.egress", ["create"], None, dict(
                base, direction="EGRESS", destination_ranges=["0.0.0.0/0"])),
            change("google_compute_firewall.deny", ["create"], None, dict(
                base, allow=[], deny=[{"protocol": "all", "ports": []}])),
            change("google_compute_firewall.off", ["create"], None, dict(base, disabled=True)),
            change("google_compute_firewall.tags", ["create"], None, dict(
                base, source_ranges=None, source_tags=["bastion"])),
        ]
        self.assertEqual(triples(self.review(*entries)[1]),
                         [("high", "open-ingress", "google_compute_firewall.open")])


class RoleTests(PlanFileCase):
    def test_azure_broad_roles(self):
        entries = [change("azurerm_role_assignment.r%d" % i, ["create"], None,
                          {"role_definition_name": name, "scope": "/subscriptions/x"})
                   for i, name in enumerate(["Owner", "Contributor", "User Access Administrator", "Reader"])]
        self.assertEqual([f["address"] for f in self.review(*entries)[1]["findings"]], [
            "azurerm_role_assignment.r0", "azurerm_role_assignment.r1", "azurerm_role_assignment.r2"])

    def test_azure_custom_role_wildcard(self):
        wide = {"permissions": [{"actions": ["*"], "not_actions": []}]}
        narrow = {"permissions": [{"actions": ["Microsoft.Compute/*/read"], "not_actions": []}]}
        self.assertEqual(self.findings(change("azurerm_role_definition.a", ["update"], narrow, wide)),
                         [("high", "iam-wildcard", 'custom role gains the action "*"')])
        self.assertEqual(self.findings(change("azurerm_role_definition.a", ["update"], wide, wide)), [])

    def test_google_binding_reports_added_members_only(self):
        before = {"role": "roles/owner", "members": ["user:a@example.com", "user:b@example.com"]}
        grown = dict(before, members=["user:a@example.com", "user:b@example.com", "user:c@example.com"])
        shrunk = dict(before, members=["user:a@example.com"])
        self.assertEqual(self.findings(change("google_project_iam_binding.a", ["update"], before, grown)), [
            ("high", "broad-role", "grants the broad built-in role roles/owner to user:c@example.com")])
        self.assertEqual(self.findings(change("google_project_iam_binding.a", ["update"], before, shrunk)), [])

    def test_google_narrow_role_is_not_flagged(self):
        entry = change("google_project_iam_member.a", ["create"], None,
                       {"role": "roles/viewer", "member": "user:a@example.com"})
        self.assertEqual(self.findings(entry), [])

    def test_google_public_members(self):
        for member in ("allUsers", "allAuthenticatedUsers"):
            entry = change("google_storage_bucket_iam_member.a", ["create"], None,
                           {"role": "roles/storage.objectViewer", "member": member})
            self.assertEqual(triples(self.review(entry)[1]),
                             [("high", "public-principal", "google_storage_bucket_iam_member.a")])

    def test_aws_administrator_access_attachment(self):
        admin = "arn:aws:iam::aws:policy/AdministratorAccess"
        attach = change("aws_iam_role_policy_attachment.a", ["create"], None, {"role": "r", "policy_arn": admin})
        other = change("aws_iam_role_policy_attachment.b", ["create"], None,
                       {"role": "r", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
        role = change("aws_iam_role.c", ["update"], {"managed_policy_arns": []}, {"managed_policy_arns": [admin]})
        self.assertEqual(triples(self.review(attach, other, role)[1]), [
            ("high", "broad-role", "aws_iam_role_policy_attachment.a"), ("high", "broad-role", "aws_iam_role.c")])


class PublicSettingTests(PlanFileCase):
    def test_turning_a_setting_on_is_high(self):
        entry = change("aws_db_instance.a", ["update"], {"publicly_accessible": False},
                       {"publicly_accessible": True})
        self.assertEqual(self.findings(entry), [
            ("high", "public-access", "publicly_accessible changes from false to true, which turns a public-access setting on")])

    def test_unchanged_public_setting_is_not_reported(self):
        entry = change("aws_db_instance.a", ["update"], {"publicly_accessible": True, "x": 1},
                       {"publicly_accessible": True, "x": 2})
        self.assertEqual(self.findings(entry), [])

    def test_creation_severity_depends_on_the_provider_default(self):
        chosen = change("aws_db_instance.a", ["create"], None, {"publicly_accessible": True})
        default = change("azurerm_mssql_server.a", ["create"], None, {"public_network_access_enabled": True})
        self.assertEqual([f[:2] for f in self.findings(chosen, default)],
                         [("high", "public-access"), ("medium", "public-access")])

    def test_bucket_acl_and_container_access(self):
        acl = change("aws_s3_bucket_acl.a", ["update"], {"acl": "private"}, {"acl": "public-read"})
        container = change("azurerm_storage_container.a", ["update"], {"container_access_type": "private"},
                           {"container_access_type": "container"})
        private = change("aws_s3_bucket_acl.b", ["create"], None, {"acl": "private"})
        self.assertEqual(triples(self.review(acl, container, private)[1]), [
            ("high", "public-access", "aws_s3_bucket_acl.a"),
            ("high", "public-access", "azurerm_storage_container.a")])

    def test_public_access_block_weakened(self):
        before = {"block_public_acls": True, "block_public_policy": True}
        after = {"block_public_acls": False, "block_public_policy": True}
        entry = change("aws_s3_bucket_public_access_block.a", ["update"], before, after)
        self.assertEqual(self.findings(entry), [
            ("high", "public-access", "block_public_acls changes from true to false, which turns a public-access setting on")])


class GuardTests(PlanFileCase):
    def test_guards_turned_off_by_an_update(self):
        cases = [("deletion_protection", True, False), ("deletion_protection", "ACTIVE", "INACTIVE"),
                 ("deletion_protection_enabled", True, False), ("enable_deletion_protection", True, False),
                 ("disable_api_termination", True, False), ("skip_final_snapshot", False, True),
                 ("force_destroy", False, True)]
        for attr, old, new in cases:
            entry = change("aws_thing.a", ["update"], {attr: old}, {attr: new})
            self.assertEqual([f[:2] for f in self.findings(entry)], [("high", "guard-removed")], attr)

    def test_guard_turned_on_or_unset_is_not_reported(self):
        entries = [
            change("aws_thing.a", ["update"], {"deletion_protection": False}, {"deletion_protection": True}),
            change("aws_thing.b", ["update"], {"deletion_protection": None}, {"deletion_protection": False}),
            change("aws_thing.c", ["update"], {"force_destroy": True}, {"force_destroy": True}),
            change("aws_thing.d", ["create"], None, {"deletion_protection": False, "force_destroy": True}),
        ]
        self.assertEqual(self.findings(*entries), [])

    def test_deleting_a_guard_resource_is_reported(self):
        entries = [change("aws_s3_bucket_public_access_block.a", ["delete"], {"bucket": "b"}),
                   change("azurerm_management_lock.b", ["delete"], {"lock_level": "CanNotDelete"})]
        self.assertEqual([f[:2] for f in self.findings(*entries)],
                         [("high", "guard-removed"), ("high", "guard-removed")])


class UnknownTests(PlanFileCase):
    def test_unknown_policy_network_source_and_member(self):
        entries = [
            change("aws_iam_role_policy.a", ["create"], None, {"role": "r"}, after_unknown={"policy": True}),
            change("aws_iam_role.b", ["create"], None, {}, after_unknown={"assume_role_policy": True}),
            change("aws_s3_bucket_policy.c", ["create"], None, {}, after_unknown={"policy": True}),
            change("aws_security_group_rule.d", ["create"], None, {"type": "ingress"},
                   after_unknown={"cidr_blocks": True}),
            change("aws_security_group.e", ["create"], None, {"ingress": [{"from_port": 22}]},
                   after_unknown={"ingress": [{"cidr_blocks": True}]}),
            change("google_project_iam_member.f", ["create"], None, {"role": "roles/viewer"},
                   after_unknown={"member": True}),
        ]
        _, result = self.review(*entries)
        self.assertEqual([(f["rule"], f["evidence"]) for f in result["findings"]], [
            ("unknown-until-apply", "resource_changes[0].change.after_unknown.policy"),
            ("unknown-until-apply", "resource_changes[1].change.after_unknown.assume_role_policy"),
            ("unknown-until-apply", "resource_changes[2].change.after_unknown.policy"),
            ("unknown-until-apply", "resource_changes[3].change.after_unknown.cidr_blocks"),
            ("unknown-until-apply", "resource_changes[4].change.after_unknown.ingress[0].cidr_blocks"),
            ("unknown-until-apply", "resource_changes[5].change.after_unknown.member"),
        ])
        self.assertTrue(all(f["severity"] == "medium" for f in result["findings"]))

    def test_provider_computed_attributes_are_not_reported(self):
        entries = [
            change("aws_s3_bucket.a", ["create"], None, {"bucket": "b"},
                   after_unknown={"policy": True, "acl": True, "arn": True}),
            change("aws_security_group.b", ["create"], None, {"name": "n"},
                   after_unknown={"ingress": True, "egress": True, "id": True}),
            change("aws_iam_policy.c", ["create"], None, {"policy": "{}"},
                   after_unknown={"arn": True, "policy_id": True}),
            change("aws_iam_role_policy_attachment.d", ["create"], None, {}, after_unknown={"policy_arn": True}),
        ]
        self.assertEqual(self.findings(*entries), [])


class FixtureTests(unittest.TestCase):
    def result(self, name, *flags):
        code, out, err = run(FIXTURES / name / "plan.json", "--json", *flags)
        self.assertEqual(err, "")
        return code, json.loads(out)

    def test_permission_widening_reports_each_planted_change(self):
        code, result = self.result("permission-widening")
        self.assertEqual(code, 1)
        self.assertEqual(triples(result), [
            ("high", "iam-wildcard", "aws_iam_policy.deploy"),
            ("high", "public-principal", "aws_s3_bucket_policy.reports"),
            ("high", "open-ingress", "aws_security_group_rule.ssh"),
            ("high", "public-access", "aws_s3_bucket_public_access_block.reports"),
            ("high", "public-access", "aws_s3_bucket_public_access_block.reports"),
            ("high", "guard-removed", "aws_db_instance.orders"),
            ("high", "public-access", "aws_db_instance.orders"),
            ("high", "broad-role", "aws_iam_role_policy_attachment.worker_admin"),
            ("medium", "iam-wildcard", "aws_iam_role_policy.ci_pull"),
            ("medium", "unknown-until-apply", "aws_iam_role_policy.worker_queue"),
        ])
        self.assertEqual(result["summary"], {"critical": 0, "high": 8, "medium": 2})
        addresses = [f["address"] for f in result["findings"]]
        self.assertNotIn("aws_security_group.internal", addresses)
        self.assertNotIn("aws_iam_role.worker", addresses)

    def test_azure_fixture_reports_each_planted_change(self):
        code, result = self.result("azure-risks")
        self.assertEqual(code, 1)
        self.assertEqual(triples(result), [
            ("high", "open-ingress", "azurerm_network_security_rule.rdp"),
            ("high", "broad-role", "azurerm_role_assignment.ops_owner"),
            ("high", "public-access", "azurerm_storage_container.exports"),
            ("high", "guard-removed", "azurerm_management_lock.billing"),
            ("high", "public-access", "azurerm_storage_account.logs"),
        ])

    def test_gcp_fixture_reports_each_planted_change(self):
        code, result = self.result("gcp-risks")
        self.assertEqual(code, 1)
        self.assertEqual(triples(result), [
            ("high", "open-ingress", "google_compute_firewall.allow_admin"),
            ("high", "broad-role", "google_project_iam_member.contractor_owner"),
            ("high", "public-principal", "google_storage_bucket_iam_member.public_exports"),
            ("high", "guard-removed", "google_sql_database_instance.orders"),
            ("high", "guard-removed", "google_storage_bucket.assets"),
            ("high", "public-access", "google_storage_bucket.assets"),
            ("high", "broad-role", "google_project_iam_binding.editors"),
            ("medium", "unknown-until-apply", "google_service_account_iam_member.deployer"),
        ])

    def test_fixtures_without_access_changes_have_no_finding_at_any_level(self):
        for name in ("low-risk", "forced-replacement", "rename-refactor"):
            code, result = self.result(name, "--fail-on", "medium")
            self.assertEqual(code, 0, name)
            self.assertEqual(result["findings"], [], name)

    def test_every_finding_cites_evidence_that_exists_in_the_plan(self):
        for path in sorted(FIXTURES.glob("*/plan.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            _, out, _ = run(path, "--json")
            for item in json.loads(out)["findings"]:
                try:
                    resolve(document, item["evidence"])
                except (KeyError, IndexError, TypeError):
                    self.fail("%s: evidence %s is not in the plan" % (path.parent.name, item["evidence"]))

    def test_fail_on_critical_does_not_block_on_high_findings(self):
        code, result = self.result("permission-widening", "--fail-on", "critical")
        self.assertEqual(code, 0)
        self.assertFalse(result["blocking"])

    def test_output_is_deterministic(self):
        path = FIXTURES / "permission-widening" / "plan.json"
        self.assertEqual(run(path), run(path))


class CommandLineTests(unittest.TestCase):
    def test_script_runs_from_another_directory_and_in_isolated_mode(self):
        path = FIXTURES / "gcp-risks" / "plan.json"
        with tempfile.TemporaryDirectory() as elsewhere:
            for flags in (["-B"], ["-B", "-I"]):
                proc = subprocess.run([sys.executable] + flags + [str(SCRIPT), str(path)], cwd=elsewhere,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(proc.returncode, 1, proc.stderr.decode())
                self.assertIn("RESULT: BLOCKING   0 critical, 7 high, 1 medium", proc.stdout.decode())

    def test_input_errors_exit_2_without_a_traceback(self):
        code, out, err = run(ROOT / "README.md")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("access_review.py: error:", err)
        self.assertNotIn("Traceback", err)

    def test_help_shows_examples_and_exit_codes(self):
        proc = subprocess.run([sys.executable, "-B", str(SCRIPT), "--help"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        text = proc.stdout.decode()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Examples:", text)
        self.assertIn("Exit codes:", text)


if __name__ == "__main__":
    unittest.main()
