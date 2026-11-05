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
SCRIPT = SKILL / "scripts" / "plan_review.py"
sys.path.insert(0, str(SKILL / "scripts"))

import plan_review  # noqa: E402

SECRET = "example-only-not-a-real-password"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = plan_review.main([str(arg) for arg in argv])
    return code, out.getvalue(), err.getvalue()


def change(address, actions, before=None, after=None, **extra):
    rtype, name = address.split(".")[-2:]
    entry = {"address": address, "mode": "managed", "type": rtype, "name": name,
             "change": {"actions": actions, "before": before, "after": after, "after_unknown": {}}}
    for key in ("replace_paths", "after_unknown", "before_sensitive", "after_sensitive", "importing"):
        if key in extra:
            entry["change"][key] = extra.pop(key)
    entry.update(extra)
    return entry


def make_plan(*changes, **top):
    plan = {"format_version": "1.2", "terraform_version": "1.9.5", "resource_changes": list(changes)}
    plan.update(top)
    return plan


def triples(result):
    return [(f["severity"], f["rule"], f["address"]) for f in result["findings"]]


def resolve(document, evidence):
    """Follow an evidence path such as resource_changes[2].change.after.ingress[0] into the plan."""
    value = document
    for name, index in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]", evidence):
        value = value[name] if name else value[int(index)]
    return value


class PlanFileCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def write(self, document, name="plan.json"):
        path = self.dir / name
        text = document if isinstance(document, str) else json.dumps(document)
        path.write_text(text, encoding="utf-8")
        return path

    def review(self, document, *flags):
        code, out, err = run(self.write(document), "--json", *flags)
        self.assertEqual(err, "")
        return code, json.loads(out)


class KindTests(unittest.TestCase):
    def test_single_actions(self):
        for action in ("no-op", "create", "read", "update", "delete"):
            self.assertEqual(plan_review.kind_of([action]), action)

    def test_both_replacement_orders_are_replace(self):
        self.assertEqual(plan_review.kind_of(["delete", "create"]), "replace")
        self.assertEqual(plan_review.kind_of(["create", "delete"]), "replace")

    def test_forget_actions(self):
        self.assertEqual(plan_review.kind_of(["forget"]), "forget")
        self.assertEqual(plan_review.kind_of(["create", "forget"]), "forget")

    def test_anything_else_is_unknown(self):
        self.assertEqual(plan_review.kind_of(["explode"]), "unknown")
        self.assertEqual(plan_review.kind_of([]), "unknown")
        self.assertEqual(plan_review.kind_of(["update", "delete"]), "unknown")


class HelperTests(unittest.TestCase):
    def test_fmt_path_mixes_names_and_indexes(self):
        self.assertEqual(plan_review.fmt_path(["ingress", 0, "cidr_blocks"]), "ingress[0].cidr_blocks")
        self.assertEqual(plan_review.fmt_path(["tags", "Name"]), "tags.Name")

    def test_get_path_returns_none_when_missing(self):
        value = {"a": [{"b": 1}]}
        self.assertEqual(plan_review.get_path(value, ["a", 0, "b"]), 1)
        self.assertIsNone(plan_review.get_path(value, ["a", 3, "b"]))
        self.assertIsNone(plan_review.get_path(value, ["x"]))

    def test_marked_is_true_at_or_below_a_true_marker(self):
        self.assertTrue(plan_review.marked({"password": True}, ["password"]))
        self.assertTrue(plan_review.marked({"settings": True}, ["settings", 0, "tier"]))
        self.assertFalse(plan_review.marked({"password": True}, ["username"]))
        self.assertFalse(plan_review.marked(False, ["password"]))

    def test_show_withholds_sensitive_unknown_and_long_values(self):
        entry = {"before": {"password": "hunter2", "size": 5, "user_data": "x" * 200, "az": "a"},
                 "after": {"password": "hunter3", "size": 10}, "after_unknown": {"az": True},
                 "before_sensitive": {"password": True}, "after_sensitive": {"password": True}}
        self.assertEqual(plan_review.show(entry, "before", ["password"]), "(sensitive)")
        self.assertEqual(plan_review.show(entry, "after", ["password"]), "(sensitive)")
        self.assertEqual(plan_review.show(entry, "after", ["az"]), "(known after apply)")
        self.assertEqual(plan_review.show(entry, "before", ["az"]), '"a"')
        self.assertEqual(plan_review.show(entry, "after", ["size"]), "10")
        self.assertEqual(plan_review.show(entry, "before", ["user_data"]), "(long or nested value, not shown)")
        self.assertEqual(plan_review.show(entry, "after", ["missing"]), "null")

    def test_diff_paths_reports_changed_leaves(self):
        before = {"size": 1, "tags": {"a": "x"}, "disks": [{"size": 10}], "ports": [1, 2]}
        after = {"size": 2, "tags": {"a": "x"}, "disks": [{"size": 20}], "ports": [1]}
        self.assertEqual(list(plan_review.diff_paths(before, after)),
                         [("disks", 0, "size"), ("ports",), ("size",)])


class FixtureTests(unittest.TestCase):
    def result(self, name, *flags):
        code, out, err = run(FIXTURES / name / "plan.json", "--json", *flags)
        self.assertEqual(err, "")
        return code, json.loads(out)

    def test_forced_replacement_reports_each_planted_replacement(self):
        code, result = self.result("forced-replacement")
        self.assertEqual(code, 1)
        self.assertTrue(result["blocking"])
        self.assertEqual(triples(result), [
            ("critical", "stateful-replace", "aws_db_instance.orders"),
            ("critical", "stateful-replace", "aws_ebs_volume.orders_data"),
            ("high", "disruptive-replace", "aws_instance.worker"),
            ("medium", "destroy", "aws_route53_record.legacy_api"),
        ])
        self.assertEqual(result["counts"], {"create": 0, "update": 2, "replace": 3, "delete": 1,
                                            "forget": 0, "no-op": 1, "unknown": 0})
        self.assertEqual(result["summary"], {"critical": 2, "high": 1, "medium": 1})

    def test_forced_replacement_names_the_forcing_attribute(self):
        _, result = self.result("forced-replacement")
        database, volume, instance = result["findings"][:3]
        self.assertIn("forced by: storage_encrypted (false -> true)", database["details"])
        self.assertEqual(database["evidence"], "resource_changes[0].change.replace_paths")
        self.assertIn('forced by: availability_zone ("eu-west-1a" -> "eu-west-1b")', volume["details"])
        self.assertIn("a new object is created, then the old one is destroyed", instance["message"])
        self.assertIn("the old object is destroyed, then a new one is created", database["message"])
        self.assertTrue(any(line.startswith("data impact: ") for line in database["details"]))
        self.assertIn("skip_final_snapshot is true in the current state, so no final snapshot is taken",
                      database["details"])

    def test_forced_replacement_lists_cost_changes_without_prices(self):
        _, result = self.result("forced-replacement")
        resized = [(r["address"], r["attribute"], r["before"], r["after"])
                   for r in result["cost_changes"]["resized"]]
        self.assertEqual(resized, [
            ("aws_autoscaling_group.web", "desired_capacity", "3", "6"),
            ("aws_autoscaling_group.web", "max_size", "6", "12"),
            ("aws_launch_template.web", "instance_type", '"m6i.large"', '"m6i.2xlarge"'),
        ])
        self.assertEqual(result["cost_changes"]["removed"], {"aws_route53_record": 1})
        _, text, _ = run(FIXTURES / "forced-replacement" / "plan.json")
        self.assertIn("no prices estimated", text)
        self.assertNotRegex(text, r"[$€£]|USD|per month")

    def test_sensitive_values_in_the_plan_are_never_printed(self):
        for name in ("forced-replacement", "rename-refactor", "permission-widening", "low-risk"):
            path = FIXTURES / name / "plan.json"
            self.assertIn(SECRET, path.read_text(encoding="utf-8"))
            for flags in ((), ("--json",)):
                _, out, _ = run(path, *flags)
                self.assertNotIn(SECRET, out)

    def test_rename_refactor_reports_stateful_destroys_and_points_at_moved_blocks(self):
        code, result = self.result("rename-refactor")
        self.assertEqual(code, 1)
        self.assertEqual(triples(result), [
            ("critical", "stateful-destroy", "aws_db_instance.orders"),
            ("critical", "stateful-destroy", "aws_s3_bucket.uploads"),
            ("medium", "destroy", "aws_security_group.app"),
        ])
        hint = result["findings"][0]["details"][-1]
        self.assertIn("module.database.aws_db_instance.orders", hint)
        self.assertIn("moved block", hint)
        self.assertIn("1 resource(s) moved to a new address (previous_address is set)", result["notes"])

    def test_azure_fixture_reports_the_database_destroy(self):
        code, result = self.result("azure-risks")
        self.assertEqual(code, 1)
        self.assertEqual(triples(result), [
            ("critical", "stateful-destroy", "azurerm_mssql_database.billing"),
            ("medium", "destroy", "azurerm_management_lock.billing"),
        ])
        self.assertEqual(result["cost_changes"]["resized"][0]["attribute"], "size")

    def test_gcp_fixture_reports_the_key_destroy_and_nested_resize(self):
        code, result = self.result("gcp-risks")
        self.assertEqual(code, 1)
        self.assertEqual(triples(result), [
            ("critical", "stateful-destroy", "google_kms_crypto_key.orders_data")])
        resized = result["cost_changes"]["resized"][0]
        self.assertEqual(resized["attribute"], "settings[0].tier")
        self.assertEqual(resized["evidence"], "resource_changes[4].change.after.settings[0].tier")

    def test_permission_fixture_has_no_destroy_or_replace(self):
        code, result = self.result("permission-widening")
        self.assertEqual(code, 0)
        self.assertEqual(result["findings"], [])

    def test_low_risk_fixture_has_no_finding_at_any_level(self):
        code, result = self.result("low-risk", "--fail-on", "medium")
        self.assertEqual(code, 0)
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["blocking"])
        self.assertIn("1 resource(s) moved to a new address (previous_address is set)", result["notes"])
        self.assertIn("1 data source(s) are read during apply", result["notes"])
        self.assertEqual(result["counts"]["no-op"], 2)

    def test_every_finding_cites_evidence_that_exists_in_the_plan(self):
        for path in sorted(FIXTURES.glob("*/plan.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            _, out, _ = run(path, "--json")
            result = json.loads(out)
            for item in result["findings"] + result["cost_changes"]["resized"]:
                try:
                    resolve(document, item["evidence"])
                except (KeyError, IndexError, TypeError):
                    self.fail("%s: evidence %s is not in the plan" % (path.parent.name, item["evidence"]))

    def test_output_is_deterministic(self):
        path = FIXTURES / "forced-replacement" / "plan.json"
        self.assertEqual(run(path), run(path))
        self.assertEqual(run(path, "--json"), run(path, "--json"))

    def test_text_output_states_the_result(self):
        _, blocked, _ = run(FIXTURES / "forced-replacement" / "plan.json")
        self.assertIn("RESULT: BLOCKING   2 critical, 1 high, 1 medium   (blocking level: high)", blocked)
        self.assertIn("CRITICAL  stateful-replace  aws_db_instance.orders", blocked)
        _, clean, _ = run(FIXTURES / "low-risk" / "plan.json")
        self.assertIn("RESULT: no blocking finding", clean)
        self.assertIn("This is not an approval.", clean)


class RuleTests(PlanFileCase):
    def test_fail_on_sets_the_blocking_level(self):
        plan = make_plan(change("aws_instance.a", ["delete"], {"ami": "x"}))
        self.assertEqual(self.review(plan)[0], 1)
        self.assertEqual(self.review(plan, "--fail-on", "critical")[0], 0)
        plain = make_plan(change("aws_route53_record.a", ["delete"], {"name": "x"}))
        self.assertEqual(self.review(plain)[0], 0)
        self.assertEqual(self.review(plain, "--fail-on", "medium")[0], 1)

    def test_stateful_type_flag_adds_a_type(self):
        plan = make_plan(change("mongodbatlas_cluster.main", ["delete"], {"name": "x"}))
        self.assertEqual(triples(self.review(plan)[1]), [("medium", "destroy", "mongodbatlas_cluster.main")])
        code, result = self.review(plan, "--stateful-type", "mongodbatlas_cluster")
        self.assertEqual(code, 1)
        self.assertEqual(triples(result), [("critical", "stateful-destroy", "mongodbatlas_cluster.main")])

    def test_resources_inside_modules_are_classified_by_type(self):
        plan = make_plan(change("module.data.aws_s3_bucket.logs[0]", ["delete"], {"bucket": "x"},
                                type="aws_s3_bucket", name="logs", index=0))
        self.assertEqual(triples(self.review(plan)[1]),
                         [("critical", "stateful-destroy", "module.data.aws_s3_bucket.logs[0]")])

    def test_forget_is_reported_and_does_not_block(self):
        plan = make_plan(change("aws_db_instance.old", ["forget"], {"identifier": "old"}))
        code, result = self.review(plan)
        self.assertEqual(code, 0)
        self.assertEqual(triples(result), [("medium", "forget", "aws_db_instance.old")])
        self.assertIn("without being destroyed", result["findings"][0]["message"])

    def test_unrecognised_action_is_reported(self):
        plan = make_plan(change("aws_instance.a", ["explode"], {}, {}))
        _, result = self.review(plan)
        self.assertEqual(triples(result), [("medium", "unrecognised-action", "aws_instance.a")])
        self.assertEqual(result["counts"]["unknown"], 1)

    def test_replace_without_replace_paths_says_so(self):
        plan = make_plan(change("aws_ebs_volume.a", ["delete", "create"], {"size": 1}, {"size": 1},
                                action_reason="replace_because_tainted"))
        finding = self.review(plan)[1]["findings"][0]
        self.assertIn("forced by: not recorded in this plan (no replace_paths)", finding["details"])
        self.assertIn("reason: replace_because_tainted (the object is tainted)", finding["details"])
        self.assertEqual(finding["evidence"], "resource_changes[0].change.actions")

    def test_forcing_attribute_marked_sensitive_or_unknown_is_not_shown(self):
        plan = make_plan(change(
            "aws_db_instance.a", ["delete", "create"],
            {"snapshot_identifier": "old-secret-snapshot", "kms_key_id": "k1"}, {},
            replace_paths=[["snapshot_identifier"], ["kms_key_id"]], after_unknown={"kms_key_id": True},
            before_sensitive={"snapshot_identifier": True}, after_sensitive={"snapshot_identifier": True}))
        code, out, _ = run(self.write(plan))
        self.assertEqual(code, 1)
        self.assertIn("forced by: snapshot_identifier ((sensitive) -> (sensitive))", out)
        self.assertIn('forced by: kms_key_id ("k1" -> (known after apply))', out)
        self.assertNotIn("old-secret-snapshot", out)

    def test_missing_safety_net_in_the_current_state_is_stated(self):
        plan = make_plan(
            change("aws_db_instance.a", ["delete"], {"skip_final_snapshot": True}),
            change("aws_s3_bucket.b", ["delete", "create"], {"force_destroy": True}, {"force_destroy": True}),
            change("aws_db_instance.c", ["delete"], {"skip_final_snapshot": False, "force_destroy": None}))
        first, second, third = [f["details"] for f in self.review(plan)[1]["findings"]]
        self.assertIn("skip_final_snapshot is true in the current state, so no final snapshot is taken", first)
        self.assertIn("force_destroy is true in the current state, so it is destroyed even if it is not empty",
                      second)
        self.assertFalse(any("current state" in line for line in third))

    def test_deposed_object_is_labelled(self):
        plan = make_plan(change("aws_ebs_volume.a", ["delete"], {"size": 1}, deposed="00000001"))
        details = self.review(plan)[1]["findings"][0]["details"]
        self.assertIn("this is a deposed object left behind by an earlier replacement", details)

    def test_data_sources_are_not_findings(self):
        plan = make_plan(change("data.aws_ami.a", ["read"], None, {}, mode="data"),
                         change("data.aws_ami.b", ["delete"], {}, None, mode="data"))
        code, result = self.review(plan)
        self.assertEqual(code, 0)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["notes"], ["1 data source(s) are read during apply"])

    def test_created_and_removed_types_are_counted(self):
        plan = make_plan(change("aws_nat_gateway.a", ["create"], None, {}),
                         change("aws_nat_gateway.b", ["create"], None, {}),
                         change("aws_eip.old", ["delete"], {}, None))
        cost = self.review(plan)[1]["cost_changes"]
        self.assertEqual(cost["new"], {"aws_nat_gateway": 2})
        self.assertEqual(cost["removed"], {"aws_eip": 1})

    def test_resize_to_an_unknown_or_sensitive_value_is_masked(self):
        plan = make_plan(change("aws_instance.a", ["update"], {"instance_type": "t3.micro", "size": 1},
                                {"size": 2}, after_unknown={"instance_type": True},
                                before_sensitive={"size": True}, after_sensitive={"size": True}))
        resized = self.review(plan)[1]["cost_changes"]["resized"]
        self.assertEqual([(r["attribute"], r["before"], r["after"]) for r in resized],
                         [("instance_type", '"t3.micro"', "(known after apply)"),
                          ("size", "(sensitive)", "(sensitive)")])
        self.assertEqual([r["evidence"] for r in resized], [
            "resource_changes[0].change.after_unknown.instance_type",
            "resource_changes[0].change.after.size"])


class NoteTests(PlanFileCase):
    def test_newer_format_version_is_noted(self):
        _, result = self.review(make_plan(format_version="2.0"))
        self.assertIn("format_version 2.0 is newer", result["notes"][0])

    def test_known_format_versions_are_not_noted(self):
        for version in ("0.2", "1.0", "1.2"):
            self.assertEqual(self.review(make_plan(format_version=version))[1]["notes"], [])

    def test_errored_plan_is_noted(self):
        _, result = self.review(make_plan(errored=True))
        self.assertIn("marked errored", result["notes"][0])

    def test_drift_and_imports_are_noted(self):
        plan = make_plan(change("aws_s3_bucket.a", ["no-op"], {}, {}, importing={"id": "a"}),
                         resource_drift=[{"address": "aws_instance.x"}, {"address": "aws_instance.y"}])
        notes = self.review(plan)[1]["notes"]
        self.assertIn("2 object(s) changed outside Terraform since the last apply (resource_drift): "
                      "aws_instance.x, aws_instance.y", notes)
        self.assertIn("1 resource(s) imported into state by this plan (change.importing is set)", notes)

    def test_plan_without_resource_changes_is_an_empty_plan(self):
        code, result = self.review({"format_version": "1.2", "planned_values": {"root_module": {}}})
        self.assertEqual(code, 0)
        self.assertEqual(result["findings"], [])
        self.assertIn("the plan has no resource_changes key: it changes no resources", result["notes"])


class InputErrorTests(PlanFileCase):
    def assert_error(self, path, expected):
        code, out, err = run(path)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("plan_review.py: error:", err)
        self.assertIn(expected, err)
        self.assertNotIn("Traceback", err)

    def test_missing_file(self):
        self.assert_error(self.dir / "nope.json", "cannot read")

    def test_invalid_json(self):
        self.assert_error(self.write("{not json"), "is not valid JSON")

    def test_plan_log_stream_gets_a_hint(self):
        log = '{"@level":"info","@message":"Plan: 1 to add"}\n{"@level":"info","@message":"done"}\n'
        self.assert_error(self.write(log), "terraform show -json <planfile>")

    def test_binary_plan_file_gets_a_hint(self):
        path = self.dir / "tfplan"
        path.write_bytes(b"PK\x03\x04\xff\xfe\x00\x80binary")
        self.assert_error(path, "convert it first")

    def test_state_json_is_rejected(self):
        state = {"format_version": "1.0", "terraform_version": "1.9.5", "values": {"root_module": {}}}
        self.assert_error(self.write(state), "neither resource_changes nor planned_values")

    def test_json_without_format_version_is_rejected(self):
        self.assert_error(self.write({"resource_changes": []}), "no format_version")
        self.assert_error(self.write([1, 2, 3]), "no format_version")

    def test_resource_changes_must_be_a_list(self):
        self.assert_error(self.write({"format_version": "1.2", "resource_changes": {}}), "is not a list")

    def test_malformed_entry_names_its_index(self):
        plan = make_plan(change("aws_instance.a", ["create"], None, {}), {"address": "aws_instance.b"})
        self.assert_error(self.write(plan), "resource_changes[1]")
        plan = make_plan({"address": "x.y", "type": "x", "change": {"actions": "delete"}})
        self.assert_error(self.write(plan), "resource_changes[0]")

    def test_missing_argument_is_a_usage_error(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            plan_review.main([])
        self.assertEqual(caught.exception.code, 2)


class CommandLineTests(unittest.TestCase):
    def test_script_runs_as_a_program_and_reads_stdin(self):
        path = FIXTURES / "forced-replacement" / "plan.json"
        direct = subprocess.run([sys.executable, "-B", str(SCRIPT), str(path), "--json"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        piped = subprocess.run([sys.executable, "-B", str(SCRIPT), "-", "--json"],
                               input=path.read_bytes(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual((direct.returncode, piped.returncode), (1, 1))
        first, second = json.loads(direct.stdout.decode()), json.loads(piped.stdout.decode())
        self.assertEqual(second["plan"]["path"], "(stdin)")
        self.assertEqual(first["findings"], second["findings"])

    def test_help_shows_examples_and_exit_codes(self):
        proc = subprocess.run([sys.executable, "-B", str(SCRIPT), "--help"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        text = proc.stdout.decode()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Examples:", text)
        self.assertIn("Exit codes:", text)


class ReadmeTests(unittest.TestCase):
    def test_console_blocks_match_what_the_scripts_print(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        blocks = re.findall(r"```console\n\$ python3 (scripts/\S+) (\S+)\n(.*?)```", readme, flags=re.S)
        self.assertEqual(len(blocks), 3)
        for script, argument, shown in blocks:
            proc = subprocess.run([sys.executable, "-B", script, argument], cwd=str(SKILL),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(proc.stdout.decode("utf-8"), shown, "%s %s" % (script, argument))


class ValidateRepoTests(unittest.TestCase):
    def test_repository_passes_its_own_validator(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import validate
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = validate.main(["validate.py", str(ROOT)])
        self.assertEqual(code, 0, buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
