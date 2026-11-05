# terraform-plan-review

**An agent skill that reviews a saved Terraform or OpenTofu plan before anyone applies it: what it destroys, what it replaces and why, where it widens access, and what changes cost.**

Left alone, a coding agent asked "is this plan safe to apply?" tends to read the console summary or the HCL diff, say the change looks reasonable, and sometimes offer to run the apply. It misses the database that is replaced because of one argument, the `moved` block nobody wrote, the wildcard added to a policy, and the policy it cannot see because its value is unknown until apply. This skill replaces that with a protocol and two scripts: the review reads the JSON of the saved plan file that will actually be applied, every destroy and replacement is listed with the attribute that forces it, no stateful resource is waved through without a data impact statement, and the agent never applies and never touches state.

Works with Claude Code, and with any agent that reads the open [Agent Skills](https://agentskills.io) format (Codex, Cursor, GitHub Copilot, Gemini CLI and others).

## What it looks like

A plan that turns on database encryption and moves a volume to another zone:

```console
$ python3 scripts/plan_review.py evals/files/forced-replacement/plan.json
plan: evals/files/forced-replacement/plan.json   format_version: 1.2   terraform_version: 1.9.5
actions: update 2, replace 3, delete 1, no-op 1
note: 1 data source(s) are read during apply

CRITICAL  stateful-replace  aws_db_instance.orders
    database or cache is replaced: the old object is destroyed, then a new one is created
    reason: replace_because_cannot_update (the provider cannot make this change in place)
    forced by: storage_encrypted (false -> true)
    data impact: the data it holds is destroyed with it unless a snapshot, backup or export is taken first
    skip_final_snapshot is true in the current state, so no final snapshot is taken
    evidence: resource_changes[0].change.replace_paths

CRITICAL  stateful-replace  aws_ebs_volume.orders_data
    disk or file system is replaced: the old object is destroyed, then a new one is created
    reason: replace_because_cannot_update (the provider cannot make this change in place)
    forced by: availability_zone ("eu-west-1a" -> "eu-west-1b")
    data impact: the data on it is destroyed with it unless a snapshot or copy is taken first
    evidence: resource_changes[1].change.replace_paths

HIGH      disruptive-replace  aws_instance.worker
    virtual machine is replaced: a new object is created, then the old one is destroyed
    reason: replace_because_cannot_update (the provider cannot make this change in place)
    forced by: ami ("ami-0a1b2c3d4e5f60718" -> "ami-08f7e6d5c4b3a2910")
    data impact: its boot disk and instance-local data go with it unless they live on separately managed disks, and it can come back with different addresses
    evidence: resource_changes[2].change.replace_paths

MEDIUM    destroy  aws_route53_record.legacy_api
    resource is destroyed
    reason: delete_because_no_resource_config (its resource block is no longer in the configuration)
    this type is not in the script's stateful list; confirm it holds no data
    evidence: resource_changes[5].change.actions

changes that can affect cost (no prices estimated; not every type listed is billed):
    removed: aws_route53_record x1
    resized: aws_autoscaling_group.web  desired_capacity: 3 -> 6
    resized: aws_autoscaling_group.web  max_size: 6 -> 12
    resized: aws_launch_template.web  instance_type: "m6i.large" -> "m6i.2xlarge"
    run a cost tool on this plan if you have one

RESULT: BLOCKING   2 critical, 1 high, 1 medium   (blocking level: high)
```

Access and protection changes in an Azure plan:

```console
$ python3 scripts/access_review.py evals/files/azure-risks/plan.json
plan: evals/files/azure-risks/plan.json   format_version: 1.2   terraform_version: 1.9.5
actions: create 3, update 3, delete 2

HIGH      open-ingress  azurerm_network_security_rule.rdp
    inbound traffic is allowed from *, protocol Tcp, ports 3389
    evidence: resource_changes[0].change.after.source_address_prefix

HIGH      broad-role  azurerm_role_assignment.ops_owner
    grants the broad built-in role Owner
    evidence: resource_changes[2].change.after.role_definition_name

HIGH      public-access  azurerm_storage_container.exports
    container_access_type changes from "private" to "blob", which turns a public-access setting on
    evidence: resource_changes[3].change.after.container_access_type

HIGH      guard-removed  azurerm_management_lock.billing
    the delete or read-only lock on its scope is removed with it
    evidence: resource_changes[5].change.actions

HIGH      public-access  azurerm_storage_account.logs
    public_network_access_enabled changes from false to true, which turns a public-access setting on
    evidence: resource_changes[6].change.after.public_network_access_enabled

RESULT: BLOCKING   0 critical, 5 high, 0 medium   (blocking level: high)
```

A routine plan with nothing blocking:

```console
$ python3 scripts/plan_review.py evals/files/low-risk/plan.json
plan: evals/files/low-risk/plan.json   format_version: 1.2   terraform_version: 1.9.5
actions: create 4, update 3, no-op 2
note: 1 resource(s) moved to a new address (previous_address is set)
note: 1 data source(s) are read during apply

changes that can affect cost (no prices estimated; not every type listed is billed):
    new:     aws_cloudwatch_metric_alarm x1, aws_iam_policy x1, aws_iam_role x1, aws_security_group_rule x1
    run a cost tool on this plan if you have one

RESULT: no blocking finding   0 critical, 0 high, 0 medium   (blocking level: high)
This is not an approval. The script checks a fixed list of resource types and rules.
```

The commands above are run from the `skills/terraform-plan-review` folder. The first two exit with code 1 and the third with code 0.

## Install

Pick one route. Installing through more than one gives you the skill twice.

**Claude Code (plugin)**

```
/plugin install terraform-plan-review --marketplace panhwerwaseem/terraform-plan-review
```

On Claude Code versions before 2.1.275, use two steps:

```
/plugin marketplace add panhwerwaseem/terraform-plan-review
/plugin install terraform-plan-review@panhwerwaseem-terraform-plan-review
```

**Any agent (skills CLI)**

```bash
npx skills add panhwerwaseem/terraform-plan-review
```

**Manual**

Copy the `skills/terraform-plan-review` folder into `.claude/skills/` (Claude Code) or `.agents/skills/` (cross-agent) in your project, or into the same folder under your home directory.

To pin a release, add the tag: `/plugin marketplace add panhwerwaseem/terraform-plan-review#v0.1.0` or `npx skills add panhwerwaseem/terraform-plan-review@v0.1.0`. Third-party plugins do not update automatically; run `claude plugin update terraform-plan-review@panhwerwaseem-terraform-plan-review` to update.

## Use

Save the plan, convert it to JSON, and ask:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json     # OpenTofu: tofu show -json tfplan > plan.json
```

> CI saved the plan for my PR and I exported it to plan.json. Is it safe to apply?

The skill loads on its own for requests like that. In Claude Code you can also call it directly with `/terraform-plan-review`.

The scripts also work without an agent, for example as a CI step after the plan job. Exit code 1 means a finding at or above `--fail-on` (default `high`).

## What is in the skill

| File | Purpose |
|---|---|
| `SKILL.md` | The protocol: seven hard rules and a seven-step workflow from the saved plan to a report |
| `scripts/plan_review.py` | Counts actions; reports every delete, replacement and forget with the forcing attribute; grades stateful resources CRITICAL and virtual machines and clusters HIGH; points at a missing `moved` block; lists cost-affecting changes |
| `scripts/access_review.py` | Compares before and after values and reports added IAM wildcards, public principals, broad built-in roles, ingress opened to the world, public-access settings turned on, deletion guards removed, and security-relevant values unknown until apply |
| `references/plan-json.md` | The plan JSON fields the scripts read, and the ways the format misleads |
| `references/risk-rubric.md` | Severity rules, the stateful resource categories across AWS, Azure and Google Cloud, what to state for each, and what the scripts do not see |
| `references/safe-replacement.md` | How to avoid an unwanted destroy: `moved`, `import` and `removed` blocks, `create_before_destroy`, migrating a stateful resource, and why state commands are left to the user |
| `evals/` | Six hand-written plans (five with planted risks, one low-risk) with five eval cases, plus trigger queries |

### What the scripts do not do

- They do not run `terraform` or `tofu`, and they do not read your configuration or state. They read one plan JSON file.
- They do not estimate prices. They list new, removed and resized resources and leave pricing to a cost tool.
- They know a fixed list of resource types for AWS, Azure and Google Cloud. Anything else that is destroyed is reported at MEDIUM; add types with `--stateful-type`.
- They do not judge partial wildcards such as `s3:Get*`, cross-account principals, egress rules, or Kubernetes RBAC. `references/risk-rubric.md` has the full list.
- Exit code 0 means no rule matched. It is not an approval.

## Requirements

- Python 3.9 or later
- A saved plan converted with `terraform show -json` or `tofu show -json`. The scripts themselves do not need Terraform or OpenTofu installed
- No packages to install and no network access

## What it reads, writes and contacts

- **Reads:** the plan JSON file you pass, or standard input.
- **Writes:** nothing. Results go to standard output and errors to standard error.
- **Runs:** nothing. The scripts start no processes.
- **Contacts:** nothing. The scripts contain no network code; CI enforces this.
- **Permissions:** the skill pre-approves no tools. Your agent asks before running commands, as usual.

Plan files and plan JSON contain variable values and resource attributes in plain text, including ones marked sensitive. Keep them out of version control. The scripts never print a value the plan marks sensitive.

See [SECURITY.md](SECURITY.md).

## Testing status

- The scripts have unit tests that run in CI on Python 3.9 and 3.12, together with a validator for the skill format and plugin manifests. One test re-runs the commands shown in this README and compares the output.
- The fixtures in `skills/terraform-plan-review/evals/files/` are written by hand in the documented plan JSON shape and trimmed to the keys the scripts read. They were not produced by running Terraform against a cloud account. If a real plan is misread, please open an issue with the relevant `resource_changes` entry, with secrets removed.
- The eval cases in `skills/terraform-plan-review/evals/` are in the [skill-creator](https://github.com/anthropics/skills/tree/main/skills/skill-creator) format. A with-skill versus without-skill score has not been published yet; results are welcome as an issue or pull request.

## Development

```bash
python3 tools/validate.py              # skill format, manifests, no-network check
python3 -m unittest discover -s tests  # script unit tests
```

## License

[MIT](LICENSE)
