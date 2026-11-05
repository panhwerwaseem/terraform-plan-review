---
name: terraform-plan-review
description: Reviews a saved Terraform or OpenTofu plan before it is applied, using scripts that read the plan JSON and report what is destroyed or replaced and why, which stateful resources lose data, where IAM, network or public access is widened, where deletion protection is removed, and which changes affect cost. Use when the user asks to review, check or approve a terraform plan or tofu plan, asks whether a plan is safe to apply, asks what will be destroyed or why a resource must be replaced, shares plan JSON or a tfplan file, or mentions forces replacement, destroy, blast radius, IAM wildcard, 0.0.0.0/0 or deletion protection in an infrastructure change.
license: MIT
compatibility: Requires Python 3.9 or later to run the bundled scripts, and plan JSON made with terraform show -json or tofu show -json. No network access and no extra packages needed.
metadata:
  author: panhwerwaseem
  version: "0.1.0"
---

# Terraform plan review

A plan review is done when the plan file that will actually be applied has been
read by both scripts, every finding has been reported with its evidence from
the plan JSON, every destroy or replacement of a stateful resource has a stated
data impact and a safer path, and nothing has been applied or changed. The
decision to apply belongs to the user.

Paths in this file are relative to this skill's directory.

## Hard rules

1. **Review the saved plan, not a fresh one.** Review only JSON made from the
   plan file that will be passed to `apply`. A new `plan` run is a different
   plan, and the HCL diff or the console text is not a plan. If no saved plan
   exists, ask for one made with `-out`. If the plan is regenerated, the review
   is void and the scripts run again.
2. **Never apply.** Do not run `apply` or `destroy` with `terraform` or `tofu`,
   in any mode, including `-auto-approve` and `-refresh-only`. Hand the user
   the report and stop.
3. **Never touch state.** Do not run `state mv`, `state rm`, `state push`,
   `import`, `taint`, `untaint` or `force-unlock`, and do not edit a state
   file. Propose configuration changes (`moved`, `import` and `removed` blocks,
   lifecycle settings) and let the user plan again.
4. **No stateful destroy without a data impact statement.** For every CRITICAL
   finding, state what data is lost, what backup the plan shows or that none
   was found, and the path that avoids the loss. Do not call such a plan safe,
   fine or ready until the user has accepted that specific loss in words.
5. **Evidence or silence.** Every claim about the plan cites the resource
   address and the JSON path the script printed. Do not infer what the plan
   does from resource names, from the HCL, or from memory of provider
   behaviour. If a script exits 2, there is no review yet.
6. **Exit code 0 is not approval.** The scripts check fixed lists of resource
   types and rules. Always report what was not reviewed: values unknown until
   apply, types outside the lists, and providers other than AWS, Azure and
   Google Cloud.
7. **No prices and no secrets.** Do not estimate cost in currency. Plan JSON
   holds sensitive values in plain text, so do not paste attribute values from
   it into chat, a pull request or a commit, and do not leave it in the
   repository.

## Workflow

### 1. Get the JSON of the plan that will be applied

```bash
terraform show -json tfplan > plan.json     # OpenTofu: tofu show -json tfplan > plan.json
```

Run it in the initialised working directory that produced `tfplan`. It reads
the plan file and changes nothing. Write `plan.json` outside the repository or
to a path git ignores. If the user already has the JSON, ask which plan file or
CI run it came from and whether that same file is what gets applied.

`terraform plan -json` output (one JSON object per line) and `terraform show
-json` without a plan file (state) are not plan JSON; the scripts reject both.
`references/plan-json.md` describes the format.

If there is no saved plan, ask the user to make one with
`terraform plan -out=tfplan`. Run it yourself only if they ask: it needs cloud
credentials, takes the state lock and refreshes against live infrastructure.

### 2. Run both scripts

```bash
python3 scripts/plan_review.py plan.json      # destroys, replacements, moves, cost-affecting changes
python3 scripts/access_review.py plan.json    # IAM, network, public access, deletion guards, unknown values
```

Work from the script output. Do not open `plan.json` in full: it is large and
it contains secrets. When a finding needs a closer look, read only the
`resource_changes` entry at the index the evidence line names.

Exit code 0 means no finding at HIGH or above, 1 means at least one, 2 means
the input could not be read. Add `--json` for machine-readable output,
`--fail-on critical|high|medium` to move the blocking level, and
`--stateful-type TYPE` (repeatable, `plan_review.py` only) for stateful types
from providers the script does not know.

### 3. Work through every destroy and replacement

For each `stateful-`, `disruptive-`, `destroy`, `replace` and `forget` finding:

1. Read `forced by` and `reason`. They say why the resource is destroyed.
2. Decide whether the change request asked for it. A destroy the request does
   not explain is a blocker until it is explained. The usual causes are below.
3. For CRITICAL findings, write the data impact statement from rule 4.
   `references/risk-rubric.md` says what to check for each category.
4. Choose the safer path from `references/safe-replacement.md`.

| What the output shows | Usual cause | First thing to try |
|---|---|---|
| `this plan also creates <same type>` on a delete | Resource renamed or moved into a module | `moved` block |
| `delete_because_count_index`, `delete_because_each_key`, `delete_because_wrong_repetition` | `count` or `for_each` changed | `moved` block to the new key, or fix the collection |
| `forced by: <attribute>` | That argument cannot change in place | Check the argument change is wanted; then migrate, not replace |
| `forced by: not recorded` with reason `replace_because_tainted` | Earlier failed apply or a taint | Ask the user why it is tainted |
| A create for something that already exists | Object made outside Terraform | `import` block |

### 4. Work through every access and protection finding

For each finding from `access_review.py`, say who gains what, on which
resource, and whether the change request asked for it. Offer the narrower form:
named actions and resource ARNs, a specific principal, a specific source
range, the guard left on.

`unknown-until-apply` findings are values the plan cannot show. Open the
configuration that produces the value and report what it will resolve to if
that can be read from the source; otherwise list it as not reviewed.

### 5. List what affects cost

Copy the `changes that can affect cost` section: new and removed resource
types and resized attributes. Give no prices. If the user has a cost tool that
reads plan files, such as Infracost, tell them to run it on this plan.

### 6. If the configuration changes, review the new plan

A fix is proven only by a new saved plan. After the user changes the
configuration and plans again, repeat steps 1 and 2 on the new file and check
that the finding is gone from the script output. For a `moved` block, the
delete and create disappear and the output says `moved to a new address`.

### 7. Report

Give the user this, filled in from the script output:

```
Plan reviewed:   <plan.json>, made from <plan file or CI run>, terraform <version>
Actions:         <create N, update N, replace N, delete N, ...>
Verdict:         BLOCKED | NEEDS YOUR DECISION | NO BLOCKING FINDING (not an approval)
Destroyed or replaced:
  <address>: <rule>, forced by <attribute or reason>
      data impact: <what is lost; backup shown in the plan, or none found>
      safer path:  <moved block, migration, lifecycle setting, or none>
Access and protection:
  <address>: <rule>, <what is granted or opened, and to whom>, evidence <JSON path>
Not reviewed:    <unknown-until-apply values, types outside the lists, anything unread>
Cost-affecting:  <new, removed and resized resources; no prices>
Not done:        nothing applied, no state changed; <questions the user must answer>
```

## Edge cases

- **No changes.** If both scripts print `actions: none` or only `no-op`, say
  so. Still report notes such as drift.
- **Partial plans.** A plan made with `-target` covers only part of the
  configuration. Ask whether it was used; the review covers only what the
  plan contains.
- **Destroy plans.** For `plan -destroy`, every managed resource is a delete.
  The CRITICAL list is the review; rule 4 applies to each entry.
- **Other providers.** Types outside AWS, Azure and Google Cloud are reported
  at MEDIUM when destroyed. Pass `--stateful-type` for each one that holds
  data (for example a Kubernetes persistent volume claim or a managed
  database from another vendor).
- **Drift note.** `changed outside Terraform` means the plan may revert a
  manual change. Name the objects and ask whether the manual change should be
  kept.
- **Errored or newer-format plans.** The scripts print a note. An errored plan
  cannot be applied; a newer `format_version` needs the results checked by
  hand.
- **Large plans.** Use `--json` and group findings by rule. Do not drop
  findings to shorten the report; summarise MEDIUM ones by count if needed.
