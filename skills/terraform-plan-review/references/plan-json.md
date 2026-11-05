# Reading the plan JSON

What `scripts/plan_review.py` and `scripts/access_review.py` read, and how to
read the same data by hand when a finding needs a closer look.

Field names here follow the JSON output format documented by Terraform, which
OpenTofu also uses. The format gains fields between versions. If a field is
missing from your plan or an unfamiliar one appears, check the "JSON Output
Format" page of the documentation for the version you run.

## Contents

- [Producing the JSON](#producing-the-json)
- [Top-level keys](#top-level-keys)
- [A resource_changes entry](#a-resource_changes-entry)
- [The change object](#the-change-object)
- [action_reason values](#action_reason-values)
- [Things that mislead](#things-that-mislead)

## Producing the JSON

```bash
terraform plan -out=tfplan            # writes the binary plan file
terraform show -json tfplan > plan.json
terraform apply tfplan                # applies exactly the reviewed actions
```

OpenTofu uses the same subcommands with `tofu`.

Applying the saved file is what ties the review to the apply. A plain `apply`
with no plan file makes a new plan, which can differ from the one reviewed.
Terraform refuses a saved plan when the state has changed since the plan was
made; the answer is a new plan and a new review, not a workaround.

These are not plan JSON:

| Output | What it is |
|---|---|
| `terraform plan -json` | A log of events, one JSON object per line |
| `terraform show -json` with no file argument | The current state |
| The text printed by `terraform plan` | For people; its layout is not a format to parse |

The plan file and its JSON contain variable values and resource attributes,
including ones marked sensitive, in plain text. Treat both as secrets.

## Top-level keys

| Key | Holds |
|---|---|
| `format_version` | Version of this JSON format, `1.x` at the time of writing |
| `terraform_version` | Version of the tool that made the plan |
| `variables` | Root variable values used for this plan |
| `planned_values` | The state as it should be after apply, as far as it is known |
| `resource_changes` | One entry per resource instance, with its planned action |
| `resource_drift` | Changes found outside Terraform since the last apply, in the same entry shape |
| `output_changes` | Planned changes to root outputs |
| `prior_state` | The state the plan was made against |
| `configuration` | The parsed configuration, including expressions and references |
| `errored` | `true` when planning stopped on an error; such a plan cannot be applied |

Other keys exist and more are added over time. A plan with nothing to change
can omit `resource_changes`.

## A resource_changes entry

```json
{
  "address": "module.database.aws_db_instance.orders",
  "module_address": "module.database",
  "mode": "managed",
  "type": "aws_db_instance",
  "name": "orders",
  "provider_name": "registry.terraform.io/hashicorp/aws",
  "change": {
    "actions": ["delete", "create"],
    "before": {"identifier": "orders-prod", "storage_encrypted": false},
    "after": {"identifier": "orders-prod", "storage_encrypted": true},
    "after_unknown": {"arn": true, "endpoint": true},
    "before_sensitive": {"password": true},
    "after_sensitive": {"password": true},
    "replace_paths": [["storage_encrypted"]]
  },
  "action_reason": "replace_because_cannot_update"
}
```

| Field | Meaning |
|---|---|
| `address` | Full address, including module path and any `count` or `for_each` key |
| `previous_address` | Set when the instance moved here, for example through a `moved` block |
| `mode` | `managed` for resources, `data` for data sources |
| `type`, `name`, `index` | Parts of the address; `index` is present with `count` or `for_each` |
| `deposed` | Set when the entry is about a deposed object: the old copy left by an unfinished create-before-destroy replacement |
| `action_reason` | Why this action was chosen, when Terraform records it |

The scripts skip `data` entries except to count the ones read during apply.

## The change object

`actions` is a list. These are the values and how the scripts name them:

| `actions` | Meaning | Script kind |
|---|---|---|
| `["no-op"]` | Nothing changes | no-op |
| `["create"]` | New object | create |
| `["read"]` | Data source read during apply | counted in a note |
| `["update"]` | Changed in place | update |
| `["delete", "create"]` | Destroyed, then re-created | replace |
| `["create", "delete"]` | New object created, then the old one destroyed (`create_before_destroy`) | replace |
| `["delete"]` | Destroyed | delete |
| `["forget"]` or `["create", "forget"]` | Removed from state without being destroyed, in versions that have `removed` blocks | forget |

Any other list is reported as `unrecognised-action`.

| Field | Meaning |
|---|---|
| `before` | The object in the prior state; `null` for a create |
| `after` | The planned object; `null` for a delete. Values not known until apply are left out |
| `after_unknown` | Same shape as `after`, with `true` where a value is known only after apply |
| `before_sensitive`, `after_sensitive` | Same shape, with `true` where a value is marked sensitive. The values themselves are still present in `before` and `after` |
| `replace_paths` | The attribute paths that force a replacement. Each path is a list of attribute names and list indexes. Absent when the action is not a replacement or Terraform did not record the cause |
| `importing` | Present when the plan imports the object into state, in versions that have `import` blocks |

`replace_paths` is the precise answer to "why must this be replaced". The
scripts print each path with its before and after value, unless the value is
sensitive, unknown, long or nested.

## action_reason values

| Value | Meaning |
|---|---|
| `replace_because_cannot_update` | The provider cannot make the change in place |
| `replace_because_tainted` | The object is marked tainted in state |
| `replace_by_request` | Replacement was requested with `-replace` |
| `replace_by_triggers` | A `replace_triggered_by` reference changed |
| `delete_because_no_resource_config` | The resource block is gone from the configuration |
| `delete_because_no_module` | The module call is gone from the configuration |
| `delete_because_wrong_repetition` | `count` or `for_each` was added to or removed from the block |
| `delete_because_count_index` | The instance index is outside the new `count` |
| `delete_because_each_key` | The instance key is no longer in `for_each` |
| `delete_because_no_move_target` | A `moved` block points at an address with no resource block |
| `read_because_config_unknown`, `read_because_dependency_pending` | A data source must wait until apply to be read |

The field is optional. Newer versions can add values; the scripts print any
value they do not know as it is.

## Things that mislead

- **A missing attribute in `after` is not always a removal.** Check
  `after_unknown` first. An attribute that is `true` there is absent from
  `after` because its value is not known yet.
- **Unknown is common for security-relevant values.** A policy that refers to
  the ARN of a resource created in the same plan is unknown as a whole. It
  cannot be reviewed from the plan; read the configuration.
- **Policies are strings.** IAM-style policy documents are JSON encoded inside
  a string attribute. Parse them before comparing; a text diff of the strings
  is unreliable.
- **Set-backed blocks change order.** Blocks such as security group `ingress`
  can appear in a different order in `before` and `after`. Compare them by
  content, not by position.
- **A delete and a create can be one resource.** After a rename or a move into
  a module without a `moved` block, the plan deletes the old address and
  creates the new one. `plan_review.py` adds a line to the delete when the
  same type is also created.
- **Defaults and choices look the same.** `after` does not say whether a value
  was written in the configuration or filled in by the provider. The
  `configuration` key has the expressions if that matters.
- **The summary line counts a replacement twice.** `Plan: 1 to add, 0 to
  change, 1 to destroy` can be one replaced resource.
- **Drift is not a planned change.** `resource_drift` lists what changed
  outside Terraform. The matching `resource_changes` entry shows whether the
  plan reverts it.
