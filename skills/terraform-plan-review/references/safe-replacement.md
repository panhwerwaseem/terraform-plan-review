# Handling a forced replacement or an unwanted destroy

What to propose when `scripts/plan_review.py` reports a destroy or a
replacement that the change request did not ask for, or one that would lose
data.

Every fix here is a configuration change that the user reviews in a new plan.
The agent does not run state commands and does not apply. Version numbers are
the releases that introduced each feature in Terraform; OpenTofu has the same
features unless noted, sometimes with different details. Check the
documentation for the version in use.

## Contents

- [Find the cause first](#find-the-cause-first)
- [Address changed: moved block](#address-changed-moved-block)
- [Object exists but is not in state: import block](#object-exists-but-is-not-in-state-import-block)
- [Stop managing without destroying: removed block](#stop-managing-without-destroying-removed-block)
- [Real replacement of a stateless resource: create_before_destroy](#real-replacement-of-a-stateless-resource-create_before_destroy)
- [Real replacement of a stateful resource: migrate](#real-replacement-of-a-stateful-resource-migrate)
- [Lifecycle settings that block or hide changes](#lifecycle-settings-that-block-or-hide-changes)
- [State commands](#state-commands)
- [Proving the fix](#proving-the-fix)

## Find the cause first

| The plan shows | Cause | Go to |
|---|---|---|
| A delete at one address and a create of the same type at another | Renamed, or moved into or out of a module | moved block |
| A delete with reason `delete_because_count_index`, `delete_because_each_key` or `delete_because_wrong_repetition` | `count` or `for_each` changed, or the collection behind it changed | moved block, or fix the collection |
| A create for something that already exists in the cloud account | Made by hand or by another tool | import block |
| A replacement with `forced by: <attribute>` | The provider cannot change that argument in place | Decide whether the argument change is wanted, then the stateless or stateful section |
| A replacement with reason `replace_because_tainted` | An earlier apply failed part way, or someone tainted it | Ask the user; removing a taint is a state command |
| A delete of something that should keep running unmanaged | The block was removed on purpose | removed block |

Do not skip the first question in the fourth row. Many forced replacements
come from an argument change nobody intended: a provider upgrade that changed
a default, a variable that resolved differently, or drift that the plan is
reverting. Reverting the argument is then the whole fix.

## Address changed: moved block

Terraform 1.1 and later. Tells Terraform that an existing object now lives at
a new address, so nothing is destroyed.

```hcl
moved {
  from = aws_db_instance.orders
  to   = module.database.aws_db_instance.orders
}
```

From `count` to `for_each`:

```hcl
moved {
  from = aws_subnet.private[0]
  to   = aws_subnet.private["eu-west-1a"]
}
```

A whole module call can be moved the same way, with `from = module.old` and
`to = module.new`.

- One block per instance address that changed, unless a whole module moved.
- A `moved` block changes the address only. It is not a general way to change
  a resource's type.
- Keep the blocks in the configuration at least until every workspace that
  uses it has applied them.

In the next plan the delete and the create are gone, the entry carries
`previous_address`, and `plan_review.py` prints a note that resources moved to
a new address.

## Object exists but is not in state: import block

Terraform 1.5 and later.

```hcl
import {
  to = aws_s3_bucket.uploads
  id = "acme-orders-uploads"
}
```

The format of `id` differs for each resource type. It is in the "Import"
section of that resource's provider documentation.

In the next plan the entry has `change.importing`. Its action should be
`no-op` or a small `update`. A replacement or a large update means the
configuration does not describe the real object yet; fix the configuration
before anyone applies. `terraform plan -generate-config-out=PATH` can write a
first draft of the configuration for imported resources; review what it
writes.

## Stop managing without destroying: removed block

Terraform 1.7 and later. Removes the resource from state and leaves the real
object alone.

```hcl
removed {
  from = aws_db_instance.legacy

  lifecycle {
    destroy = false
  }
}
```

In the next plan the action is `forget` instead of `delete`, which the script
reports at MEDIUM. The object keeps running and keeps costing money, and
nothing manages it. Say who owns it from now on.

OpenTofu also has a `removed` block. Its arguments have not matched
Terraform's in every version, so check its documentation before writing one.

## Real replacement of a stateless resource: create_before_destroy

```hcl
resource "aws_instance" "worker" {
  # ...
  lifecycle {
    create_before_destroy = true
  }
}
```

The new object is created and only then is the old one destroyed. The plan
shows `["create", "delete"]`.

- Both objects exist at once, so anything that must be unique collides. Use a
  generated name or a name prefix instead of a fixed name.
- Terraform applies the same ordering to the resources this one depends on.
- It does not copy data. On a stateful resource the new object is empty and
  the old one is still destroyed.

## Real replacement of a stateful resource: migrate

When the argument change is wanted and the provider can only replace, do not
let the plan do it in one step. Split it:

1. Add the replacement as a new resource at a new address, next to the old
   one. That plan only creates.
2. Move the data: restore from a snapshot, replicate, dump and load, or copy.
3. Point consumers at the new resource and verify.
4. Remove the old resource in a separate, later plan. That plan has one
   CRITICAL finding, accepted on purpose, with a recovery point taken first.

Two common cases:

- **Turning on encryption for an existing RDS instance.** Storage encryption
  cannot be changed in place. The route is a snapshot, an encrypted copy of
  that snapshot, and a new instance restored from the copy.
- **Moving an EBS volume to another availability zone.** A volume cannot
  change zone. The route is a snapshot and a new volume created from it in the
  target zone.

Before the destroy step, make the recovery point explicit in the state that
will be used for the destroy. For RDS that means `skip_final_snapshot = false`
and a `final_snapshot_identifier`, applied before the plan that destroys.

## Lifecycle settings that block or hide changes

```hcl
lifecycle {
  prevent_destroy = true
  ignore_changes  = [ami]
}
```

- `prevent_destroy` makes any plan that would destroy the resource fail. It
  stops working when the resource block itself is deleted, because the setting
  goes with it. It complements the cloud provider's own deletion protection
  and does not replace it.
- `ignore_changes` stops Terraform from proposing changes to the listed
  arguments. Use it when something else legitimately manages the value. It
  also hides intended changes to that argument from then on, so name the
  narrowest argument and say so in the report.

## State commands

These change state directly, outside any plan. The agent does not run them.
If the user chooses one, they run it, after saving a copy of the state with
`terraform state pull > backup.tfstate`.

| Command | Does | Block that replaces it |
|---|---|---|
| `terraform state mv SOURCE DESTINATION` | Changes an address in state | `moved` |
| `terraform import ADDRESS ID` | Adds an existing object to state | `import` |
| `terraform state rm ADDRESS` | Drops an object from state without destroying it | `removed` |
| `terraform untaint ADDRESS` | Clears a taint so the object is not replaced | none |

Prefer the blocks. They are reviewed in a plan, they are recorded in version
control, and they apply the same way in every environment.

## Proving the fix

A fix is proven by a new saved plan, not by reading the configuration.

1. The user changes the configuration and runs `terraform plan -out=tfplan`.
2. Convert it and run both scripts again.
3. The finding must be gone from the output, and no new destroy or
   replacement may have appeared in its place.

A plan that still shows the delete after a `moved` block was added usually
means the `from` address does not match the address in state exactly,
including the module path and the index or key.
