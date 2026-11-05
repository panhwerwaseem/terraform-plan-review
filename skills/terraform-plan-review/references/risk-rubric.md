# Risk rubric by resource category

How the scripts grade a change, and what to check and say for each category
before a plan is approved. Covers AWS (`aws_`), Azure (`azurerm_`) and Google
Cloud (`google_`).

Attribute names and defaults below are from recent versions of the three
providers. They change between provider versions. When a decision depends on
one, confirm it in the provider documentation for the version in the lock
file.

## Contents

- [Severity](#severity)
- [Stateful categories](#stateful-categories)
- [What to state for each category](#what-to-state-for-each-category)
- [Virtual machines and clusters](#virtual-machines-and-clusters)
- [Deletion guards](#deletion-guards)
- [Permission and exposure rules](#permission-and-exposure-rules)
- [What the scripts do not see](#what-the-scripts-do-not-see)

## Severity

| Severity | Used for | Blocks by default |
|---|---|---|
| CRITICAL | A stateful resource is destroyed or replaced | Yes |
| HIGH | A virtual machine or Kubernetes cluster is destroyed or replaced; a wildcard, public or broad grant is added; ingress is opened to the world; a public-access setting is turned on; a deletion guard is removed | Yes |
| MEDIUM | Any other destroy, replacement or forget; `Resource "*"` with named actions; a public principal limited by a condition; a new resource created with a public setting that may be the provider default; a security-relevant value unknown until apply | No |

`--fail-on` moves the blocking level. Severity describes what the plan does,
not whether it is wanted. A CRITICAL finding on a database that is meant to be
retired is still CRITICAL; the review records that the loss was accepted.

## Stateful categories

Destroying or replacing a resource of these types is CRITICAL. The complete
list is the `STATEFUL` table at the top of `scripts/plan_review.py`; this
table shows the main types.

| Category | AWS | Azure | Google Cloud |
|---|---|---|---|
| Database or cache | `aws_db_instance`, `aws_rds_cluster`, `aws_dynamodb_table`, `aws_redshift_cluster`, `aws_elasticache_replication_group`, `aws_opensearch_domain` | `azurerm_mssql_server`, `azurerm_mssql_database`, `azurerm_postgresql_flexible_server`, `azurerm_cosmosdb_account`, `azurerm_redis_cache` | `google_sql_database_instance`, `google_bigquery_dataset`, `google_spanner_instance`, `google_bigtable_instance`, `google_redis_instance` |
| Object storage | `aws_s3_bucket` | `azurerm_storage_account`, `azurerm_storage_container` | `google_storage_bucket` |
| Disk or file system | `aws_ebs_volume`, `aws_efs_file_system`, `aws_fsx_*_file_system` | `azurerm_managed_disk`, `azurerm_storage_share` | `google_compute_disk`, `google_filestore_instance` |
| Backup or snapshot | `aws_db_snapshot`, `aws_ebs_snapshot`, `aws_backup_vault` | `azurerm_snapshot`, `azurerm_recovery_services_vault` | `google_compute_snapshot` |
| Key or secret | `aws_kms_key`, `aws_secretsmanager_secret` | `azurerm_key_vault`, `azurerm_key_vault_key`, `azurerm_key_vault_secret` | `google_kms_key_ring`, `google_kms_crypto_key`, `google_secret_manager_secret` |
| Queue or stream | `aws_sqs_queue`, `aws_kinesis_stream`, `aws_msk_cluster` | `azurerm_eventhub_namespace`, `azurerm_servicebus_namespace` | `google_pubsub_topic`, `google_pubsub_subscription` |
| Log store | `aws_cloudwatch_log_group` | `azurerm_log_analytics_workspace` | `google_logging_project_bucket_config` |
| Container registry | `aws_ecr_repository` | `azurerm_container_registry` | `google_artifact_registry_repository` |
| DNS zone | `aws_route53_zone` | `azurerm_dns_zone`, `azurerm_private_dns_zone` | `google_dns_managed_zone` |
| Identity store | `aws_cognito_user_pool` | | |
| Resource container | | `azurerm_resource_group` | `google_project` |

A type that is not in the script's list is reported at MEDIUM with the line
"confirm it holds no data". That covers every other provider and the less
common services of these three. Use `--stateful-type` for the ones that hold
data.

A replacement is as destructive as a delete for these types. With
`create_before_destroy` the new object exists first, but it starts empty.

## What to state for each category

For every CRITICAL finding the report needs three things: what is lost, what
recovery point the plan shows, and the path that avoids the loss.

**Database or cache.** What is lost: every row, document or key in it. Look in
`change.before` for the recovery point:

- AWS RDS and Aurora: `skip_final_snapshot` and `final_snapshot_identifier`.
  The value in the current state is the one used at destroy, which is why
  `plan_review.py` prints a line when it is `true`. `delete_automated_backups`
  on `aws_db_instance` decides whether automated backups go too.
- Google Cloud SQL: backups belong to the instance. Check Google's
  documentation for whether they survive its deletion in your configuration.
- Azure SQL: a deleted database can usually be restored only while its server
  still exists, so a plan that deletes the server as well removes that route.

If the plan shows no recovery point, say "none found", not "probably backed up".

**Object storage.** What is lost: every object, and with it every version.
The S3 and Cloud Storage APIs refuse to delete a bucket that still has
objects, so the apply fails part way unless `force_destroy` is `true`, in
which case the provider empties the bucket first. Deleting an Azure storage
account removes its containers, file shares, queues and tables with it.

**Disk or file system.** What is lost: the data on the volume. Snapshots are
separate resources and survive, if any exist; the plan does not list snapshots
that Terraform does not manage.

**Backup or snapshot.** What is lost: the ability to restore to that point.
Ask what restores from it and whether a retention rule requires it.

**Key or secret.** What is lost: the ability to decrypt everything encrypted
under the key. This is the widest blast radius in the list, because the data
sits in other resources that the plan shows as unchanged.

- AWS KMS keys are scheduled for deletion after a waiting period set by
  `deletion_window_in_days`; the deletion can be cancelled during that window.
  Secrets Manager has `recovery_window_in_days`; `0` deletes at once.
- Azure Key Vault uses soft delete. The `azurerm` provider's `features` block
  has `key_vault` settings that decide whether a destroy also purges the
  soft-deleted object. Read them before relying on recovery.
- Google Cloud KMS key rings and keys cannot be deleted. Destroying a
  `google_kms_crypto_key` removes it from state and destroys its key versions,
  which makes the data unreadable all the same.

**Queue or stream.** What is lost: messages not yet consumed, and the
endpoint that producers and consumers are configured with.

**Log store.** What is lost: the retained logs, which may be audit evidence.

**Container registry.** What is lost: the images. Running workloads keep
running until they need to pull again.

**DNS zone.** What is lost: the zone and the records in it. Records made
outside Terraform either block the delete or are removed with the zone,
depending on the provider and its `force_destroy` setting. A re-created zone
can be assigned different name servers, so the delegation at the registrar or
parent zone breaks until it is updated.

**Identity store.** What is lost: the users, their credentials and their
identifiers. Applications that stored those identifiers no longer match.

**Resource container.** Deleting an Azure resource group or a Google Cloud
project deletes what is inside it, including resources this plan never
mentions. The `azurerm` provider has a `resource_group` feature setting that
can refuse to delete a group that still contains resources; do not assume it
is on.

## Virtual machines and clusters

Destroying or replacing these is HIGH.

| Category | Types | What to check |
|---|---|---|
| Virtual machine | `aws_instance`, `azurerm_linux_virtual_machine`, `azurerm_windows_virtual_machine`, `azurerm_virtual_machine`, `google_compute_instance` | Whether anything on the boot disk or instance-local disks matters; whether the private or public address is referenced elsewhere; whether the service has other instances while this one is replaced |
| Kubernetes cluster | `aws_eks_cluster`, `azurerm_kubernetes_cluster`, `google_container_cluster` | Where the workloads go; what happens to persistent volumes; what else points at the cluster endpoint |

## Deletion guards

`access_review.py` reports `guard-removed` when an in-place update turns one
of these off, whatever the resource type.

| Attribute | Guard removed when it becomes | Seen on, for example |
|---|---|---|
| `deletion_protection` | `false`, or `"INACTIVE"` | `aws_db_instance`, `aws_rds_cluster`, `google_sql_database_instance`, `google_container_cluster`, `aws_cognito_user_pool` |
| `deletion_protection_enabled` | `false` | `aws_dynamodb_table` |
| `enable_deletion_protection` | `false` | `aws_lb` |
| `disable_api_termination` | `false` | `aws_instance` |
| `skip_final_snapshot` | `true` | `aws_db_instance`, `aws_rds_cluster` |
| `force_destroy` | `true` | `aws_s3_bucket`, `google_storage_bucket` |

It also reports the deletion of an `aws_s3_bucket_public_access_block` or an
`azurerm_management_lock`, because each protects another resource.

A plan that only turns a guard off is usually the first half of a destroy.
Ask what the next plan will be, and review the pair as one change.

The `prevent_destroy` lifecycle setting does not appear in the plan JSON as a
finding. Terraform fails the plan instead of producing one that destroys such
a resource. It gives no protection once the whole resource block is deleted.

## Permission and exposure rules

All of these compare `before` with `after` and report only what the change
adds. An existing wildcard that the plan leaves alone is not reported.

| Rule | Severity | Reported when | Ask |
|---|---|---|---|
| `iam-wildcard` | HIGH | An `Allow` statement gains `Action` `*` or `service:*`, or uses `NotAction`; an Azure custom role gains the action `*` | Which actions does the workload call? Name them |
| `iam-wildcard` | MEDIUM | An `Allow` statement with named actions gains `Resource` `*` or uses `NotResource` | Can the resource be an ARN? Some list and describe actions accept only `*` |
| `public-principal` | HIGH | An `Allow` statement gains `Principal` `*` with no `Condition`; a Google IAM member becomes `allUsers` or `allAuthenticatedUsers` | Is public access the purpose of this resource? |
| `public-principal` | MEDIUM | `Principal` `*` with a `Condition` | Does the condition limit callers, for example by organisation, source ARN or VPC endpoint? |
| `broad-role` | HIGH | Azure `Owner`, `Contributor` or `User Access Administrator` is assigned; Google `roles/owner` or `roles/editor` is granted or gains members; AWS `AdministratorAccess` is attached | Which narrower role covers the task? At what scope? |
| `open-ingress` | HIGH | An inbound rule gains `0.0.0.0/0` or `::/0` (Azure: also `*` or `Internet`) | Which ports? Is the target meant to face the internet? |
| `public-access` | HIGH | A public-access setting is turned on in an update, or a new resource is created with one whose default is private | What becomes reachable, and by whom? |
| `public-access` | MEDIUM | A new resource is created with a public setting that can be the provider default | Was it chosen or inherited? Set it explicitly |
| `unknown-until-apply` | MEDIUM | A policy document, network source or member is known only after apply | Read the configuration that produces the value |

`allAuthenticatedUsers` means any signed-in Google account, not only accounts
in your organisation.

The public-access settings checked are `publicly_accessible` (RDS, Redshift),
the four `aws_s3_bucket_public_access_block` arguments, the `public-read` and
`public-read-write` bucket ACLs, `allow_nested_items_to_be_public` and
`container_access_type` on Azure storage, `public_network_access_enabled` on
any `azurerm_` resource, and `public_access_prevention` on
`google_storage_bucket`. A setting being on does not always mean the resource
is reachable: firewalls, policies and authentication can still stand in the
way. Report the setting and let the user judge.

## What the scripts do not see

State these limits in the report when they are relevant.

- Partial wildcards such as `s3:Get*`, and single actions that allow privilege
  escalation, such as `iam:PassRole`.
- Cross-account principals. Only `*` is reported.
- Google `policy_data` documents on `google_*_iam_policy` resources, and
  Google IAM conditions.
- Azure custom role actions other than `*`.
- Egress rules, network ACLs, route changes, and rules that reference another
  security group rather than a CIDR range.
- Unknown `source_ranges` on `google_compute_firewall`.
- Kubernetes RBAC and any provider outside AWS, Azure and Google Cloud.
- Downtime caused by in-place updates, for example an instance class change
  that restarts a database.
- Prices.
