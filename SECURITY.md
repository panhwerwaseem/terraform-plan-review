# Security

An agent skill is instructions and code that your coding agent will follow and run. Review a skill before installing it, the same way you would review any dependency.

## What this skill does on your machine

| | |
|---|---|
| Reads | The plan JSON file you pass to a script, or standard input |
| Writes | Nothing. Results go to standard output and errors to standard error |
| Executes | Nothing. The scripts start no processes and never run `terraform` or `tofu` |
| Network | None. The bundled scripts import no network modules. `tools/validate.py` checks this in CI |
| Dependencies | Python standard library only. `access_review.py` imports `plan_review.py` from its own directory |
| Pre-approved tools | None. `SKILL.md` has no `allowed-tools` entry, so your agent's normal permission prompts apply |
| Hooks, MCP servers, background processes | None |

The skill instructs the agent never to run `apply`, `destroy`, `import` or any state command, and to propose configuration changes for you to plan again. It may ask to run `terraform show -json <planfile>` to convert a saved plan to JSON. That command goes through your agent's normal permission flow.

## Plan files contain secrets

A plan file and the JSON made from it hold variable values and resource attributes in plain text, including values marked sensitive.

- Keep `tfplan` and `plan.json` out of version control and delete them when the review is done.
- The scripts never print a value that the plan marks sensitive, and they withhold long and nested values. They do print resource addresses, short values of the attributes that force a replacement or change size, IAM action names, role names, members, CIDR ranges, ports and the values of the settings they check, when the plan does not mark those sensitive.
- If your agent opens `plan.json` itself instead of running the scripts, its whole content, secrets included, goes to the model like any other file the agent reads. `SKILL.md` tells the agent to work from the script output.

## Limits of the review

The scripts match a fixed list of resource types and rules for AWS, Azure and Google Cloud. Exit code 0 means no rule matched; it does not mean the plan is safe. Do not use this skill as the only control in front of a production apply.

## Reporting a vulnerability

Please report security problems privately through the repository's **Security** tab ("Report a vulnerability"). If that option is not available, open an issue that says a private channel is needed, without including exploit details.

## Verifying what you install

- Install from a tagged release and read the diff between tags before updating.
- The whole skill is the `skills/terraform-plan-review/` folder: one Markdown protocol, two Python scripts, three reference files, and eval fixtures.
