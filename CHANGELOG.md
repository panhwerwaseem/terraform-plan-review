# Changelog

All notable changes to this skill are recorded here. Versions follow [Semantic Versioning](https://semver.org).

## 0.1.0 - 2026-11-06

### Added

- `SKILL.md` with the review protocol: seven hard rules and a seven-step workflow.
- `scripts/plan_review.py` for destroys, replacements with their forcing attribute, stateful resources, missing `moved` blocks, and cost-affecting changes.
- `scripts/access_review.py` for added IAM wildcards, public principals, broad roles, open ingress, public-access settings, removed deletion guards, and values unknown until apply.
- References for the plan JSON format, the risk rubric across AWS, Azure and Google Cloud, and safe handling of a forced replacement.
- Six hand-written plan fixtures (five with planted risks, one low-risk) with five eval cases, and trigger queries.
- Unit tests, a format validator, and a CI workflow.
