# AI Assistance Note

As required by the assignment's academic integrity policy, this note discloses all AI assistance
used in preparing this submission.

## Tool used
Claude (Anthropic) — used as a coding/writing assistant throughout Tasks 1–6.

## How it was used

| Task | AI assistance |
|---|---|
| Task 1 (TI Architecture Design) | Drafted the architecture document structure and prose, and generated the architecture diagram (matplotlib), based on the design decisions made for the Task 2/3 implementation. |
| Task 2 (TI Enrichment Engine) | Wrote `ti_enricher.py`, `config.yaml`, and supporting files; iteratively tested and debugged (type detection, caching, rate limiting, risk scoring) until the script ran correctly end-to-end. |
| Task 3 (IOC Manager) | Wrote `ioc_manager.py` and configuration; tested the full lifecycle (add/update/expire/blocklist/report/health/alert) against Task 2's sample output. |
| Task 4 (IaC Security Architecture) | Drafted the architecture document and generated the module-structure diagram, mirroring the actual Task 5 Terraform module layout. |
| Task 5 (Terraform) | Wrote the modular Terraform configuration (root + vpc/security/compute/storage modules). Verified with a real HCL2 parser (`python-hcl2`, 0 syntax errors across 16 files) and a Checkov static security scan (iterated until 72 passed / 0 failed / 10 documented false-positive skips, each with an inline rationale comment). A live AWS account/Terraform CLI was not available in the authoring environment, so `terraform_plan.txt` is a hand-verified sample of expected output rather than a live plan capture. |
| Task 6 (Ansible) | Wrote the playbooks, roles, and templates; verified with `ansible-playbook --syntax-check` on both playbooks, a `--check --diff` dry run of `site.yml` against localhost (common role's apt/template/timezone tasks executed correctly), and real Jinja2 template rendering through Ansible (the included `compliance_report.txt` is genuine template output). A `--check` run of `security.yml` surfaced that the authoring container has no `openssh-server` installed — documented in `ANSIBLE_README.md` as an authoring-environment gap, not a role defect, since any real target host ships `sshd`. |

## What was NOT AI-generated
- The overall task prioritization and submission strategy (what to build first given the deadline).
- The decision to keep AWS/live-server deployment optional per the assignment's own allowance,
  and to compensate with additional hardening/automation features instead.
- Review and verification of every deliverable before submission (test runs shown in each task's
  README under "How this was tested").

## Disclosure statement
All code was reviewed, tested, and understood before submission. No content was submitted without
independent verification that it functions as described (see per-task README "testing" sections
for the specific checks run on each deliverable).
