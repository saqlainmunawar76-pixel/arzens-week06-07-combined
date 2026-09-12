# THE ARZENS — Advanced Track — Week 06-07 Combined Assignment

Threat Intelligence Automation + Infrastructure as Code Security

**GitHub Repository:** https://github.com/saqlainmunawar76-pixel/arzens-week06-07-combined

**Submitted by:** Saqlain Munawar | **Track:** AI, Automation & Security Engineering (Advanced)

## Contents

| Task | Points | Folder / File |
|---|---|---|
| Task 1 — TI Platform Architecture Design | 5 | `Task1_TI_Architecture_Design.pdf` (+ `ti_architecture_diagram.png`) |
| Task 2 — TI Enrichment Engine | 5 | `Task2_TI_Enrichment_Engine/` |
| Task 3 — IOC Manager & Automation | 5 | `Task3_IOC_Manager/` |
| Task 4 — IaC Security Architecture | 5 | `Task4_IaC_Security_Architecture.pdf` (+ `iac_architecture_diagram.png`) |
| Task 5 — Terraform Secure Infrastructure | 5 | `Task5_Terraform/` |
| Task 6 — Ansible Hardening & Compliance | 5 | `Task6_Ansible/` |
| AI Assistance Note | — | `AI_ASSISTANCE_NOTE.md` |

Each task folder has its own `README.md` with setup instructions and a note on how that specific deliverable was tested/verified.

## Quick start per task

```bash
# Task 2
cd Task2_TI_Enrichment_Engine && pip install pyyaml requests
python ti_enricher.py --indicator 8.8.8.8

# Task 3
cd Task3_IOC_Manager && pip install pyyaml
python ioc_manager.py --add-file sample_enrichment_input.csv --health-check

# Task 5
cd Task5_Terraform && cp terraform.tfvars.example terraform.tfvars   # edit it first
terraform init && terraform plan -var-file="terraform.tfvars"

# Task 6
cd Task6_Ansible && pip install ansible
ansible-galaxy collection install -r requirements.yml
ansible-playbook site.yml --check --diff
```

## Note on live deployment (Tasks 5 & 6)

Per the assignment's own instructions ("AWS Free Tier — optional, can use local"), this submission does not deploy to a live AWS account. Instead, every deliverable was verified as thoroughly as possible without one:

- **Task 5**: every `.tf` file parses cleanly with a real HCL2 parser, and the whole configuration passes a Checkov static security scan (72 passed / 0 failed / 10 documented false-positive skips — see inline `#checkov:skip` comments); `terraform_plan.txt` shows the expected plan output for the 28 resources this configuration defines.
- **Task 6**: both playbooks pass `ansible-playbook --syntax-check`; a `--check --diff` dry run of `site.yml` against localhost executed the `common` role's tasks correctly; all three Jinja2 templates (fail2ban jail, auditd rules, compliance report) were rendered through real Ansible runs — the included `compliance_report.txt` is genuine template output. (`security.yml`'s dry run hits a missing-`sshd`-package gap specific to the authoring container — documented in `Task6_Ansible/ANSIBLE_README.md`.)

Extra hardening/automation features (multi-environment tfvars, VPC flow logs, NACL defense-in-depth, IMDSv2 enforcement, least-privilege EC2 IAM role, locked-down default VPC security group, TLS-only + access-logged S3 bucket, fail2ban custom jails, CIS-mapped auditd rules, a `validate.sh` CI gate, alerting/health-check bonus commands in the IOC manager) were added throughout to go beyond the baseline requirements, and the Terraform config was iterated against a real Checkov security scan until it reached a clean pass.