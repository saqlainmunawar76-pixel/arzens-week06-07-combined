# Ansible Hardening & Compliance — THE ARZENS Week 07 (Task 6)

Idempotent Ansible playbooks that harden Linux servers (SSH, firewall,
fail2ban, auditd) and validate the result against a CIS-aligned compliance
checklist, producing a per-host report.

## Structure

```
task6_ansible/
├── ansible.cfg
├── hosts.ini                    # inventory (webservers, dbservers -> all_servers)
├── requirements.yml               # collection dependency: community.general
├── site.yml                        # main playbook: common -> security -> compliance
├── security.yml                     # security role only, for fast re-hardening
├── compliance_report.txt              # sample output (see "How this was tested" below)
├── reports/                             # per-host reports land here after a real run
└── roles/
    ├── common/tasks/main.yml              # apt updates, unattended-upgrades, timezone, rsyslog, chrony
    ├── security/
    │   ├── tasks/main.yml                    # SSH hardening, ufw, fail2ban, auditd
    │   ├── handlers/main.yml                  # restart sshd / fail2ban / auditd
    │   └── templates/
    │       ├── jail.local.j2                     # fail2ban config (sshd + web-tier jail)
    │       └── audit.rules.j2                      # CIS-mapped auditd rules
    └── compliance/
        ├── tasks/main.yml                            # runs checks, builds facts, renders + fetches report
        └── templates/compliance_report.txt.j2          # report template
```

## Setup

```bash
pip install ansible
ansible-galaxy collection install -r requirements.yml
```

## Usage

```bash
# Full hardening + compliance run
ansible-playbook site.yml

# Dry run first (always do this before a real run)
ansible-playbook site.yml --check --diff

# Security hardening only (fast drift-remediation pass)
ansible-playbook security.yml

# Target a single group
ansible-playbook site.yml --limit webservers
```

After a run, per-host reports are fetched to `reports/compliance_report_<host>.txt`
on the control node.

## Idempotency

Every task uses a real-state-checking module (`apt`, `lineinfile`,
`template`, `service`/`ufw`/`fail2ban`) rather than raw shell commands, so
re-running `site.yml` a second time converges to the same state and reports
`changed=0` for anything already applied — safe to run on a cron schedule
for continuous compliance enforcement.

## CIS mapping

The `compliance` role's checks are tagged with their CIS Distribution
Independent Linux Benchmark control IDs (e.g. `5.2.10` for root SSH login,
`4.1.x` for the auditd rule set) so the generated report doubles as an audit
artifact, not just a pass/fail list.

## How this was tested

This environment has no target Linux server or live AWS account attached, so
full end-to-end execution against real infrastructure wasn't possible here.
What *was* verified directly:

1. **`ansible-playbook site.yml --syntax-check`** and **`security.yml --syntax-check`** — both pass.
2. **`ansible-playbook site.yml --check --diff`** against `localhost` — the
   `common` role's apt/template/timezone tasks executed correctly in check
   mode (see the diff output for `20auto-upgrades` and the timezone change).
   The `service` module error on `rsyslog` in that run is a known check-mode
   limitation (Ansible can't validate a systemd unit for a package that
   check-mode only *pretended* to install) — not a defect in the task itself.
3. **`ansible-playbook security.yml --check --diff`** against `localhost` —
   fails immediately on the SSH-hardening tasks because this authoring
   container has no `openssh-server` installed (`/etc/ssh/sshd_config`
   doesn't exist here), and package installs are only simulated in check
   mode. This is an authoring-environment gap, not a role defect: any real
   target (the Task 5 EC2 AMI, any standard Ubuntu/Amazon Linux server)
   ships `sshd` pre-installed, so `lineinfile` against `sshd_config` will
   succeed there.
4. **Every Jinja2 template** (`jail.local.j2`, `audit.rules.j2`,
   `compliance_report.txt.j2`) was rendered through a real
   `ansible-playbook` run with representative variables — `compliance_report.txt`
   in this repo is genuine template output, not hand-written.

For a real submission run: provision the Task 5 EC2 instance, add its IP to
`hosts.ini`, point `ansible_ssh_private_key_file` at your key pair, and run
`ansible-playbook site.yml`.
