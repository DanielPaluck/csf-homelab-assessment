# NIST CSF 2.0 Security Self-Assessment (Home Lab)

**Assessor:** Daniel Paluck
**Baseline:** 2026-10-31  **Re-assessed:** 2026-11-03
**Framework:** NIST Cybersecurity Framework 2.0 (control text is US-government public domain)
**Scope:** A personal home lab and home network, assessed by the owner as sole administrator: a Linux virtualization host running containerized services on a segmented, firewalled network, with redundant local storage and offsite backups.

> This is a sanitized public version. The detailed per-control worksheet, evidence, and risk register are kept private because they describe a live personal environment; they are available to walk through on request.

## Summary
I assessed the environment against all 106 controls of NIST CSF 2.0, scored each on a 0-3 implementation scale, and produced a risk register and remediation plan. Baseline maturity was **1.16 / 3** across 92 in-scope controls. After a first remediation pass, a re-assessment came out at **1.51 / 3**. Fourteen controls were judged not applicable to a single-person environment and excluded from scoring.

## Method
Each CSF 2.0 subcategory was rated 0 (not implemented) to 3 (fully implemented) against observed evidence, with a target of 3; a control counts as a gap when it is below target. Evidence was gathered partly through a read-only Linux collection script included in this repository. The 0-3 scale is a common self-assessment convention, not part of the CSF standard.

## Overall maturity by function

| Function | Baseline | After first remediation pass |
|----------|----------|------------------------------|
| Govern | 1.05 | 1.71 |
| Identify | 0.89 | 1.58 |
| Protect | 1.50 | 1.59 |
| Detect | 1.09 | 1.09 |
| Respond | 1.15 | 1.31 |
| Recover | 1.33 | 1.50 |
| **Overall** | **1.16 / 3** | **1.51 / 3** |

## What the baseline showed
The strongest areas were Protect and Recover: network segmentation, encryption in transit, patching, access control, capacity headroom, and working backups. The weakest were Identify and Govern, and almost entirely as documentation gaps rather than missing technical controls. The environment did many of the right things in practice but had no written policy, no asset or data inventory, and no recorded risk register.

## Remediation performed (first pass)
- Wrote a home-lab security policy covering access, patching, backups, logging, acceptable use, and risk management.
- Built hardware, software and service, and data inventories.
- Created an incident-response and recovery runbook.
- Started a vulnerability, threat, and change log.
- Performed and logged a backup restore test to confirm recoverability.

Re-assessing after this pass moved overall maturity from 1.16 to 1.51, with the largest gains in Govern and Identify, where the missing piece had been documentation.

## Remaining priorities
- Detection and monitoring: centralized log collection and host or endpoint monitoring.
- Formal configuration baselines and hardening standards.
- Continued maturation of the response process (evidence handling, categorization).

## Note
This is a self-assessment of a personal environment, done to practice applied GRC work end to end: assess against a framework, record evidence, build a risk register, remediate, and re-measure.
