# NIST CSF 2.0 Home Lab Security Self-Assessment

A hands-on GRC project: I assessed my own home lab and home network against all 106 controls of the NIST Cybersecurity Framework 2.0, scored each one against real evidence, built a risk register and remediation plan, fixed the top gaps, and re-measured.

**Result:** overall maturity went from **1.16 / 3** to **1.51 / 3** after a first remediation pass, with the largest gains in the Govern and Identify functions, where the gaps were documentation rather than missing technical controls.

Read the short write-up first: [WRITEUP.md](WRITEUP.md). The sanitized results are in [csf-maturity-report.md](csf-maturity-report.md).

## What is in this repo
- `WRITEUP.md` - the story: approach, findings, what I fixed, what I learned.
- `csf-maturity-report.md` - sanitized assessment report with the before and after maturity by function.
- `csf_assess.py` - a small, dependency-free Python tool that downloads the official NIST CSF 2.0 control set, scores a worksheet, and generates the report and a risk register.
- `collect-evidence.sh` - a read-only Linux script that gathers configuration evidence (firewall, SSH, patching, logging, backups) and maps each finding to the CSF controls it informs. It changes nothing on the system.

## What is intentionally not here
The detailed per-control worksheet, the raw evidence output, the full risk register, and the internal policy and inventory documents are kept private. They describe a live personal environment in enough detail that publishing them would be a security risk in itself. I am happy to walk through them in an interview.

## How the tool works
```
python3 csf_assess.py init      # download the CSF 2.0 control set, write a blank worksheet
# rate each control 0-3 and record evidence
python3 csf_assess.py report     # generate the scored report and risk register
```
`collect-evidence.sh` is optional and read-only; run it on the server first to ground your ratings in real configuration. NIST CSF 2.0 is US-government public domain.

## Honest framing
This is a self-assessment of a personal environment, built to practice applied GRC end to end (assess, record evidence, build a risk register, remediate, re-measure), not an enterprise engagement. The scoring scale is a common self-assessment convention, not part of the CSF standard itself.
