#!/usr/bin/env bash
# collect-evidence.sh - read-only Debian / Proxmox evidence collector for a
# NIST CSF 2.0 self-assessment.
#
# IT CHANGES NOTHING ON THE SYSTEM. It only runs read commands and writes one
# Markdown file of findings, each tagged with the CSF controls it informs. Use
# that output to write honest ratings and evidence notes in csf-worksheet.csv.
# It deliberately does NOT rate controls for you: the judgement is yours, and an
# auto-filled rating would not be real evidence.
#
# Usage:
#   ./collect-evidence.sh            # best-effort as the current user
#   sudo ./collect-evidence.sh       # fuller output (firewall rules, auditd, LUKS, sshd -T)
#
# Output: evidence-<hostname>-<date>.md in the current directory.

set -u

OUT="evidence-$(hostname -s 2>/dev/null || echo host)-$(date +%F).md"
: > "$OUT"   # truncate/create the output file; the only write this script makes

have() { command -v "$1" >/dev/null 2>&1; }

say() { printf '%s\n' "$*" >> "$OUT"; }

section() {
  # section "Heading" "Relevant CSF controls"
  say ""
  say "## $1"
  say ""
  say "_Relevant CSF 2.0 controls: $2_"
  say ""
}

run() {
  # run "label" cmd args...   -> fenced block with the command line and its output
  local label="$1"; shift
  say "### $label"
  say ""
  say '```'
  say "\$ $*"
  if have "${1%% *}" 2>/dev/null || command -v "$1" >/dev/null 2>&1; then
    { "$@"; } >> "$OUT" 2>&1 || say "(command exited non-zero; partial or permission-limited output above)"
  else
    say "(command '$1' not installed)"
  fi
  say '```'
  say ""
}

note() { say "> $*"; say ""; }

# ----------------------------------------------------------------------------- #

say "# Evidence Collection for NIST CSF 2.0 Self-Assessment"
say ""
say "**Host:** $(hostname -f 2>/dev/null || hostname 2>/dev/null)  "
say "**Collected:** $(date '+%Y-%m-%d %H:%M:%S %Z')  "
say "**Collector:** $(id -un) (uid $(id -u))  "
if [ "$(id -u)" -ne 0 ]; then
  note "Run again with **sudo** for fuller output: firewall rules, auditd status, LUKS, and \`sshd -T\` need root."
fi
say "This file is read-only evidence. Nothing on the system was modified."

# --- ID.AM: asset inventory -------------------------------------------------- #
section "System identity and inventory" "ID.AM-01 (hardware), ID.AM-02 (software), ID.AM-03 (data flows / network)"
run "Host and OS"            hostnamectl
run "Kernel"                 uname -a
run "Uptime"                 uptime
run "Installed package count" bash -c 'dpkg-query -f "." -W 2>/dev/null | wc -c'
run "Block devices"          lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
run "Network interfaces"     ip -brief address
run "Routing table"          ip route
run "Listening services"     ss -tulpn

# --- PR.AA: identity, authentication, access control ------------------------- #
section "Identity and access control" "PR.AA-01 (identities), PR.AA-03 (authn), PR.AA-05 (least privilege)"
run "Login-capable accounts" bash -c "getent passwd | awk -F: '\$7 ~ /(bash|sh|zsh)\$/ {print \$1\"  (uid \"\$3\", shell \"\$7\")\"}'"
run "Members of sudo group"  getent group sudo
run "Members of root group"  getent group root
run "Sudoers drop-ins"       ls -l /etc/sudoers.d
run "SSH effective config (root)" bash -c "sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|x11forwarding|permitemptypasswords|maxauthtries' || echo '(needs root; falling back to file grep)'"
run "SSH config file settings" bash -c "grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|X11Forwarding|PermitEmptyPasswords|MaxAuthTries)' /etc/ssh/sshd_config 2>/dev/null || echo '(no sshd_config readable)'"
run "Password policy (login.defs)" bash -c "grep -Ei '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs 2>/dev/null"
run "Brute-force protection (fail2ban)" fail2ban-client status

# --- PR.PS / ID.RA: patching and platform security --------------------------- #
section "Patch and platform security" "PR.PS-01 (config), PR.PS-02 (software maint), ID.RA-01 (vulnerabilities)"
run "Automatic updates config" bash -c "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || echo '(file not present)'"
run "unattended-upgrades service" systemctl is-enabled unattended-upgrades
run "Pending upgrades"       bash -c "apt-get -s upgrade 2>/dev/null | grep -E '^[0-9]+ upgraded' || echo '(apt simulate unavailable)'"
run "Pending security upgrades" bash -c "apt list --upgradable 2>/dev/null | grep -i security || echo '(none listed or apt index stale; run apt update first)'"
run "Last apt history"       bash -c "tail -n 15 /var/log/apt/history.log 2>/dev/null || echo '(no apt history readable)'"

# --- PR.DS: data security ---------------------------------------------------- #
section "Data security" "PR.DS-01 (data at rest), PR.DS-02 (data in transit)"
run "Encrypted volumes (LUKS)" bash -c "lsblk -o NAME,FSTYPE,TYPE,MOUNTPOINT | grep -i crypt || blkid 2>/dev/null | grep -i crypto_LUKS || echo '(no LUKS volumes detected or needs root)'"
run "TLS certificates on disk" bash -c "find /etc/ssl /etc/letsencrypt /etc/nginx /etc/pki -name '*.crt' -o -name '*.pem' 2>/dev/null | head -n 20 || echo '(none found in common paths)'"

# --- PR.IR: network / infrastructure protection ------------------------------ #
section "Network and infrastructure protection" "PR.IR-01 (network protection), PR.IR-04 (resilience)"
run "ufw status"             bash -c "ufw status verbose 2>/dev/null || echo '(ufw not installed or needs root)'"
run "nftables ruleset"       bash -c "nft list ruleset 2>/dev/null | head -n 60 || echo '(nftables empty or needs root)'"
run "iptables rules"         bash -c "iptables -S 2>/dev/null | head -n 60 || echo '(needs root or iptables not in use)'"
run "IP forwarding"          bash -c "sysctl net.ipv4.ip_forward 2>/dev/null"

# --- DE.CM / DE.AE: monitoring and detection --------------------------------- #
section "Monitoring and detection" "DE.CM-01 (network monitoring), DE.CM-09 (computing monitoring), DE.AE-02/03 (event analysis/correlation)"
run "auditd status"          bash -c "systemctl is-active auditd 2>/dev/null; auditctl -s 2>/dev/null || echo '(auditd not active or needs root)'"
run "journald disk usage"    bash -c "journalctl --disk-usage 2>/dev/null || echo '(journald not readable)'"
run "Integrity / AV tooling" bash -c "for t in aide rkhunter clamscan chkrootkit; do printf '%s: ' \$t; command -v \$t >/dev/null 2>&1 && echo present || echo absent; done"
run "Recent auth failures"   bash -c "journalctl -u ssh -p warning --since '7 days ago' --no-pager 2>/dev/null | tail -n 15 || grep -i 'authentication failure' /var/log/auth.log 2>/dev/null | tail -n 15 || echo '(auth logs need root)'"

# --- RC.RP: backups and recovery --------------------------------------------- #
section "Backup and recovery" "RC.RP-01 (recovery plan execution), PR.DS-11 (backups)"
run "Backup tooling present" bash -c "for t in restic borg borgmatic rsync duplicity bacula; do printf '%s: ' \$t; command -v \$t >/dev/null 2>&1 && echo present || echo absent; done"
run "Scheduled timers"       bash -c "systemctl list-timers --all 2>/dev/null | head -n 20 || echo '(no timers readable)'"
run "User cron jobs"         bash -c "crontab -l 2>/dev/null || echo '(no user crontab)'"
run "System cron dirs"       bash -c "ls -1 /etc/cron.d /etc/cron.daily 2>/dev/null"

# --- Proxmox (if present) ---------------------------------------------------- #
if have pveversion || have qm || have zpool; then
  section "Proxmox / virtualization platform" "ID.AM-02 (software assets), PR.IR-04 (resilience), RC.RP-01 (recovery)"
  run "Proxmox version"      bash -c "pveversion 2>/dev/null || echo '(pveversion unavailable)'"
  run "ZFS pool status"      bash -c "zpool status 2>/dev/null || echo '(no ZFS pools or needs root)'"
  run "VM / CT list"         bash -c "qm list 2>/dev/null; pct list 2>/dev/null"
fi

# --- GV.* governance hints --------------------------------------------------- #
section "Governance signals (manual judgement)" "GV.OC (context), GV.PO (policy), GV.RR (roles)"
note "The Govern function is mostly documentation, not system state. These are things to write up by hand: who owns this environment, what it is for, what policies (if any) apply, and how decisions get made. The collector cannot find these; rate them from what you actually have."

say ""
say "---"
say "_End of evidence. Map these findings to controls in csf-worksheet.csv, then run \`python3 csf_assess.py report\`._"

echo "Wrote $OUT"
echo "Review it, then fill ratings + evidence in csf-worksheet.csv."
