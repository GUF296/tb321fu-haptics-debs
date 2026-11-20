#!/bin/bash -p
clean_environment=1
[ "${HAPTICS_APT_CLEAN_ENV:-}" = 1 ] &&
  [ "${PATH:-}" = /usr/sbin:/usr/bin:/sbin:/bin ] &&
  [ "${LANG:-}" = C ] && [ "${LC_ALL:-}" = C ] &&
  [ "${TZ:-}" = UTC ] && [ "${HOME:-}" = /root ] &&
  [ "${TMPDIR:-}" = /tmp ] || clean_environment=0
while IFS= read -r -d '' entry; do
  name=${entry%%=*}
  case "$name" in
    PATH|LANG|LC_ALL|TZ|HOME|TMPDIR|HAPTICS_APT_CLEAN_ENV|PWD|SHLVL|_) ;;
    *) clean_environment=0 ;;
  esac
done < <(/usr/bin/env -0)
if [ "$clean_environment" != 1 ]; then
  script_path=$(/usr/bin/realpath -e -- "$0") || exit 1
  exec /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/root TMPDIR=/tmp \
    HAPTICS_APT_CLEAN_ENV=1 \
    /bin/bash -p "$script_path" "$@"
fi
case $- in
  *p*) ;;
  *) echo 'dependency installation requires privileged Bash mode' >&2; exit 1 ;;
esac
set -euo pipefail
umask 077

work_dir=
apt_phase_pid=
apt_phase_start_time=
apt_phase_starting=0
apt_phase_signal_name=
apt_phase_signal_status=
apt_phase_cgroup=
apt_phase_cgroup_parent=
apt_phase_cgroup_leaf=
apt_phase_cgroup_parent_fd=
apt_phase_cgroup_fd=
apt_phase_cgroup_identity=
apt_phase_cgroup_had_members=0
apt_phase_cgroup_sequence=0
apt_phase_cgroup_unsettled=0
apt_phase_completion_sequence=0
apt_phase_completion_read_fd=
apt_phase_completion_write_fd=
installer_signal_status=
apt_transaction_active=0
apt_transaction_cancel_forward=0
apt_cleanup_active=0
apt_phase_now_cs=0
# The inner runner can spend 3s converging, 1s waiting, 3s in emergency
# convergence and up to 1s publishing terminal diagnostics. The outer
# insurance must not kill that valid protocol before it can report its result.
readonly APT_PHASE_TAIL_GRACE_CS=1000
readonly APT_PHASE_KILL_GRACE_CS=200

read_apt_phase_clock() {
  local uptime idle whole fraction

  # Linux uptime is CLOCK_BOOTTIME: monotonic, including host suspend. These
  # producer jobs run on a disposable Ubuntu host; wall-clock changes never
  # extend either a phase ceiling or a cleanup deadline.
  IFS=' ' read -r uptime idle < /proc/uptime || return 1
  [[ "$uptime" =~ ^[0-9]{1,12}\.[0-9]{2}$ ]] || return 1
  whole=${uptime%.*}
  fraction=${uptime#*.}
  apt_phase_now_cs=$((10#$whole * 100 + 10#$fraction))
}

close_apt_phase_completion_channel() {
  local failed=0

  if [ -n "$apt_phase_completion_write_fd" ]; then
    exec {apt_phase_completion_write_fd}>&- || failed=1
    apt_phase_completion_write_fd=
  fi
  if [ -n "$apt_phase_completion_read_fd" ]; then
    exec {apt_phase_completion_read_fd}<&- || failed=1
    apt_phase_completion_read_fd=
  fi
  [ "$failed" -eq 0 ]
}

create_apt_phase_completion_channel() {
  local fifo_path hold_fd read_fd write_fd failed=0

  close_apt_phase_completion_channel || return 1
  apt_phase_completion_sequence=$((apt_phase_completion_sequence + 1))
  fifo_path="$work_dir/.apt-phase-completion-$BASHPID-$apt_phase_completion_sequence"
  /usr/bin/mkfifo -m 0600 -- "$fifo_path" || return 1
  if ! exec {hold_fd}<> "$fifo_path"; then
    /usr/bin/rm -f -- "$fifo_path"
    return 1
  fi
  if ! exec {read_fd}< "$fifo_path"; then
    failed=1
  elif ! exec {write_fd}> "$fifo_path"; then
    failed=1
  fi
  /usr/bin/rm -f -- "$fifo_path" || failed=1
  exec {hold_fd}>&- || failed=1
  if [ "$failed" -ne 0 ]; then
    [ -z "${write_fd:-}" ] || exec {write_fd}>&-
    [ -z "${read_fd:-}" ] || exec {read_fd}<&-
    return 1
  fi
  apt_phase_completion_read_fd=$read_fd
  apt_phase_completion_write_fd=$write_fd
}

authenticate_apt_phase_completion() {
  local expected_status=$1 record= read_status=0 authenticated=1

  if [ -n "$apt_phase_completion_write_fd" ]; then
    exec {apt_phase_completion_write_fd}>&- || true
    apt_phase_completion_write_fd=
  fi
  if [ -n "$apt_phase_completion_read_fd" ]; then
    # A valid exit status plus newline is at most four bytes.  Read through
    # EOF rather than treating an unterminated second line as clean EOF.
    # A NUL delimiter or the five-character cap succeeds and is rejected.
    IFS= read -r -d '' -n 5 record <&"$apt_phase_completion_read_fd" || read_status=$?
    if [ "$read_status" -eq 1 ] && [ "$record" = "$expected_status"$'\n' ]; then
      authenticated=0
    fi
  fi
  close_apt_phase_completion_channel || authenticated=1
  return "$authenticated"
}

read_process_start_time() {
  local pid=$1 stat_line stat_tail
  local -a stat_fields

  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  IFS= read -r stat_line < "/proc/$pid/stat" || return 1
  stat_tail=${stat_line##*) }
  [ "$stat_tail" != "$stat_line" ] || return 1
  read -r -a stat_fields <<< "$stat_tail"
  [ "${#stat_fields[@]}" -ge 20 ] || return 1
  [[ "${stat_fields[19]}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${stat_fields[19]}"
}

read_process_state() {
  local pid=$1 expected_start=$2 stat_line stat_tail
  local -a stat_fields

  [[ "$pid" =~ ^[1-9][0-9]*$ ]] && [[ "$expected_start" =~ ^[0-9]+$ ]] || return 2
  if ! IFS= read -r stat_line < "/proc/$pid/stat"; then
    [ ! -e "/proc/$pid" ] && return 1
    return 2
  fi
  stat_tail=${stat_line##*) }
  [ "$stat_tail" != "$stat_line" ] || return 2
  read -r -a stat_fields <<< "$stat_tail"
  [ "${#stat_fields[@]}" -ge 20 ] || return 2
  case "${stat_fields[0]}" in
    R|S|D|Z|T|t|X|x|K|W|P|I) ;;
    *) return 2 ;;
  esac
  [ "${stat_fields[19]}" = "$expected_start" ] || return 1
  printf '%s\n' "${stat_fields[0]}"
}

read_started_process_state() {
  local pid=$1 stat_line stat_tail
  local -a stat_fields

  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 2
  if ! IFS= read -r stat_line < "/proc/$pid/stat"; then
    [ ! -e "/proc/$pid" ] && return 1
    return 2
  fi
  stat_tail=${stat_line##*) }
  [ "$stat_tail" != "$stat_line" ] || return 2
  read -r -a stat_fields <<< "$stat_tail"
  [ "${#stat_fields[@]}" -ge 20 ] || return 2
  case "${stat_fields[0]}" in
    R|S|D|Z|T|t|X|x|K|W|P|I) ;;
    *) return 2 ;;
  esac
  printf '%s\n' "${stat_fields[0]}"
}

reap_owned_apt_phase() {
  local pid=$1 expected_start=$2 grace_cs=${3:-$APT_PHASE_TAIL_GRACE_CS}
  local state observation_status deadline_cs

  read_apt_phase_clock || return 2
  deadline_cs=$((apt_phase_now_cs + grace_cs))

  while :; do
    if state=$(read_process_state "$pid" "$expected_start"); then
      case "$state" in
        Z|X|x)
          wait "$pid" 2>/dev/null || true
          return 0
          ;;
      esac
    else
      observation_status=$?
      if [ "$observation_status" -eq 1 ]; then
        wait "$pid" 2>/dev/null || true
        return 0
      fi
      return 2
    fi
    read_apt_phase_clock || return 2
    [ "$apt_phase_now_cs" -lt "$deadline_cs" ] || return 1
    /usr/bin/sleep 0.01
  done
}

reap_started_apt_phase() {
  local pid=$1 grace_cs=${2:-$APT_PHASE_KILL_GRACE_CS}
  local state observation_status deadline_cs

  read_apt_phase_clock || return 2
  deadline_cs=$((apt_phase_now_cs + grace_cs))

  while :; do
    if state=$(read_started_process_state "$pid"); then
      case "$state" in
        Z|X|x)
          wait "$pid" 2>/dev/null || true
          return 0
          ;;
      esac
    else
      observation_status=$?
      if [ "$observation_status" -eq 1 ]; then
        wait "$pid" 2>/dev/null || true
        return 0
      fi
      return 2
    fi
    read_apt_phase_clock || return 2
    [ "$apt_phase_now_cs" -lt "$deadline_cs" ] || return 1
    /usr/bin/sleep 0.01
  done
}

signal_owned_apt_phase() {
  local signal_name=$1

  [ -n "$apt_phase_pid" ] && [ -n "$apt_phase_start_time" ] || return 1
  /usr/bin/python3 -I -B -c '
import os, signal, sys
pid, expected, name = sys.argv[1:]
if not pid.isascii() or not pid.isdigit() or int(pid) <= 1:
    raise SystemExit(1)
if not expected.isascii() or not expected.isdigit() or name not in ("TERM", "KILL"):
    raise SystemExit(1)
descriptor = -1
try:
    descriptor = os.pidfd_open(int(pid))
    with open("/proc/" + pid + "/stat", encoding="ascii") as stream:
        parts = stream.read().rsplit(") ", 1)
    fields = parts[1].split() if len(parts) == 2 else []
    if len(fields) < 20 or fields[19] != expected:
        raise SystemExit(1)
    signal.pidfd_send_signal(descriptor, getattr(signal, "SIG" + name))
except (OSError, ValueError, UnicodeError):
    raise SystemExit(1)
finally:
    if descriptor >= 0:
        os.close(descriptor)
' "$apt_phase_pid" "$apt_phase_start_time" "$signal_name"
}

read_unified_cgroup_path() {
  local hierarchy controllers relative extra found=

  while IFS=: read -r hierarchy controllers relative extra; do
    [ "$hierarchy" = 0 ] && [ -z "$controllers" ] &&
      [ -z "$extra" ] && [[ "$relative" = /* ]] && [ -z "$found" ] || return 1
    found=$relative
  done < /proc/self/cgroup
  [ -n "$found" ] || return 1
  printf '%s\n' "$found"
}

apt_phase_cgroup_object_identity_matches() {
  local current_identity

  [ -n "$apt_phase_cgroup_fd" ] && [ -n "$apt_phase_cgroup_identity" ] || return 1
  current_identity=$(/usr/bin/stat -Lc '%d:%i' -- \
    "/proc/self/fd/$apt_phase_cgroup_fd") || return 1
  [ "$current_identity" = "$apt_phase_cgroup_identity" ]
}

apt_phase_cgroup_path_identity_matches() {
  local current_identity

  apt_phase_cgroup_object_identity_matches || return 1
  [ -n "$apt_phase_cgroup_parent_fd" ] && [ -n "$apt_phase_cgroup_leaf" ] || return 1
  current_identity=$(/usr/bin/stat -Lc '%d:%i' -- \
    "/proc/self/fd/$apt_phase_cgroup_parent_fd/$apt_phase_cgroup_leaf") || return 1
  [ "$current_identity" = "$apt_phase_cgroup_identity" ]
}

apt_phase_cgroup_populated() {
  local key value extra populated= count=0

  apt_phase_cgroup_object_identity_matches || return 1
  while read -r key value extra; do
    if [ "$key" = populated ]; then
      [ -z "$extra" ] && [[ "$value" =~ ^[01]$ ]] || return 1
      populated=$value
      count=$((count + 1))
    fi
  done < "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.events"
  [ "$count" -eq 1 ] || return 1
  printf '%s\n' "$populated"
}

clear_apt_phase_cgroup_ownership() {
  local failed=0

  if [ -n "$apt_phase_cgroup_fd" ]; then
    exec {apt_phase_cgroup_fd}<&- || failed=1
    apt_phase_cgroup_fd=
  fi
  if [ -n "$apt_phase_cgroup_parent_fd" ]; then
    exec {apt_phase_cgroup_parent_fd}<&- || failed=1
    apt_phase_cgroup_parent_fd=
  fi
  apt_phase_cgroup=
  apt_phase_cgroup_parent=
  apt_phase_cgroup_leaf=
  apt_phase_cgroup_identity=
  [ "$failed" -eq 0 ]
}

apt_phase_cgroup_object_removed() {
  local descriptor_target

  [ -n "$apt_phase_cgroup_fd" ] && [ -n "$apt_phase_cgroup" ] || return 1
  descriptor_target=$(/usr/bin/readlink -- "/proc/self/fd/$apt_phase_cgroup_fd") || return 1
  [ "$descriptor_target" = "$apt_phase_cgroup (deleted)" ]
}

remove_apt_phase_cgroup_leaf() {
  local leaf_path

  if apt_phase_cgroup_object_removed; then
    clear_apt_phase_cgroup_ownership
    return
  fi
  apt_phase_cgroup_path_identity_matches || return 1
  leaf_path="/proc/self/fd/$apt_phase_cgroup_parent_fd/$apt_phase_cgroup_leaf"
  if /usr/bin/rmdir -- "$leaf_path"; then
    clear_apt_phase_cgroup_ownership
    return
  fi
  if apt_phase_cgroup_object_removed; then
    clear_apt_phase_cgroup_ownership
    return
  fi
  return 1
}

rollback_apt_phase_cgroup_creation() {
  local metadata device inode owner group extra first_member child_path

  [ -n "$apt_phase_cgroup" ] || return 0
  [ -n "$apt_phase_cgroup_parent_fd" ] && [ -n "$apt_phase_cgroup_leaf" ] || return 1
  child_path="/proc/self/fd/$apt_phase_cgroup_parent_fd/$apt_phase_cgroup_leaf"
  if [ ! -e "$child_path" ] && [ ! -L "$child_path" ]; then
    clear_apt_phase_cgroup_ownership
    return 0
  fi
  [ -n "$apt_phase_cgroup_parent" ] &&
    [ "${apt_phase_cgroup%/*}" = "$apt_phase_cgroup_parent" ] &&
    [ -d "$child_path" ] && [ ! -L "$child_path" ] || return 1
  if [ -z "$apt_phase_cgroup_fd" ]; then
    exec {apt_phase_cgroup_fd}< "$child_path" || return 1
  fi
  [ "$(/usr/bin/realpath -e -- "/proc/self/fd/$apt_phase_cgroup_fd")" = \
    "$apt_phase_cgroup" ] || return 1
  [ "$(/usr/bin/stat -fc '%t' -- "/proc/self/fd/$apt_phase_cgroup_fd")" = \
    63677270 ] || return 1
  metadata=$(/usr/bin/stat -Lc '%d:%i:%u:%g' -- \
    "/proc/self/fd/$apt_phase_cgroup_fd") || return 1
  IFS=: read -r device inode owner group extra <<< "$metadata"
  [ -z "$extra" ] && [[ "$device" =~ ^[0-9]+$ ]] &&
    [[ "$inode" =~ ^[0-9]+$ ]] && [ "$owner" = 0 ] && [ "$group" = 0 ] || return 1
  if [ -n "$apt_phase_cgroup_identity" ]; then
    [ "$device:$inode" = "$apt_phase_cgroup_identity" ] || return 1
  else
    apt_phase_cgroup_identity="$device:$inode"
  fi
  apt_phase_cgroup_path_identity_matches || return 1
  [ -f "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.procs" ] &&
    [ ! -L "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.procs" ] || return 1
  first_member=$(/usr/bin/head -c 1 -- \
    "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.procs") || return 1
  [ -z "$first_member" ] || return 1
  remove_apt_phase_cgroup_leaf
}

create_apt_phase_cgroup() {
  local relative parent parent_real installer_pid start_time candidate identity control
  local cgroup_type
  local parent_fd_path child_path

  [ -z "$apt_phase_cgroup" ] && [ -z "$apt_phase_cgroup_identity" ] &&
    [ -z "$apt_phase_cgroup_parent_fd" ] && [ -z "$apt_phase_cgroup_fd" ] || return 1
  apt_phase_cgroup_had_members=0
  if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    return 0
  fi
  relative=$(read_unified_cgroup_path) || return 1
  if [ "$relative" = / ]; then
    parent=/sys/fs/cgroup
  else
    parent="/sys/fs/cgroup$relative"
  fi
  [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
  parent_real=$(/usr/bin/realpath -e -- "$parent") || return 1
  [ "$parent_real" = "$parent" ] || return 1
  [ "$(/usr/bin/stat -fc '%t' -- "$parent")" = 63677270 ] || return 1
  exec {apt_phase_cgroup_parent_fd}< "$parent" || return 1
  parent_fd_path="/proc/self/fd/$apt_phase_cgroup_parent_fd"
  if [ "$(/usr/bin/realpath -e -- "$parent_fd_path")" != "$parent" ]; then
    clear_apt_phase_cgroup_ownership || true
    return 1
  fi
  installer_pid=$BASHPID
  if ! start_time=$(read_process_start_time "$installer_pid"); then
    clear_apt_phase_cgroup_ownership || true
    return 1
  fi
  apt_phase_cgroup_sequence=$((apt_phase_cgroup_sequence + 1))
  apt_phase_cgroup_leaf="tb321fu-haptics-apt-$installer_pid-$start_time-$apt_phase_cgroup_sequence"
  candidate="$parent/$apt_phase_cgroup_leaf"
  child_path="$parent_fd_path/$apt_phase_cgroup_leaf"
  if [ -e "$child_path" ] || [ -L "$child_path" ]; then
    clear_apt_phase_cgroup_ownership || true
    return 1
  fi
  apt_phase_cgroup_parent=$parent
  apt_phase_cgroup=$candidate
  if ! /usr/bin/mkdir -- "$child_path"; then
    rollback_apt_phase_cgroup_creation || true
    return 1
  fi
  if ! exec {apt_phase_cgroup_fd}< "$child_path"; then
    rollback_apt_phase_cgroup_creation || true
    return 1
  fi
  if ! identity=$(/usr/bin/stat -Lc '%d:%i' -- \
    "/proc/self/fd/$apt_phase_cgroup_fd"); then
    rollback_apt_phase_cgroup_creation || true
    return 1
  fi
  apt_phase_cgroup_identity=$identity
  for control in cgroup.procs cgroup.kill cgroup.events cgroup.type; do
    [ -f "/proc/self/fd/$apt_phase_cgroup_fd/$control" ] &&
      [ ! -L "/proc/self/fd/$apt_phase_cgroup_fd/$control" ] || {
      rollback_apt_phase_cgroup_creation || true
      return 1
    }
  done
  cgroup_type=$(< "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.type")
  if [ "$cgroup_type" != domain ] || [ "$(apt_phase_cgroup_populated)" != 0 ]; then
    rollback_apt_phase_cgroup_creation || true
    return 1
  fi
}

settle_apt_phase_cgroup() {
  local populated= deadline_cs

  apt_phase_cgroup_had_members=0
  if [ -z "$apt_phase_cgroup" ]; then
    if [ -n "$apt_phase_cgroup_fd" ] || [ -n "$apt_phase_cgroup_parent_fd" ]; then
      clear_apt_phase_cgroup_ownership
      return
    fi
    return 0
  fi
  if [ -z "$apt_phase_cgroup_identity" ]; then
    rollback_apt_phase_cgroup_creation
    return
  fi
  if ! read_apt_phase_clock; then
    if apt_phase_cgroup_object_identity_matches; then
      printf '1\n' > "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.kill" || true
    fi
    return 1
  fi
  deadline_cs=$((apt_phase_now_cs + 300))
  while :; do
    apt_phase_cgroup_object_identity_matches || return 1
    populated=$(apt_phase_cgroup_populated) || return 1
    [ "$populated" = 0 ] || apt_phase_cgroup_had_members=1
    printf '1\n' > "/proc/self/fd/$apt_phase_cgroup_fd/cgroup.kill" || return 1
    populated=$(apt_phase_cgroup_populated) || return 1
    if [ "$populated" = 0 ]; then
      if remove_apt_phase_cgroup_leaf; then
        return 0
      fi
      apt_phase_cgroup_object_identity_matches || return 1
    fi
    read_apt_phase_clock || return 1
    [ "$apt_phase_now_cs" -lt "$deadline_cs" ] || return 1
    /usr/bin/sleep 0.01
  done
}

converge_owned_apt_phase() {
  local state observation_status

  [ -n "$apt_phase_pid" ] && [ -n "$apt_phase_start_time" ] || return 0
  if state=$(read_process_state "$apt_phase_pid" "$apt_phase_start_time"); then
    case "$state" in
      Z|X|x)
        wait "$apt_phase_pid" 2>/dev/null || true
        return 0
        ;;
    esac
  else
    observation_status=$?
    if [ "$observation_status" -eq 1 ]; then
      wait "$apt_phase_pid" 2>/dev/null || true
      return 0
    fi
    return 2
  fi
  signal_owned_apt_phase TERM 2>/dev/null || true
  reap_owned_apt_phase "$apt_phase_pid" "$apt_phase_start_time" && return 0
  signal_owned_apt_phase KILL 2>/dev/null || true
  reap_owned_apt_phase "$apt_phase_pid" "$apt_phase_start_time" \
    "$APT_PHASE_KILL_GRACE_CS"
}

cleanup() {
  local entry_status=$? apt_cleanup_active=1 cgroup_settled=1 process_settled=1 cleanup_failed=0

  close_apt_phase_completion_channel || cleanup_failed=1
  if [ -n "$apt_phase_pid" ]; then
    converge_owned_apt_phase || process_settled=0
  fi
  if ! settle_apt_phase_cgroup; then
    cgroup_settled=0
    cleanup_failed=1
    echo 'APT phase cgroup cleanup did not converge' >&2
  fi
  if [ -n "$apt_phase_pid" ]; then
    if [ "$process_settled" != 1 ] && [ "$cgroup_settled" = 1 ]; then
      if converge_owned_apt_phase; then
        process_settled=1
      fi
    fi
    if [ "$process_settled" = 1 ]; then
      wait "$apt_phase_pid" 2>/dev/null || true
      apt_phase_pid=
      apt_phase_start_time=
    else
      cleanup_failed=1
      echo 'APT phase process cleanup did not converge' >&2
    fi
  fi
  if [ "$cgroup_settled" = 1 ] && [ "$process_settled" = 1 ] &&
    [ -n "$work_dir" ] && [ -d "$work_dir" ]; then
    if ! /usr/bin/rm -rf -- "$work_dir"; then
      cleanup_failed=1
      echo 'APT phase work directory cleanup failed' >&2
    fi
  fi
  if [ -n "$installer_signal_status" ]; then
    entry_status=$installer_signal_status
  elif [ "$cleanup_failed" = 1 ] && [ "$entry_status" -eq 0 ]; then
    entry_status=125
  fi
  trap - EXIT
  # Expansion of this final command is the terminal status commit. Include
  # cancellation delivered during the last cleanup/status-selection commands.
  exit "${installer_signal_status:-$entry_status}"
}
trap cleanup EXIT

handle_installer_signal() {
  local signal_name=$1 signal_status=$2

  if [ -z "$installer_signal_status" ]; then
    installer_signal_status=$signal_status
  fi
  if [ "$apt_cleanup_active" = 1 ]; then
    return 0
  fi
  if [ "$apt_transaction_active" = 1 ] &&
    [ "$apt_transaction_cancel_forward" != 1 ]; then
    return 0
  fi
  if [ "$apt_phase_starting" = 1 ] || [ -n "$apt_phase_pid" ]; then
    if [ -z "$apt_phase_signal_status" ]; then
      apt_phase_signal_name=$signal_name
      apt_phase_signal_status=$signal_status
    fi
    return 0
  fi
  if [ "$apt_transaction_active" = 1 ]; then
    return 0
  fi
  exit "$signal_status"
}
trap 'handle_installer_signal HUP 129' HUP
trap 'handle_installer_signal INT 130' INT
trap 'handle_installer_signal TERM 143' TERM

early_script_path=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
early_script_dir=${early_script_path%/*}
APT_PHASE_RUNNER="$early_script_dir/run-haptics-apt-phase.py"
[ -f "$APT_PHASE_RUNNER" ] && [ ! -L "$APT_PHASE_RUNNER" ] || {
  echo 'APT phase runner is not a regular non-symlink file' >&2
  exit 1
}

run_apt_phase() {
  local phase=$1 timeout_seconds=$2 stdout_path=$3
  shift 3
  local runner_pid runner_start_time status cgroup_status=0 process_settled=0
  local runner_completion_authenticated=0
  local timeout_cs phase_ceiling_cs state observation_status
  local -a cgroup_arguments=()

  [ "$#" -gt 0 ] || {
    echo 'APT phase command is empty' >&2
    return 125
  }
  apt_phase_signal_name=
  apt_phase_signal_status=
  apt_phase_cgroup_unsettled=0
  apt_phase_starting=1
  if ! timeout_cs=$(/usr/bin/python3 -I -B -c '
import math, sys
try:
    value = float(sys.argv[1])
    if not math.isfinite(value) or not 0 < value <= 3600:
        raise ValueError()
    print(math.ceil(value * 100))
except (ValueError, OverflowError):
    raise SystemExit(1)
' "$timeout_seconds"); then
    apt_phase_starting=0
    return "${apt_phase_signal_status:-125}"
  fi
  if [ "$apt_transaction_active" = 1 ] &&
    [ "$apt_transaction_cancel_forward" = 1 ] &&
    [ -n "$installer_signal_status" ]; then
    apt_phase_starting=0
    return "$installer_signal_status"
  fi
  if ! create_apt_phase_cgroup; then
    if [ -n "$apt_phase_cgroup" ]; then
      if ! settle_apt_phase_cgroup; then
        apt_phase_cgroup_unsettled=1
      fi
    fi
    apt_phase_starting=0
    if [ -n "$apt_phase_signal_status" ]; then
      status=$apt_phase_signal_status
      apt_phase_signal_name=
      apt_phase_signal_status=
      return "$status"
    fi
    return 125
  fi
  if [ -n "$apt_phase_signal_status" ]; then
    if ! settle_apt_phase_cgroup; then
      apt_phase_cgroup_unsettled=1
    fi
    apt_phase_starting=0
    status=$apt_phase_signal_status
    apt_phase_signal_name=
    apt_phase_signal_status=
    return "$status"
  fi
  if ! create_apt_phase_completion_channel; then
    if ! settle_apt_phase_cgroup; then
      apt_phase_cgroup_unsettled=1
    fi
    apt_phase_starting=0
    return "${apt_phase_signal_status:-125}"
  fi
  if [ -n "$apt_phase_cgroup" ]; then
    cgroup_arguments=(
      --cgroup "$apt_phase_cgroup"
      --cgroup-identity "$apt_phase_cgroup_identity"
    )
  fi
  /usr/bin/python3 -I -B "$APT_PHASE_RUNNER" \
    --phase "$phase" \
    --timeout-seconds "$timeout_seconds" \
    --private-root "$work_dir" \
    --stdout "$stdout_path" \
    --status-fd "$apt_phase_completion_write_fd" \
    "${cgroup_arguments[@]}" \
    -- "$@" &
  runner_pid=$!
  exec {apt_phase_completion_write_fd}>&-
  apt_phase_completion_write_fd=
  if ! runner_start_time=$(read_process_start_time "$runner_pid"); then
    kill -s TERM %+ 2>/dev/null || true
    if ! reap_started_apt_phase "$runner_pid" "$APT_PHASE_TAIL_GRACE_CS"; then
      kill -s KILL %+ 2>/dev/null || true
    fi
    if ! settle_apt_phase_cgroup; then
      cgroup_status=125
      apt_phase_cgroup_unsettled=1
    fi
    if ! reap_started_apt_phase "$runner_pid"; then
      cgroup_status=125
      apt_phase_cgroup_unsettled=1
    fi
    apt_phase_starting=0
    if [ -n "$apt_phase_signal_status" ]; then
      status=$apt_phase_signal_status
    elif [ "$cgroup_status" -ne 0 ]; then
      status=$cgroup_status
    else
      status=125
    fi
    apt_phase_signal_name=
    apt_phase_signal_status=
    close_apt_phase_completion_channel || true
    return "$status"
  fi
  apt_phase_pid=$runner_pid
  apt_phase_start_time=$runner_start_time
  apt_phase_starting=0
  if read_apt_phase_clock; then
    phase_ceiling_cs=$((apt_phase_now_cs + timeout_cs + APT_PHASE_TAIL_GRACE_CS))
  else
    phase_ceiling_cs=0
  fi
  while :; do
    if [ -n "$apt_phase_signal_name" ]; then
      if converge_owned_apt_phase; then
        process_settled=1
      fi
      status=$apt_phase_signal_status
      break
    fi
    if state=$(read_process_state "$runner_pid" "$runner_start_time"); then
      observation_status=0
    else
      observation_status=$?
    fi
    if [ "$observation_status" -eq 1 ] ||
      { [ "$observation_status" -eq 0 ] && [[ "$state" = Z || "$state" = X || "$state" = x ]]; }; then
      if wait "$runner_pid"; then
        status=0
      else
        status=$?
      fi
      process_settled=1
      break
    fi
    if [ "$observation_status" -ne 0 ] || [ "$phase_ceiling_cs" -eq 0 ] ||
      ! read_apt_phase_clock; then
      status=125
      echo 'APT phase supervisor could not authenticate live process state or time' >&2
      if converge_owned_apt_phase; then
        process_settled=1
      fi
      break
    fi
    if [ "$apt_phase_now_cs" -ge "$phase_ceiling_cs" ]; then
      status=124
      echo 'APT phase outer deadline exceeded after runner cleanup allowance' >&2
      signal_owned_apt_phase KILL 2>/dev/null || true
      if reap_owned_apt_phase "$runner_pid" "$runner_start_time" \
        "$APT_PHASE_KILL_GRACE_CS"; then
        process_settled=1
      fi
      break
    fi
    /usr/bin/sleep 0.01
  done
  if [ "$process_settled" = 1 ]; then
    apt_phase_pid=
    apt_phase_start_time=
  fi
  if ! settle_apt_phase_cgroup; then
    cgroup_status=125
    apt_phase_cgroup_unsettled=1
  fi
  if [ "$process_settled" != 1 ] && [ "$cgroup_status" -eq 0 ]; then
    if reap_owned_apt_phase "$runner_pid" "$runner_start_time" \
      "$APT_PHASE_KILL_GRACE_CS"; then
      process_settled=1
      apt_phase_pid=
      apt_phase_start_time=
    else
      cgroup_status=125
      apt_phase_cgroup_unsettled=1
    fi
  fi
  if [ "$process_settled" != 1 ]; then
    apt_phase_cgroup_unsettled=1
  fi
  if [ "$process_settled" = 1 ] &&
    authenticate_apt_phase_completion "$status"; then
    runner_completion_authenticated=1
  else
    close_apt_phase_completion_channel || true
  fi
  if [ -n "$apt_phase_signal_status" ]; then
    status=$apt_phase_signal_status
    apt_phase_signal_name=
    apt_phase_signal_status=
  elif [ "$cgroup_status" -eq 0 ] && [ "$apt_phase_cgroup_had_members" = 1 ] &&
    [ "$status" -eq 0 ]; then
    status=125
  elif [ "$status" -ne 124 ] && [ "$runner_completion_authenticated" != 1 ]; then
    status=125
  elif [ "$cgroup_status" -ne 0 ] && [ "$status" -eq 0 ]; then
    status=$cgroup_status
  fi
  return "$status"
}

verify_apt_partial_directory_empty() {
  local partial=$1 residue private_root

  [ -d "$partial" ] && [ ! -L "$partial" ] || {
    echo 'apt partial path is not a real directory' >&2
    return 1
  }
  partial=$(/usr/bin/realpath -e -- "$partial") || return 1
  private_root=$(/usr/bin/realpath -e -- "$work_dir") || return 1
  case "$partial" in
    "$private_root"/*/partial) ;;
    *) echo 'apt partial directory escaped the private work directory' >&2; return 1 ;;
  esac
  residue=$(/usr/bin/find "$partial" -mindepth 1 -maxdepth 1 -print -quit)
  [ -z "$residue" ] || {
    echo 'apt reported success with a nonempty partial directory' >&2
    return 1
  }
}

prepare_reviewed_dpkg_config() {
  local config_root="$work_dir/reviewed-dpkg"

  /usr/bin/mkdir -m 0755 -p -- "$config_root/etc" \
    "$config_root/etc/dpkg.cfg.d"
  /usr/bin/chmod 0755 -- "$config_root" "$config_root/etc"
  /usr/bin/tee "$config_root/etc/dpkg.cfg" >/dev/null <<'DPKG_CFG'
# dpkg configuration file
#
# This file can contain default options for dpkg.  All command-line
# options are allowed.  Values can be specified by putting them after
# the option, separated by whitespace and/or an `=' sign.
#

# Do not enable debsig-verify by default; since the distribution is not using
# embedded signatures, debsig-verify would reject all packages.
no-debsig

# Log status changes and actions to a file.
log /var/log/dpkg.log
DPKG_CFG
  /usr/bin/chmod 0644 -- "$config_root/etc/dpkg.cfg"
  printf '%s\n' "$config_root/etc"
}

verify_private_apt_source() {
  local digest

  [ -f "$sources_file" ] && [ ! -L "$sources_file" ] &&
    [ "$(/usr/bin/stat -c '%a' -- "$sources_file")" = 644 ] || {
      echo 'private apt source is not a mode-0644 regular file' >&2
      return 1
    }
  digest=$(/usr/bin/sha256sum -- "$sources_file" | /usr/bin/cut -d' ' -f1)
  [ "$digest" = 96379d39707e38712509e7db3197cd13663a1486c0401347cbac75ffcc181f0b ] || {
    echo 'private apt source differs from the reviewed snapshot contract' >&2
    return 1
  }
}

verify_private_apt_permissions() {
  local path

  for path in \
    "$work_dir" "$source_parts" "$config_parts" "$auth_parts" \
    "$preferences_parts" "$trusted_parts" \
    "$lists" "$archives" "$cache" "$compat_dir" "$state" "$logs"; do
    [ -d "$path" ] && [ ! -L "$path" ] &&
      [ "$(/usr/bin/stat -c '%a' -- "$path")" = 755 ] || {
        echo "private apt public directory is not a real mode-0755 directory: $path" >&2
        return 1
      }
  done
  for path in "$lists/partial" "$archives/partial"; do
    [ -d "$path" ] && [ ! -L "$path" ] &&
      [ "$(/usr/bin/stat -c '%a:%u:%g' -- "$path")" = \
        "700:$apt_partial_uid:$apt_partial_gid" ] || {
        echo "private apt partial directory has unsafe ownership or mode: $path" >&2
        return 1
      }
  done
  [ -d "$compat_private_dir" ] && [ ! -L "$compat_private_dir" ] &&
    [ "$(/usr/bin/stat -c '%a:%u:%g' -- "$compat_private_dir")" = \
      "700:$private_uid:$private_gid" ] || {
      echo 'private compatibility-package directory has unsafe ownership or mode' >&2
      return 1
    }
}

configure_private_apt_hook() {
  local hook_command=$1
  local expected_hook_script=${2:-}
  local hook_tool hook_rest hook_script

  [ -n "$hook_command" ] &&
    [ "${#hook_command}" -le 12288 ] &&
    [[ "$hook_command" != *[$'\n\r\t"\\']* ]] &&
    [[ "$hook_command" == /usr/bin/python3\ -I\ -B\ /*\ --verify-hook\ /*\ /* ]] || {
      echo 'private APT hook command is not canonical' >&2
      return 1
    }
  hook_tool=${hook_command%% *}
  [ -n "$hook_tool" ] || {
    echo 'private APT hook executable is missing' >&2
    return 1
  }
  if [ -n "$expected_hook_script" ]; then
    hook_rest=${hook_command#"/usr/bin/python3 -I -B "}
    hook_script=${hook_rest%% --verify-hook *}
    [ "$hook_script" = "$expected_hook_script" ] || {
      echo 'private APT hook is not bound to the reviewed verifier' >&2
      return 1
    }
  fi
  [ -f "$apt_config" ] && [ ! -L "$apt_config" ] &&
    [ "$(/usr/bin/stat -c '%a' -- "$apt_config")" = 600 ] || {
      echo 'private apt configuration is not a mode-0600 regular file' >&2
      return 1
    }
  if /usr/bin/grep -Eq '^(DPkg::Pre-Install-Pkgs|DPkg::Tools)' "$apt_config"; then
    echo 'private apt configuration already contains a package hook' >&2
    return 1
  fi
  {
    printf 'DPkg::Pre-Install-Pkgs { "%s"; };\n' "$hook_command"
    printf 'DPkg::Tools::options { "%s" { InfoFD "21"; Version "3"; }; };\n' \
      "$hook_tool"
  } >> "$apt_config"
  /usr/bin/chmod 0600 "$apt_config"
}

verify_private_apt_configuration() {
  local hook_command=${1:-}
  local expected_hook_script=${2:-}
  local resolved_config="$work_dir/resolved-apt-config.txt"
  local expected count hook_key hook_rest hook_script
  local -a expected_lines=(
    "Dir::State::lists \"$lists\";"
    "Dir::State::extended_states \"$extended_states\";"
    'Dir::State::status "/var/lib/dpkg/status";'
    "Dir::Cache \"$cache\";"
    "Dir::Cache::archives \"$archives\";"
    "Dir::Cache::srcpkgcache \"$srcpkgcache\";"
    "Dir::Cache::pkgcache \"$pkgcache\";"
    "Dir::Etc::sourcelist \"$sources_file\";"
    "Dir::Etc::sourceparts \"$source_parts\";"
    "Dir::Etc::main \"$empty_config\";"
    "Dir::Etc::parts \"$config_parts\";"
    "Dir::Etc::netrc \"$empty_config\";"
    "Dir::Etc::netrcparts \"$auth_parts\";"
    "Dir::Etc::preferences \"$empty_config\";"
    "Dir::Etc::preferencesparts \"$preferences_parts\";"
    'Dir::Etc::trusted "/dev/null";'
    "Dir::Etc::trustedparts \"$trusted_parts\";"
    "Dir::Log \"$logs\";"
    'Acquire::AllowInsecureRepositories "0";'
    'Acquire::AllowWeakRepositories "0";'
    'Acquire::AllowDowngradeToInsecureRepositories "0";'
    'Acquire::Retries "3";'
    'Acquire::https::Verify-Peer "1";'
    'Acquire::https::Verify-Host "1";'
    'APT::Get::AllowUnauthenticated "0";'
    'APT::Update::Error-Mode "any";'
    'APT::Sandbox::User "_apt";'
    'APT::Architecture "amd64";'
    'APT::Architectures:: "amd64";'
    'Dir::Bin::dpkg "/usr/bin/dpkg";'
    'Dir::Bin::planners "";'
    'Dir::Bin::planners:: "/usr/lib/apt/planners";'
    'Dir::Bin::solvers "";'
    'Dir::Bin::solvers:: "/usr/lib/apt/solvers";'
    'DPkg::ConfigurePending "1";'
    'DPkg::Path "/usr/sbin:/usr/bin:/sbin:/bin";'
    'DPkg::Run-Directory "/";'
  )
  if [ -n "$hook_command" ]; then
    if [ -n "$expected_hook_script" ]; then
      hook_rest=${hook_command#"/usr/bin/python3 -I -B "}
      hook_script=${hook_rest%% --verify-hook *}
      [ "$hook_script" = "$expected_hook_script" ] || {
        echo 'resolved APT hook is not bound to the reviewed verifier' >&2
        return 1
      }
    fi
    hook_key=${hook_command%% *}
    expected_lines+=(
      'DPkg::Pre-Install-Pkgs "";'
      "DPkg::Pre-Install-Pkgs:: \"$hook_command\";"
      'DPkg::Tools "";'
      'DPkg::Tools::options "";'
      "DPkg::Tools::options::$hook_key \"\";"
      "DPkg::Tools::options::$hook_key::InfoFD \"21\";"
      "DPkg::Tools::options::$hook_key::Version \"3\";"
    )
  fi

  [ -f "$apt_config" ] && [ ! -L "$apt_config" ] &&
    [ "$(/usr/bin/stat -c '%a' -- "$apt_config")" = 600 ] || {
      echo 'private apt configuration is not a mode-0600 regular file' >&2
      return 1
    }
  /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/root TMPDIR=/tmp \
    APT_CONFIG="$apt_config" \
    /usr/bin/apt-config dump > "$resolved_config"
  /usr/bin/chmod 0600 "$resolved_config"
  for expected in "${expected_lines[@]}"; do
    count=$(/usr/bin/grep -Fxc -- "$expected" "$resolved_config" || true)
    [ "$count" -eq 1 ] || {
      echo "private apt configuration did not resolve exactly: $expected" >&2
      /usr/bin/grep -E '^DPkg::(Pre-Install-Pkgs|Tools)' \
        "$resolved_config" >&2 || true
      return 1
    }
  done
  count=$(/usr/bin/grep -c '^APT::Architectures:: ' "$resolved_config" || true)
  [ "$count" -eq 1 ] || {
    echo 'private apt configuration did not isolate the native architecture' >&2
    return 1
  }
  count=$(/usr/bin/grep -Ec \
    '^(Dir::Bin::(dpkg|planners|solvers)(::)?|DPkg::(ConfigurePending|Path|Run-Directory)) ' \
    "$resolved_config" || true)
  [ "$count" -eq 8 ] || {
    echo 'private apt execution binary/configuration namespace is not exact' >&2
    return 1
  }
  if /usr/bin/grep -Eq \
    '^(APT::Update::[^ ]*Invoke[^ ]*|DPkg::(Pre|Post)-Invoke|DPkg::Options|Acquire::(http|https)::Proxy)(::| )' \
    "$resolved_config" ||
    { [ -z "$hook_command" ] && /usr/bin/grep -Eq \
      '^(DPkg::Pre-Install-Pkgs|DPkg::Tools)(::| )' "$resolved_config"; }; then
    echo 'private apt configuration inherited a host hook or proxy' >&2
    return 1
  fi
  if [ -n "$hook_command" ]; then
    count=$(/usr/bin/grep -Ec '^DPkg::Pre-Install-Pkgs(::)? ' "$resolved_config" || true)
    [ "$count" -eq 2 ] || {
      echo 'private apt configuration has an inexact pre-install hook set' >&2
      return 1
    }
    count=$(/usr/bin/grep -c '^DPkg::Tools' "$resolved_config" || true)
    [ "$count" -eq 5 ] || {
      echo 'private apt configuration has an inexact hook protocol set' >&2
      return 1
    }
  fi
  count=$(/usr/bin/grep -Fxc -- 'Acquire::Retries "3";' "$apt_config" || true)
  [ "$count" -eq 1 ] &&
    [ "$(/usr/bin/grep -c '^Acquire::Retries ' "$apt_config" || true)" -eq 1 ] || {
      echo 'private apt configuration has an inexact acquisition retry policy' >&2
      return 1
    }
  count=$(/usr/bin/grep -Fxc -- 'APT::Update::Error-Mode "any";' "$apt_config" || true)
  [ "$count" -eq 1 ] &&
    [ "$(/usr/bin/grep -c '^APT::Update::Error-Mode ' "$apt_config" || true)" -eq 1 ] || {
      echo 'private apt configuration has an inexact update failure policy' >&2
      return 1
    }
}

prepare_private_apt_state() {
  local enable_apt_downloads=$1
  case "$enable_apt_downloads" in
    0|1) ;;
    *) echo 'invalid private apt state mode' >&2; exit 1 ;;
  esac
  sources_file="$work_dir/ubuntu-snapshot.sources"
  apt_config="$work_dir/apt.conf"
  empty_config="$work_dir/empty.conf"
  source_parts="$work_dir/source-parts"
  config_parts="$work_dir/config-parts"
  auth_parts="$work_dir/auth-parts"
  preferences_parts="$work_dir/preferences-parts"
  trusted_parts="$work_dir/trusted-parts"
  lists="$work_dir/lists"
  archives="$work_dir/cache/archives"
  cache="$work_dir/cache"
  compat_dir="$work_dir/compat"
  compat_private_dir="$work_dir/compat-private"
  state="$work_dir/state"
  logs="$work_dir/log"
  extended_states="$state/extended_states"
  srcpkgcache="$cache/srcpkgcache.bin"
  pkgcache="$cache/pkgcache.bin"

  /usr/bin/chmod 0755 "$work_dir"
  /usr/bin/mkdir -p \
    "$source_parts" "$config_parts" "$auth_parts" \
    "$preferences_parts" "$trusted_parts" \
    "$lists/partial" "$archives/partial" "$compat_dir" \
    "$compat_private_dir" "$state" "$logs"
  /usr/bin/chmod 0755 \
    "$source_parts" "$config_parts" "$auth_parts" \
    "$preferences_parts" "$trusted_parts" \
    "$lists" "$archives" "$cache" "$compat_dir" "$state" "$logs"
  /usr/bin/chmod 0700 \
    "$lists/partial" "$archives/partial" "$compat_private_dir"
  private_uid=$(/usr/bin/id -u)
  private_gid=$(/usr/bin/id -g)
  if [ "$enable_apt_downloads" = 1 ]; then
    /usr/bin/chown _apt:root "$lists/partial" "$archives/partial"
    apt_partial_uid=$(/usr/bin/id -u _apt)
    apt_partial_gid=0
  else
    apt_partial_uid=$private_uid
    apt_partial_gid=$private_gid
  fi
  verify_private_apt_permissions
  : > "$empty_config"
  /usr/bin/chmod 0644 "$empty_config"
  {
    echo 'Types: deb'
    printf 'URIs: %s\n' "$snapshot"
    echo 'Suites: noble noble-updates noble-security'
    echo 'Components: main'
    echo 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg'
    echo 'Check-Valid-Until: no'
  } > "$sources_file"
  /usr/bin/chmod 0644 "$sources_file"
  verify_private_apt_source
  {
    printf 'Dir::State::lists "%s";\n' "$lists"
    printf 'Dir::State::extended_states "%s";\n' "$extended_states"
    echo 'Dir::State::status "/var/lib/dpkg/status";'
    printf 'Dir::Cache "%s";\n' "$cache"
    printf 'Dir::Cache::archives "%s";\n' "$archives"
    printf 'Dir::Cache::srcpkgcache "%s";\n' "$srcpkgcache"
    printf 'Dir::Cache::pkgcache "%s";\n' "$pkgcache"
    printf 'Dir::Etc::sourcelist "%s";\n' "$sources_file"
    printf 'Dir::Etc::sourceparts "%s";\n' "$source_parts"
    printf 'Dir::Etc::main "%s";\n' "$empty_config"
    printf 'Dir::Etc::parts "%s";\n' "$config_parts"
    printf 'Dir::Etc::netrc "%s";\n' "$empty_config"
    printf 'Dir::Etc::netrcparts "%s";\n' "$auth_parts"
    printf 'Dir::Etc::preferences "%s";\n' "$empty_config"
    printf 'Dir::Etc::preferencesparts "%s";\n' "$preferences_parts"
    echo 'Dir::Etc::trusted "/dev/null";'
    printf 'Dir::Etc::trustedparts "%s";\n' "$trusted_parts"
    printf 'Dir::Log "%s";\n' "$logs"
    echo 'Acquire::Languages "none";'
    echo 'Acquire::Check-Valid-Until "0";'
    echo 'Acquire::AllowInsecureRepositories "0";'
    echo 'Acquire::AllowWeakRepositories "0";'
    echo 'Acquire::AllowDowngradeToInsecureRepositories "0";'
    echo 'Acquire::Retries "3";'
    echo 'Acquire::https::Verify-Peer "1";'
    echo 'Acquire::https::Verify-Host "1";'
    echo 'APT::Get::AllowUnauthenticated "0";'
    echo 'APT::Get::List-Cleanup "0";'
    echo 'APT::Update::Error-Mode "any";'
    echo 'APT::Sandbox::User "_apt";'
    echo '#clear APT::Architectures;'
    echo 'APT::Architecture "amd64";'
    echo 'APT::Architectures { "amd64"; };'
    echo 'DPkg::ConfigurePending "1";'
    echo 'DPkg::Path "/usr/sbin:/usr/bin:/sbin:/bin";'
    echo 'DPkg::Run-Directory "/";'
  } > "$apt_config"
  /usr/bin/chmod 0600 "$apt_config"
  verify_private_apt_configuration
}

if [ "${1:-}" = --check-clean-environment ]; then
  [ "$#" -eq 1 ] || exit 1
  echo 'HAPTICS_APT_CLEAN_ENVIRONMENT=PASS'
  exit 0
fi

if [ "${1:-}" = --check-apt-isolation ]; then
  [ "$#" -eq 1 ] || exit 1
  snapshot=https://snapshot.ubuntu.com/ubuntu/20260913T000000Z/
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-check.XXXXXX)
  prepare_private_apt_state 0
  echo 'HAPTICS_APT_CONFIGURATION=PASS'
  exit 0
fi

if [ "${1:-}" = --check-dpkg-isolation ]; then
  [ "$#" -eq 1 ] || exit 1
  mode_script_path=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
  mode_script_dir=${mode_script_path%/*}
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-dpkg-check.XXXXXX)
  private_home="$work_dir/home"
  reviewed_dpkg_config=$(prepare_reviewed_dpkg_config)
  /usr/bin/mkdir -- "$private_home"
  /usr/bin/chmod 0700 "$private_home"
  /usr/bin/python3 -I -B \
    "$mode_script_dir/verify-haptics-dpkg-configuration.py" \
    --expected-owner 0 --expected-group 0 \
    --expected-home-owner "$(/usr/bin/id -u)" \
    --expected-home-group "$(/usr/bin/id -g)" \
    "$reviewed_dpkg_config" "$private_home" >/dev/null
  echo 'HAPTICS_DPKG_CONFIGURATION_CHECK=PASS'
  exit 0
fi

if [ "${1:-}" = --self-test-apt-source ]; then
  [ "$#" -eq 1 ] || exit 1
  snapshot=https://snapshot.ubuntu.com/ubuntu/20260913T000000Z/
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-source-test.XXXXXX)
  prepare_private_apt_state 0
  printf 'Trusted: yes\n' >> "$sources_file"
  if verify_private_apt_source >/dev/null 2>&1; then
    echo 'private apt source verifier accepted a trusted=yes mutation' >&2
    exit 1
  fi
  echo 'HAPTICS_APT_SOURCE_FIXTURE=PASS'
  exit 0
fi

if [ "${1:-}" = --self-test-apt-config ]; then
  [ "$#" -eq 1 ] || exit 1
  snapshot=https://snapshot.ubuntu.com/ubuntu/20260913T000000Z/
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-config-test.XXXXXX)
  prepare_private_apt_state 0
  echo 'DPkg::Pre-Invoke { "/bin/false"; };' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted a root hook' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'DPkg::Options:: "--force-all";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted a dpkg option' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'Dir::Bin::dpkg "/bin/true";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted a substituted dpkg binary' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'DPkg::ConfigurePending "0";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted disabled pending configuration' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'DPkg::Run-Directory "/tmp";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted a substituted dpkg run directory' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'APT::Update::Post-Invoke-Success:: "/bin/true";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an update success hook' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'Acquire::Retries "0";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted disabled acquisition retries' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'Acquire::Retries "3";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted duplicate acquisition retries' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'APT::Update::Error-Mode "persistent";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted weakened update failure mode' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'APT::Update::Error-Mode "any";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted duplicate update failure mode' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'Dir::Bin::solvers:: "/tmp/evil-solver";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an additional solver' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  echo 'DPkg::Tools::options::/bin/true::Version "2";' >> "$apt_config"
  if verify_private_apt_configuration >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an unbound tool protocol' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  mode_script_path=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
  mode_script_dir=${mode_script_path%/*}
  hook_private="$work_dir/hook-private"
  /usr/bin/mkdir -- "$hook_private"
  /usr/bin/chmod 0700 "$hook_private"
  hook_manifest="$hook_private/expected.tsv"
  hook_marker="$hook_private/hook.ok"
  hook_command="/usr/bin/python3 -I -B $mode_script_dir/verify-haptics-apt-transaction.py --verify-hook $hook_manifest $hook_marker"
  configure_private_apt_hook "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  verify_private_apt_configuration "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  printf 'DPkg::Tools::options { "%s" { InfoFD "22"; }; };\n' \
    "${hook_command%% *}" >> "$apt_config"
  if verify_private_apt_configuration "$hook_command" >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted the wrong hook InfoFD' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  configure_private_apt_hook "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  printf 'DPkg::Tools::options { "%s" { Version "2"; }; };\n' \
    "${hook_command%% *}" >> "$apt_config"
  if verify_private_apt_configuration "$hook_command" >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted the wrong hook version' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  configure_private_apt_hook "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  printf 'DPkg::Pre-Install-Pkgs { "/bin/true"; };\n' >> "$apt_config"
  if verify_private_apt_configuration "$hook_command" >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an extra package hook' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  configure_private_apt_hook "$hook_command" "$mode_script_dir/verify-haptics-apt-transaction.py"
  printf 'DPkg::Tools::options { "%s" { Unknown "1"; }; };\n' \
    "${hook_command%% *}" >> "$apt_config"
  if verify_private_apt_configuration "$hook_command" >/dev/null 2>&1; then
    echo 'private apt configuration verifier accepted an unknown hook option' >&2
    exit 1
  fi
  echo 'HAPTICS_APT_CONFIGURATION_FIXTURE=PASS'
  exit 0
fi

if [ "${1:-}" = --self-test-apt-permissions ]; then
  [ "$#" -eq 1 ] || exit 1
  snapshot=https://snapshot.ubuntu.com/ubuntu/20260913T000000Z/
  work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt-permission-test.XXXXXX)
  prepare_private_apt_state 0
  /usr/bin/chmod 0700 "$work_dir"
  if verify_private_apt_permissions >/dev/null 2>&1; then
    echo 'private apt permission verifier accepted a non-traversable root' >&2
    exit 1
  fi
  prepare_private_apt_state 0
  : > "$lists/partial/residue"
  if verify_apt_partial_directory_empty "$lists/partial" >/dev/null 2>&1; then
    echo 'apt partial-directory verifier accepted a residual index file' >&2
    exit 1
  fi
  /usr/bin/rm -f -- "$lists/partial/residue"
  verify_apt_partial_directory_empty "$lists/partial"
  echo 'HAPTICS_APT_PERMISSION_FIXTURE=PASS'
  exit 0
fi

[ "$#" -eq 4 ] || {
  echo 'usage: install-haptics-build-dependencies.sh PACKAGE_LOCK BUILD_TOOLS_REFERENCE RELEASE_REFERENCE DPKG_HOST_REFERENCE' >&2
  exit 1
}
[ "$(/usr/bin/id -u)" -eq 0 ] || {
  echo 'dependency installation must run as root' >&2
  exit 1
}

SCRIPT_PATH=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
SCRIPT_DIR=${SCRIPT_PATH%/*}
  [ -f "$1" ] && [ ! -L "$1" ] &&
  [ -f "$2" ] && [ ! -L "$2" ] &&
  [ -f "$3" ] && [ ! -L "$3" ] &&
  [ -f "$4" ] && [ ! -L "$4" ] || {
  echo 'dependency evidence inputs must be regular non-symlink files' >&2
  exit 1
}
PACKAGE_LOCK=$(/usr/bin/realpath -e -- "$1")
BUILD_TOOLS_REFERENCE=$(/usr/bin/realpath -e -- "$2")
RELEASE_REFERENCE=$(/usr/bin/realpath -e -- "$3")
DPKG_HOST_REFERENCE=$(/usr/bin/realpath -e -- "$4")
PACKAGE_VERIFIER="$SCRIPT_DIR/verify-haptics-build-packages.py"
COMPAT_VERIFIER="$SCRIPT_DIR/verify-haptics-compat-package.sh"
COMPAT_DOWNLOADER="$SCRIPT_DIR/download-haptics-compat-packages.sh"
DPKG_CONFIG_VERIFIER="$SCRIPT_DIR/verify-haptics-dpkg-configuration.py"
DPKG_STATE_VERIFIER="$SCRIPT_DIR/verify-haptics-dpkg-state.py"
APT_TRANSACTION_VERIFIER="$SCRIPT_DIR/verify-haptics-apt-transaction.py"
SNAPSHOT_VERIFIER="$SCRIPT_DIR/snapshot-bounded-regular-file.py"
LIVE_TOOLS_VERIFIER="$SCRIPT_DIR/verify-haptics-live-build-tools.sh"
BISON_NORMALIZER="$SCRIPT_DIR/normalize-bison-data-directory.py"

[ -f "$BISON_NORMALIZER" ] && [ ! -L "$BISON_NORMALIZER" ] || {
  echo 'Bison data-directory normalizer is not a regular non-symlink file' >&2
  exit 1
}
[ -x "$COMPAT_DOWNLOADER" ] && [ ! -L "$COMPAT_DOWNLOADER" ] || {
  echo 'compatibility-package downloader is not an executable non-symlink file' >&2
  exit 1
}

work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-apt.XXXXXX)
dpkg_home=/root
reviewed_dpkg_config=$(prepare_reviewed_dpkg_config)
/usr/bin/python3 -I -B "$DPKG_CONFIG_VERIFIER" \
  --expected-owner 0 --expected-group 0 \
  "$reviewed_dpkg_config" "$dpkg_home" >/dev/null
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" --self-test
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" "$PACKAGE_LOCK"
HOME="$dpkg_home" /usr/bin/python3 -I -B \
  "$PACKAGE_VERIFIER" --verify-bootstrap "$PACKAGE_LOCK"
[ "$(/usr/bin/sha256sum -- /usr/share/keyrings/ubuntu-archive-keyring.gpg | /usr/bin/cut -d' ' -f1)" = \
  80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31 ] || {
  echo 'Ubuntu archive keyring differs from the reviewed trust anchor' >&2
  exit 1
}

mapfile -d '' -t snapshots < <(
  /usr/bin/python3 -I -B "$PACKAGE_VERIFIER" --emit-snapshot-urls "$PACKAGE_LOCK"
)
[ "${#snapshots[@]}" -eq 1 ] || {
  echo 'package lock must emit exactly one apt snapshot' >&2
  exit 1
}
snapshot=${snapshots[0]}
prepare_private_apt_state 1
transaction_dir="$work_dir/transaction"
/usr/bin/mkdir -- "$transaction_dir"
/usr/bin/chmod 0700 "$transaction_dir"
runtime_package_lock="$work_dir/package-lock.tsv"
private_package_lock="$transaction_dir/package-lock.tsv"
private_host_reference="$transaction_dir/dpkg-host-reference.tsv"
/usr/bin/python3 -I -B "$SNAPSHOT_VERIFIER" \
  "$PACKAGE_LOCK" "$runtime_package_lock" 32768 --mode 0644
/usr/bin/python3 -I -B "$SNAPSHOT_VERIFIER" \
  "$runtime_package_lock" "$private_package_lock" 32768 --mode 0644
/usr/bin/chmod 0600 "$private_package_lock"
/usr/bin/python3 -I -B "$SNAPSHOT_VERIFIER" \
  "$DPKG_HOST_REFERENCE" "$private_host_reference" 33554432 --mode 0644
/usr/bin/chmod 0600 "$private_host_reference"
/usr/bin/python3 -I -B "$DPKG_STATE_VERIFIER" \
  --verify-host-reference /var/lib/dpkg 0 0 "$private_host_reference" >/dev/null
apt_command=(
  /usr/bin/env -i
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  LANG=C LC_ALL=C TZ=UTC HOME="$dpkg_home" TMPDIR=/tmp
  DEBIAN_FRONTEND=noninteractive
  APT_CONFIG="$apt_config"
  /usr/bin/apt-get
)
before_state="$transaction_dir/package-state.before.tsv"
HOME="$dpkg_home" /usr/bin/python3 -I -B \
  "$PACKAGE_VERIFIER" --capture-system-state "$runtime_package_lock" > "$before_state"
/usr/bin/chmod 0600 "$before_state"
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --verify-baseline-state "$runtime_package_lock" "$before_state"
before_dpkg_state="$transaction_dir/dpkg-state.before.tsv"
/usr/bin/python3 -I -B "$DPKG_STATE_VERIFIER" \
  --capture-state /var/lib/dpkg 0 0 > "$before_dpkg_state"
/usr/bin/chmod 0600 "$before_dpkg_state"
before_audit="$work_dir/dpkg-audit.before.txt"
HOME="$dpkg_home" /usr/bin/dpkg --audit > "$before_audit"
/usr/bin/chmod 0600 "$before_audit"
[ ! -s "$before_audit" ] || {
  echo 'dpkg reports an inconsistent pre-transaction state' >&2
  /usr/bin/cat -- "$before_audit" >&2
  exit 1
}

apt_update_stdout="$work_dir/apt-update.stdout"
if run_apt_phase update 300 "$apt_update_stdout" \
  "${apt_command[@]}" -qq update; then
  :
else
  apt_update_status=$?
  exit "$apt_update_status"
fi
verify_apt_partial_directory_empty "$lists/partial"
mapfile -d '' -t package_arguments < <(
  /usr/bin/python3 -I -B "$PACKAGE_VERIFIER" --emit-apt-arguments "$runtime_package_lock"
)
[ "${#package_arguments[@]}" -gt 0 ] || {
  echo 'package lock emitted no apt arguments' >&2
  exit 1
}
mapfile -d '' -t compat_records < <(
  /usr/bin/python3 -I -B "$PACKAGE_VERIFIER" --emit-compat-records "$runtime_package_lock"
)
[ "${#compat_records[@]}" -eq 10 ] || {
  echo 'package lock emitted an unexpected compatibility-package count' >&2
  exit 1
}
compat_debs=()
compat_records_file="$work_dir/compat-records.tsv"
: > "$compat_records_file"
/usr/bin/chmod 0600 "$compat_records_file"
for record in "${compat_records[@]}"; do
  IFS=$'\t' read -r name architecture version url digest extra <<< "$record"
  [ -n "$name" ] && [ -n "$architecture" ] && [ -n "$version" ] &&
    [ -n "$url" ] && [ -n "$digest" ] && [ -z "${extra:-}" ] || {
      echo 'invalid compatibility-package record emitted by verifier' >&2
      exit 1
    }
  destination="$compat_dir/${name}_${version}_${architecture}.deb"
  compat_debs+=("$destination")
  printf '%s\n' "$record" >> "$compat_records_file"
done
compat_download_stdout="$work_dir/compat-download.stdout"
if run_apt_phase compatibility-download 600 "$compat_download_stdout" \
  /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/root TMPDIR=/tmp \
    /bin/bash -p "$COMPAT_DOWNLOADER" \
      "$COMPAT_VERIFIER" "$compat_records_file" \
      "$compat_dir" "$compat_private_dir"; then
  :
else
  compatibility_download_status=$?
  exit "$compatibility_download_status"
fi

transaction_arguments=("${package_arguments[@]}" "${compat_debs[@]}")
[ "${#transaction_arguments[@]}" -eq 211 ] || {
  echo 'package lock emitted an unexpected transaction argument count' >&2
  exit 1
}
empty_status="$work_dir/empty-status"
: > "$empty_status"
/usr/bin/chmod 0600 "$empty_status"
closure_plan="$work_dir/apt-closure.plan"
if run_apt_phase closure-plan 120 "$closure_plan" \
  "${apt_command[@]}" -s -qq \
    -o APT::Get::Show-User-Simulation-Note=0 \
    -o "Dir::State::status=$empty_status" \
    install --no-install-recommends --allow-downgrades --no-remove -- \
    "${transaction_arguments[@]}"; then
  :
else
  closure_plan_status=$?
  exit "$closure_plan_status"
fi
/usr/bin/chmod 0600 "$closure_plan"
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --verify-closure-plan "$runtime_package_lock" "$closure_plan"

host_plan="$transaction_dir/apt-host.plan"
if run_apt_phase host-plan 120 "$host_plan" \
  "${apt_command[@]}" -s -qq \
    -o APT::Get::Show-User-Simulation-Note=0 \
    install --no-install-recommends --allow-downgrades --no-remove -- \
    "${transaction_arguments[@]}"; then
  :
else
  host_plan_status=$?
  exit "$host_plan_status"
fi
/usr/bin/chmod 0600 "$host_plan"
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --verify-host-plan "$runtime_package_lock" "$before_state" "$host_plan"

download_stdout="$work_dir/package-download.stdout"
if run_apt_phase download 600 "$download_stdout" \
  "${apt_command[@]}" -qq -y --download-only \
    install --no-install-recommends --allow-downgrades --no-remove -- \
    "${transaction_arguments[@]}"; then
  :
else
  download_status=$?
  exit "$download_status"
fi
verify_apt_partial_directory_empty "$archives/partial"
hook_manifest="$transaction_dir/expected.tsv"
hook_marker="$transaction_dir/hook.ok"
hook_command="/usr/bin/python3 -I -B $APT_TRANSACTION_VERIFIER --verify-hook $hook_manifest $hook_marker"
[ ! -e "$hook_manifest" ] && [ ! -L "$hook_manifest" ] &&
  [ ! -e "$hook_marker" ] && [ ! -L "$hook_marker" ] || {
    echo 'APT transaction manifest or marker path already exists' >&2
    exit 1
  }
/usr/bin/python3 -I -B "$APT_TRANSACTION_VERIFIER" \
  --prepare-manifest-runtime-reference "$hook_command" \
  "$private_package_lock" "$before_state" "$host_plan" \
  "$before_dpkg_state" "$private_host_reference" \
  "$archives" "$compat_dir" "$hook_manifest"
configure_private_apt_hook "$hook_command" "$APT_TRANSACTION_VERIFIER"
verify_private_apt_configuration "$hook_command" "$APT_TRANSACTION_VERIFIER"
compat_apt_stdout="$work_dir/package-install.stdout"
marker_stdout="$work_dir/package-install-marker.stdout"
post_stdout="$work_dir/package-install-post.stdout"
apt_transaction_cancel_forward=1
apt_transaction_active=1
if run_apt_phase install 600 "$compat_apt_stdout" \
  "${apt_command[@]}" -o Acquire::Retries=0 install -y --no-download \
    --no-install-recommends --allow-downgrades --no-remove -- \
    "${transaction_arguments[@]}"; then
  apt_install_status=0
else
  apt_install_status=$?
fi
apt_transaction_cancel_forward=0
install_cgroup_unsettled=$apt_phase_cgroup_unsettled
if [ "$install_cgroup_unsettled" = 1 ]; then
  marker_status=125
  post_status=125
else
  if run_apt_phase install-marker 120 "$marker_stdout" \
    /usr/bin/python3 -I -B "$APT_TRANSACTION_VERIFIER" \
      --verify-marker "$hook_manifest" "$hook_marker"; then
    marker_status=0
  else
    marker_status=$?
  fi
  if run_apt_phase install-post 120 "$post_stdout" \
    /usr/bin/python3 -I -B "$APT_TRANSACTION_VERIFIER" \
      --verify-post "$hook_manifest" "$before_dpkg_state"; then
    post_status=0
  else
    post_status=$?
  fi
fi
apt_transaction_active=0
if [ -n "$installer_signal_status" ]; then
  exit "$installer_signal_status"
fi
if [ "$apt_install_status" -ne 0 ]; then
  exit "$apt_install_status"
fi
if [ "$marker_status" -ne 0 ] || [ "$post_status" -ne 0 ]; then
  exit 1
fi
if /usr/bin/python3 -I -B "$BISON_NORMALIZER"; then
  bison_normalizer_status=0
else
  bison_normalizer_status=$?
fi
if [ "$bison_normalizer_status" -eq 0 ]; then
  /usr/bin/update-alternatives --set awk /usr/bin/gawk
fi
after_state="$work_dir/package-state.after.tsv"
HOME="$dpkg_home" /usr/bin/python3 -I -B \
  "$PACKAGE_VERIFIER" --capture-system-state "$runtime_package_lock" > "$after_state"
/usr/bin/chmod 0600 "$after_state"
/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --verify-state-transition "$runtime_package_lock" "$before_state" "$after_state"
after_audit="$work_dir/dpkg-audit.after.txt"
HOME="$dpkg_home" /usr/bin/dpkg --audit > "$after_audit"
/usr/bin/chmod 0600 "$after_audit"
[ ! -s "$after_audit" ] || {
  echo 'dpkg reports an inconsistent post-transaction state' >&2
  /usr/bin/cat -- "$after_audit" >&2
  exit 1
}
apt_check_stdout="$work_dir/apt-check.stdout"
if run_apt_phase check 120 "$apt_check_stdout" \
  "${apt_command[@]}" -qq check; then
  :
else
  apt_check_status=$?
  exit "$apt_check_status"
fi
HOME="$dpkg_home" /usr/bin/python3 -I -B \
  "$PACKAGE_VERIFIER" --verify-installed "$runtime_package_lock"
if [ "$bison_normalizer_status" -ne 0 ]; then
  echo 'Bison data-directory normalization failed after package-state audit' >&2
  exit "$bison_normalizer_status"
fi
/bin/bash -p "$LIVE_TOOLS_VERIFIER" \
  "$BUILD_TOOLS_REFERENCE" "$RELEASE_REFERENCE"
echo 'HAPTICS_BUILD_DEPENDENCIES=PASS'
