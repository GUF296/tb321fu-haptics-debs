#!/bin/bash -p
set -euo pipefail
umask 077

SCRIPT_PATH=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
SCRIPT_DIR=${SCRIPT_PATH%/*}
REFERENCE="$SCRIPT_DIR/HAPTICS-BUILD-TOOLS-REFERENCE.tsv"
RELEASE_REFERENCE="$SCRIPT_DIR/HAPTICS-RELEASE-REFERENCE.tsv"
VERIFIER="$SCRIPT_DIR/verify-haptics-live-build-tools.sh"
INSTALLER="$SCRIPT_DIR/install-haptics-build-dependencies.sh"
NORMALIZER="$SCRIPT_DIR/normalize-bison-data-directory.py"
tmp=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-live-tools-test.XXXXXX)
cleanup() {
  /usr/bin/rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

/bin/bash -p "$VERIFIER" --verify-manifest \
  "$REFERENCE" "$REFERENCE" "$RELEASE_REFERENCE" >/dev/null
/usr/bin/env -i \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C TZ=UTC \
  HOME=/nonexistent TMPDIR=/tmp HAPTICS_LIVE_TOOLS_CLEAN_ENV=1 \
  APT_CONFIG="$tmp/hostile-apt.conf" PYTHONPATH="$tmp/hostile-python" \
  BASH_FUNC_sha256sum%%='() { echo hostile; }' \
  /bin/bash -p "$VERIFIER" --verify-manifest \
    "$REFERENCE" "$REFERENCE" "$RELEASE_REFERENCE" >/dev/null
/usr/bin/env -i \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C TZ=UTC \
  HOME=/root TMPDIR=/tmp HAPTICS_APT_CLEAN_ENV=1 \
  APT_CONFIG="$tmp/hostile-apt.conf" PYTHONPATH="$tmp/hostile-python" \
  BASH_FUNC_dpkg%%='() { echo hostile; }' \
  /bin/bash -p "$INSTALLER" --check-clean-environment >/dev/null
/bin/bash -p "$INSTALLER" --check-apt-isolation >/dev/null
/bin/bash -p "$INSTALLER" --check-dpkg-isolation >/dev/null
/bin/bash -p "$INSTALLER" --self-test-apt-source >/dev/null
/bin/bash -p "$INSTALLER" --self-test-apt-config >/dev/null
/bin/bash -p "$INSTALLER" --self-test-apt-permissions >/dev/null
/bin/bash -p "$INSTALLER" --self-test-apt-sandbox-log >/dev/null
/usr/bin/python3 -I -B "$NORMALIZER" --self-test >/dev/null
for transaction_gate in \
  --capture-system-state --verify-closure-plan --verify-host-plan \
  --verify-state-transition --download-only --prepare-manifest-runtime-reference \
  --verify-marker --verify-post configure_private_apt_hook; do
  /usr/bin/grep -Fq -- "$transaction_gate" "$INSTALLER" || {
    echo "dependency installer omits transaction gate: $transaction_gate" >&2
    exit 1
  }
done
if /usr/bin/grep -Fq -- '  --prepare-manifest "$hook_command"' "$INSTALLER"; then
  echo 'dependency installer still uses the cross-runner host-reference mode' >&2
  exit 1
fi
install_count=$(/usr/bin/grep -Fc -- '"${apt_command[@]}" install -y' "$INSTALLER")
[ "$install_count" -eq 1 ] || {
  echo "dependency installer must execute exactly one apt install transaction" >&2
  exit 1
}
download_line=$(/usr/bin/grep -nF -- '--download-only' "$INSTALLER" | /usr/bin/tail -n1 | /usr/bin/cut -d: -f1)
prepare_line=$(/usr/bin/grep -nF -- '--prepare-manifest-runtime-reference' "$INSTALLER" | /usr/bin/tail -n1 | /usr/bin/cut -d: -f1)
configure_line=$(/usr/bin/grep -nF -- 'configure_private_apt_hook "$hook_command"' "$INSTALLER" | /usr/bin/tail -n1 | /usr/bin/cut -d: -f1)
install_line=$(/usr/bin/grep -nF -- '"${apt_command[@]}" install -y' "$INSTALLER" | /usr/bin/cut -d: -f1)
marker_line=$(/usr/bin/grep -nF -- '--verify-marker' "$INSTALLER" | /usr/bin/tail -n1 | /usr/bin/cut -d: -f1)
post_line=$(/usr/bin/grep -nF -- '--verify-post' "$INSTALLER" | /usr/bin/tail -n1 | /usr/bin/cut -d: -f1)
sandbox_line=$(/usr/bin/grep -nF -- 'verify_no_apt_sandbox_fallback "$compat_apt_stderr"' "$INSTALLER" | /usr/bin/tail -n1 | /usr/bin/cut -d: -f1)
normalize_line=$(/usr/bin/grep -nF -- '/usr/bin/python3 -I -B "$BISON_NORMALIZER"' "$INSTALLER" | /usr/bin/cut -d: -f1)
live_tools_line=$(/usr/bin/grep -nF -- '"$LIVE_TOOLS_VERIFIER"' "$INSTALLER" | /usr/bin/tail -n1 | /usr/bin/cut -d: -f1)
[ "$download_line" -lt "$prepare_line" ] &&
  [ "$prepare_line" -lt "$configure_line" ] &&
  [ "$configure_line" -lt "$install_line" ] &&
  [ "$install_line" -lt "$marker_line" ] &&
  [ "$marker_line" -lt "$post_line" ] &&
  [ "$post_line" -lt "$sandbox_line" ] &&
  [ "$sandbox_line" -lt "$normalize_line" ] &&
  [ "$normalize_line" -lt "$live_tools_line" ] || {
    echo 'dependency installer transaction gates are not in fail-closed order' >&2
    exit 1
  }
/usr/bin/grep -Fq -- '"$PACKAGE_VERIFIER" --capture-system-state "$runtime_package_lock"' "$INSTALLER" || {
  echo 'dependency installer captures post-state through the mutable package-lock path' >&2
  exit 1
}
/usr/bin/grep -Fq -- "--proto-redir '=https'" "$INSTALLER" || {
  echo 'dependency installer does not restrict compatibility-package redirects to HTTPS' >&2
  exit 1
}
/usr/bin/cp -- "$REFERENCE" "$tmp/mutated.tsv"
/usr/bin/chmod 0644 "$tmp/mutated.tsv"
/usr/bin/sed -i 's#tool\tgit\t#tool\tgit-mutated\t#' "$tmp/mutated.tsv"
if /bin/bash -p "$VERIFIER" --verify-manifest \
  "$tmp/mutated.tsv" "$REFERENCE" "$RELEASE_REFERENCE" >/dev/null 2>&1; then
  echo 'mutated live build-tools manifest was accepted' >&2
  exit 1
fi
/usr/bin/cp -- "$RELEASE_REFERENCE" "$tmp/reference.tsv"
/usr/bin/chmod 0644 "$tmp/reference.tsv"
/usr/bin/sed -i \
  's#^build-tools-manifest-sha256\t.#build-tools-manifest-sha256\t0#' \
  "$tmp/reference.tsv"
if /bin/bash -p "$VERIFIER" --verify-manifest \
  "$REFERENCE" "$REFERENCE" "$tmp/reference.tsv" >/dev/null 2>&1; then
  echo 'mutated release-reference build-tools digest was accepted' >&2
  exit 1
fi
echo 'HAPTICS_LIVE_BUILD_TOOLS_FIXTURE=PASS'
