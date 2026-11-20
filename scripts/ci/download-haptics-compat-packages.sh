#!/bin/bash -p
case $- in
  *p*) ;;
  *) echo 'compatibility-package download requires privileged Bash mode' >&2; exit 1 ;;
esac
set -euo pipefail
umask 077

[ "$#" -eq 4 ] || {
  echo 'usage: download-haptics-compat-packages.sh VERIFIER RECORDS PUBLIC_DIR PRIVATE_DIR' >&2
  exit 1
}
verifier=$1
records_file=$2
public_dir=$3
private_dir=$4
# Soft admission budget, checked only before starting the next package. Curl
# resets --max-time for each retry; --retry-max-time does not stop an attempt
# already in progress. Verification may also finish after this soft budget.
# The installer's outer phase supervision supplies the 600-second hard deadline.
soft_admission_seconds=590
current_partial=

cleanup() {
  if [ -n "$current_partial" ]; then
    /usr/bin/rm -f -- "$current_partial"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for file in "$verifier" "$records_file"; do
  [ -f "$file" ] && [ ! -L "$file" ] &&
    [ "$file" = "$(/usr/bin/realpath -e -- "$file")" ] || {
      echo "compatibility-package input is not a canonical regular file: $file" >&2
      exit 1
    }
done
[ -x "$verifier" ] || {
  echo 'compatibility-package verifier is not executable' >&2
  exit 1
}
[ "$(/usr/bin/stat -c '%a:%u:%g:%h' -- "$records_file")" = \
  "600:$(/usr/bin/id -u):$(/usr/bin/id -g):1" ] &&
  [ "$(/usr/bin/stat -c '%s' -- "$records_file")" -le 32768 ] || {
  echo 'compatibility-package record file has unsafe metadata' >&2
  exit 1
}
for directory in "$public_dir" "$private_dir"; do
  [ -d "$directory" ] && [ ! -L "$directory" ] &&
    [ "$directory" = "$(/usr/bin/realpath -e -- "$directory")" ] || {
      echo "compatibility-package directory is not canonical: $directory" >&2
      exit 1
    }
done
[ "$(/usr/bin/stat -c '%a:%u:%g' -- "$public_dir")" = \
  "755:$(/usr/bin/id -u):$(/usr/bin/id -g)" ] &&
  [ "$(/usr/bin/stat -c '%a:%u:%g' -- "$private_dir")" = \
  "700:$(/usr/bin/id -u):$(/usr/bin/id -g)" ] || {
  echo 'compatibility-package directories have unsafe metadata' >&2
  exit 1
}
[ "$public_dir" != "$private_dir" ] &&
  [ "$(/usr/bin/stat -c '%d' -- "$public_dir")" = \
  "$(/usr/bin/stat -c '%d' -- "$private_dir")" ] || {
  echo 'compatibility-package directories are not separate on one filesystem' >&2
  exit 1
}

mapfile -t records < "$records_file"
[ "${#records[@]}" -eq 10 ] || {
  echo 'compatibility-package record file has an unexpected record count' >&2
  exit 1
}
names=()
architectures=()
versions=()
urls=()
digests=()
declare -A seen_outputs=()
for record in "${records[@]}"; do
  IFS=$'\t' read -r name architecture version url digest extra <<< "$record"
  [[ $name =~ ^[a-z0-9][a-z0-9+.-]{0,79}$ ]] &&
    [[ $version =~ ^[0-9A-Za-z][0-9A-Za-z.+:~-]{0,159}$ ]] &&
    [[ $architecture = amd64 || $architecture = all ]] &&
    [[ $url =~ ^https://[^[:space:]]{1,2048}$ ]] &&
    [[ $digest =~ ^[0-9a-f]{64}$ ]] &&
    [ -z "${extra:-}" ] || {
      echo 'compatibility-package record is not canonical' >&2
      exit 1
    }
  destination="$public_dir/${name}_${version}_${architecture}.deb"
  partial="$private_dir/${name}_${version}_${architecture}.deb.part"
  [ -z "${seen_outputs[$destination]+present}" ] || {
    echo "duplicate compatibility-package output: $name" >&2
    exit 1
  }
  seen_outputs[$destination]=1
  [ ! -e "$destination" ] && [ ! -L "$destination" ] &&
    [ ! -e "$partial" ] && [ ! -L "$partial" ] || {
      echo "compatibility-package output already exists: $name" >&2
      exit 1
    }
  names+=("$name")
  architectures+=("$architecture")
  versions+=("$version")
  urls+=("$url")
  digests+=("$digest")
done

SECONDS=0
for index in "${!names[@]}"; do
  remaining=$((soft_admission_seconds - SECONDS))
  [ "$remaining" -gt 0 ] || {
    echo 'compatibility-package next-package admission budget expired' >&2
    exit 124
  }
  connect_timeout=$remaining
  [ "$connect_timeout" -le 30 ] || connect_timeout=30
  name=${names[$index]}
  architecture=${architectures[$index]}
  version=${versions[$index]}
  destination="$public_dir/${name}_${version}_${architecture}.deb"
  current_partial="$private_dir/${name}_${version}_${architecture}.deb.part"
  /usr/bin/curl --disable --fail --location --silent --show-error \
    --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout "$connect_timeout" \
    --max-time "$remaining" --max-filesize 67108864 \
    --retry 3 --retry-delay 2 --retry-max-time "$remaining" \
    --output "$current_partial" -- "${urls[$index]}"
  /bin/bash -p "$verifier" "$current_partial" "$destination" \
    "$name" "$version" "$architecture" "${digests[$index]}" >/dev/null
  current_partial=
done

echo 'HAPTICS_COMPAT_PACKAGE_DOWNLOADS=PASS'
