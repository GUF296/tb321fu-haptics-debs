#!/usr/bin/bash -p
set -euo pipefail
export LANG=C LC_ALL=C TZ=UTC DEBIAN_FRONTEND=noninteractive
cd /policy
mapfile -t debs < <(printf '%s\n' /debs/*.deb)
[ "${#debs[@]}" -eq 211 ]
mkdir -p /tmp/haptics-empty-apt
: > /tmp/haptics-empty-apt/sources.list
archive_options=(-o Dir::Etc::sourcelist=/tmp/haptics-empty-apt/sources.list
                 -o Dir::Etc::sourceparts=/tmp/haptics-empty-apt)
# The canonical OCI image supplies APT and dpkg. The verified DEBs are the only
# package source, and Docker builds this stage with networking disabled.
apt-get "${archive_options[@]}" -y --no-install-recommends --allow-downgrades \
  --no-remove install -- "${debs[@]}"
update-alternatives --set awk /usr/bin/gawk
python3 -IB verify-haptics-build-packages.py --verify-installed HAPTICS-BUILD-PACKAGES.tsv
apt-get "${archive_options[@]}" check
audit=$(dpkg --audit)
[ -z "$audit" ] || { printf '%s\n' "$audit" >&2; exit 1; }
/bin/bash -p verify-haptics-live-build-tools.sh \
  HAPTICS-BUILD-TOOLS-REFERENCE.tsv HAPTICS-RELEASE-REFERENCE.tsv
