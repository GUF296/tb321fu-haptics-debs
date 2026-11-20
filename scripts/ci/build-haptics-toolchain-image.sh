#!/usr/bin/bash -p
set -euo pipefail
script_dir=$(/usr/bin/dirname "$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")")
exec /usr/bin/python3 -I -B "$script_dir/build-haptics-toolchain-image.py" "$@"
