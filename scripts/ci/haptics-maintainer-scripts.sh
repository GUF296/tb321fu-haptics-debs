#!/usr/bin/env bash
# Render the producer-owned Debian maintainer-script templates.

# The package contract is producer-owned. Do not honor an inherited template
# directory, which could otherwise make an untracked file part of the DEB.
HAPTICS_MAINTAINER_TEMPLATE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/haptics-control-templates" && pwd -P)

haptics_validate_kernel_release() {
  local kernel_release=${1:-}

  [[ $kernel_release =~ ^[0-9A-Za-z][0-9A-Za-z._+~-]{0,127}$ ]]
}

haptics_render_maintainer_template() {
  local template=$1 destination=$2 kernel_release=$3 placeholders placeholder_count
  local destination_parent temporary

  [ -f "$template" ] && [ ! -L "$template" ] || {
    printf 'haptics maintainer template is not a regular file: %s\n' "$template" >&2
    return 1
  }
  haptics_validate_kernel_release "$kernel_release" || {
    printf 'unsafe haptics kernel release: %s\n' "$kernel_release" >&2
    return 1
  }
  if LC_ALL=C grep -aq $'\r' "$template"; then
    printf 'haptics maintainer template contains CR bytes: %s\n' "$template" >&2
    return 1
  fi
  if ! cmp -s "$template" <(tr -d '\000' < "$template"); then
    printf 'haptics maintainer template contains NUL bytes: %s\n' "$template" >&2
    return 1
  fi
  placeholders=$(LC_ALL=C grep -aoE '@[A-Z0-9_]+@' "$template" | sort -u || true)
  [ "$placeholders" = '@KERNEL_RELEASE@' ] || {
    printf 'haptics maintainer template has unsupported placeholders: %s\n' "$template" >&2
    return 1
  }
  placeholder_count=$(LC_ALL=C grep -aoF '@KERNEL_RELEASE@' "$template" | wc -l)
  [ "$placeholder_count" -eq 1 ] || {
    printf 'haptics maintainer template must have exactly one kernel placeholder: %s\n' "$template" >&2
    return 1
  }

  destination_parent=$(dirname -- "$destination")
  [ -d "$destination_parent" ] && [ ! -L "$destination_parent" ] || {
    printf 'haptics maintainer render destination parent is not a real directory: %s\n' "$destination_parent" >&2
    return 1
  }
  [ ! -L "$destination" ] || {
    printf 'haptics maintainer render destination is a symlink: %s\n' "$destination" >&2
    return 1
  }
  temporary=$(mktemp "$destination_parent/.haptics-maintainer.XXXXXX") || {
    printf 'haptics maintainer render cannot create a temporary destination: %s\n' "$destination" >&2
    return 1
  }
  if ! sed "s/@KERNEL_RELEASE@/$kernel_release/g" "$template" > "$temporary"; then
    rm -f -- "$temporary"
    printf 'haptics maintainer render failed while writing: %s\n' "$destination" >&2
    return 1
  fi
  if grep -Fq '@KERNEL_RELEASE@' "$temporary"; then
    rm -f -- "$temporary"
    printf 'haptics maintainer template render left a kernel placeholder: %s\n' "$template" >&2
    return 1
  fi
  if ! dash -n "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  chmod 0755 "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  if ! mv -f -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    printf 'haptics maintainer render cannot atomically install: %s\n' "$destination" >&2
    return 1
  fi
}

haptics_write_maintainer_scripts() {
  local pkgdir=$1 kernel_release=$2 script template template_dir=${3:-$HAPTICS_MAINTAINER_TEMPLATE_DIR}

  [ -d "$pkgdir" ] || {
    printf 'haptics maintainer-script destination is not a directory: %s\n' "$pkgdir" >&2
    return 1
  }
  haptics_validate_kernel_release "$kernel_release" || {
    printf 'unsafe haptics kernel release: %s\n' "$kernel_release" >&2
    return 1
  }
  case "$template_dir" in
    /*) ;;
    *)
      printf 'haptics maintainer template directory must be absolute: %s\n' "$template_dir" >&2
      return 1
      ;;
  esac
  [ -d "$template_dir" ] && [ ! -L "$template_dir" ] || {
    printf 'haptics maintainer template directory is not a real directory: %s\n' "$template_dir" >&2
    return 1
  }
  [ ! -L "$pkgdir/DEBIAN" ] || {
    printf 'haptics maintainer-script destination DEBIAN is a symlink: %s\n' "$pkgdir/DEBIAN" >&2
    return 1
  }
  mkdir -p "$pkgdir/DEBIAN"
  [ -d "$pkgdir/DEBIAN" ] && [ ! -L "$pkgdir/DEBIAN" ] || {
    printf 'haptics maintainer-script destination DEBIAN is not a real directory: %s\n' "$pkgdir/DEBIAN" >&2
    return 1
  }
  for script in postinst prerm postrm; do
    template="$template_dir/$script.in"
    haptics_render_maintainer_template "$template" "$pkgdir/DEBIAN/$script" "$kernel_release" ||
      return 1
  done
  chmod 0755 "$pkgdir/DEBIAN/postinst" "$pkgdir/DEBIAN/prerm" "$pkgdir/DEBIAN/postrm"
}
