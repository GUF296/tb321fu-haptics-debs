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

  sed "s/@KERNEL_RELEASE@/$kernel_release/g" "$template" > "$destination"
  if grep -Fq '@KERNEL_RELEASE@' "$destination"; then
    printf 'haptics maintainer template render left a kernel placeholder: %s\n' "$template" >&2
    return 1
  fi
  dash -n "$destination"
}

haptics_write_maintainer_scripts() {
  local pkgdir=$1 kernel_release=$2 script template

  [ -d "$pkgdir" ] || {
    printf 'haptics maintainer-script destination is not a directory: %s\n' "$pkgdir" >&2
    return 1
  }
  haptics_validate_kernel_release "$kernel_release" || {
    printf 'unsafe haptics kernel release: %s\n' "$kernel_release" >&2
    return 1
  }
  mkdir -p "$pkgdir/DEBIAN"
  for script in postinst prerm postrm; do
    template="$HAPTICS_MAINTAINER_TEMPLATE_DIR/$script.in"
    haptics_render_maintainer_template "$template" "$pkgdir/DEBIAN/$script" "$kernel_release" ||
      return 1
  done
  chmod 0755 "$pkgdir/DEBIAN/postinst" "$pkgdir/DEBIAN/prerm" "$pkgdir/DEBIAN/postrm"
}
