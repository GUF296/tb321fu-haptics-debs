# Patch Records

This directory records the source/rootfs delta in patch-like form for review.

- `mainline-delta-summary.patch` is a human-readable unified-diff style record
  for the files that need to be added or integrated relative to a mainline-style
  tree.
- The canonical full files are in `../source-integration/` and
  `../testing-tools/`.

For actual reproduction, prefer copying the full files/snippets from the
canonical directories rather than manually applying this review summary.
