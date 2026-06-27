# TB321FU Haptics Debs

Builds the verified AW86937 haptics Debian package for Lenovo Legion Y700 (2025) / TB321FU.

Output:

- tb321fu-haptics_20260627.1_arm64.deb
- tb321fu-haptics-debs_20260627.1_arm64.tar.gz

The workflow builds an external module for kernel 7.1.1-g5df8e852ea72 from:

- Kernel source: https://github.com/GUF296/linux/tree/tb321fu-v7.1.1-y700-daily-20260623
- Kernel build SDK: https://github.com/GUF296/tb321fu-haptics-debs/releases/download/kernel-sdk-7.1.1-g5df8e852ea72/tb321fu-kernel-build-sdk-7.1.1-g5df8e852ea72.tar.gz

The package provides `tb321fu-haptics.service`, `/usr/libexec/tb321fu-haptics/bind-aw86937`, firmware, udev feedbackd integration, and `/dev/input/tb321fu-haptics-left/right` symlinks.
