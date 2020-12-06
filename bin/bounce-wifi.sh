#!/bin/sh

# Script for replugging the Broadcom wifi kernel module when it fails.
#
# Example dmesg entries:
#
#   ieee80211 phy0: brcmf_msgbuf_tx_ioctl: Failed to reserve space in commonring
#   ieee80211 phy0: brcmf_cfg80211_set_power_mgmt: error (-12)
#
# This issue is under investigation: https://bugzilla.kernel.org/show_bug.cgi?id=201853
#
# Machine: XPS 15, Linux 5.x

kernel_version=$(ls -1 /lib/modules | tail -1)
echo "Kernel version: ${kernel_version}"

module=brcmfmac
set -x
modprobe -r ${module}
# By default, modprobe infers the kernel version from `uname`, which fails if
# the kernel headers are more up-to-date than the live kernel. Therefore, we
# explicitly supply the kernel version.
modprobe -S ${kernel_version} ${module}
systemctl restart NetworkManager.service
