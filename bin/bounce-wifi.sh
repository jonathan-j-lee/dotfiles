#!/bin/sh

# Sometimes, wifi will stop working after suspension (XPS 15, Arch Linux). Example dmesg errors:
#
#   ieee80211 phy0: brcmf_msgbuf_tx_ioctl: Failed to reserve space in commonring
#   ieee80211 phy0: brcmf_cfg80211_set_power_mgmt: error (-12)
#
# This script reloads a wifi-related kernel module.

kernel_version=$(ls -1 /lib/modules | tail -1)
echo "Kernel version: ${kernel_version}"

module=brcmfmac
set -x
modprobe -r ${module}
modprobe -S ${kernel_version} ${module}
systemctl restart NetworkManager.service
