# System Maintenance

## Set Up an Encrypted Drive

1. Generate 2048 cryptographically secure random bytes.
```sh
dd bs=512 count=4 if=/dev/urandom of=/path/to/backup-drive-key
```
1. Set up a LUKS2 encrypted volume.
```sh
cryptsetup --cipher aes-xts-plain64 --key-size 512 --hash sha256 --use-urandom luksFormat --type luks2 /dev/sda /path/to/backup-drive-key
```
1. Open the volume, which makes `/dev/mapper/vault` available to mount.
```sh
cryptsetup open --type luks2 --key-file /path/to/backup-drive-key /dev/sda vault
```
1. Make an `ext4` filesystem (pick any `mkfs.*` command, as desired).
```sh
mkfs.ext4 /dev/mapper/vault
```
1. Close the volume.
```sh
cryptsetup close vault
```

Repeat steps (3) and (5) on subsequent use.
