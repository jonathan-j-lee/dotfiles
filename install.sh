#!/bin/bash

dotfiles=$(git rev-parse --show-toplevel)

sudo cp $dotfiles/systemd/* /etc/systemd/system
sudo systemctl enable rkhunter.timer
sudo systemctl start rkhunter.timer
