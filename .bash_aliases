#
# ~/.bash_aliases
#

# Enable color on coreutils
alias ls="ls --color=auto"
alias diff="diff --color"
alias grep="grep --line-number --colour --binary-files=without-match"

alias scp="scp -F ~/.ssh/config"
alias journalclean="journalctl --vacuum-time=2d"

# Power information
alias battery="upower -i /org/freedesktop/UPower/devices/battery_BAT0"
alias pwr="acpi"
alias temp="acpi -tf"

alias ports="ss -lnptu"
alias alert="notify-send --urgency=low -i terminal $1"
alias nfiles="ls -1A | wc -l"  # Count number of files (includes hidden files)
alias rmd5sum="find $1 -type f -print0 | xargs -0 md5sum"  # Recursive md5sum

alias sl="sl -a"
