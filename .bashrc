#
# ~/.bashrc
#

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

[[ -f ~/.bash_aliases ]] && . ~/.bash_aliases

PS1='[\u@\h \W]\$ '
PATH=$PATH:${HOME}/.gem/ruby/2.5.0/bin:${HOME}/.local/bin

export EDITOR=/usr/bin/vim
export PYTHONPATH=${PYTHONPATH}:${HOME}/.local/lib/python3.6/site-packages
