" .vimrc

colorscheme hybrid
set background=dark
syntax enable

" Enable four-space tabs
set tabstop=4
set softtabstop=4
set expandtab

set number
set showcmd
set cursorline  " Highlight current line of cursor
set autoindent
set wildmenu
set lazyredraw
set showmatch   " Highlight search matches

filetype plugin indent on

set incsearch
set hlsearch

" Disable swap files
set noswapfile

autocmd BufWritePre * :%s/\s\+$//e

set backup
set backupdir=/tmp
set writebackup

if has("autocmd")
  au BufReadPost * if line("'\"") > 0 && line("'\"") <= line("$") | exe "normal! g`\"" | endif
endif
