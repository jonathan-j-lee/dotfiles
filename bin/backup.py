#!/usr/bin/env python3

import dataclasses
import datetime
import hashlib
import itertools
import json
import pathlib
import tarfile
import typing
import re

import click


METADATA_NAME = '.backup'
KEBIBYTE, MEBIBYTE, GIBIBYTE = 2**10, 2**20, 2**30

as_path = lambda _ctx, path: pathlib.Path(path)
as_paths = lambda _ctx, paths: tuple(map(pathlib.Path, paths))


@dataclasses.dataclass
class ProgressBar:
    total_bytes: int
    width: int = 25
    fill_char: str = '#'
    empty_char: str = '.'
    bytes_processed: int = dataclasses.field(default=0, init=False)
    time_started: datetime.datetime = dataclasses.field(default=datetime.datetime.min, init=False)
    last_update: datetime.datetime = dataclasses.field(default=datetime.datetime.min, init=False)
    current_rate: float = 0

    RATE_DECAY: typing.ClassVar[float] = 0.9

    def __enter__(self):
        self.bytes_processed = 0
        self.time_started = self.last_update = datetime.datetime.now()
        self.current_rate = 0
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        click.echo()

    @property
    def progress(self) -> float:
        return self.bytes_processed/self.total_bytes

    def humanize_file_size(self, byte_count: int, rounding: int = 1) -> str:
        prefixes = ['', 'Ki', 'Mi', 'Gi']
        sizes = [1, KEBIBYTE, MEBIBYTE, GIBIBYTE, float('inf')]
        for prefix, divisor, limit in zip(prefixes, sizes[:-1], sizes[1:]):
            if byte_count < limit:
                value = byte_count if divisor == 1 else round(byte_count/divisor, rounding)
                return f'{value} {prefix}B'

    def update_rate(self, info, default: float = KEBIBYTE) -> float:
        """ Computes the archive rate in bytes per second. """
        now = datetime.datetime.now()
        delta, self.last_update = now - self.last_update, now
        if info.size:
            new_rate = info.size/delta.total_seconds()
            self.current_rate = (1 - self.RATE_DECAY)*new_rate + self.RATE_DECAY*self.current_rate
        return self.current_rate

    def format_rate(self, rate: float) -> str:
        if rate < 8*MEBIBYTE:       # About 0.533 GiB/min
            fg = 'red'
        elif rate < 16*MEBIBYTE:    # About 1.067 GiB/min
            fg = 'yellow'
        else:
            fg = 'green'
        return click.style(self.humanize_file_size(rate) + '/s', fg=fg, bold=True)

    @property
    def eta(self) -> datetime.timedelta:
        if self.bytes_processed == 0:
            return datetime.timedelta.max
        long_term_rate = self.bytes_processed/(self.last_update - self.time_started).total_seconds()
        return datetime.timedelta(seconds=(self.total_bytes - self.bytes_processed)/long_term_rate)

    def format_eta(self, eta: datetime.timedelta) -> str:
        if eta == datetime.timedelta.max:
            return ':'.join(3*['--'])
        seconds = int(eta.total_seconds())
        seconds, minutes = seconds%60, seconds//60
        minutes, hours = minutes%60, minutes//60
        return '{}:{:0>2}:{:0>2}'.format(hours, minutes, seconds)

    def clear(self):
        width, _ = click.get_terminal_size()
        click.echo(' '*width + '\r', nl=False)

    def update(self, info: tarfile.TarFile):
        self.clear()
        self.bytes_processed += info.size
        full = self.fill_char*int(self.width*self.progress)
        empty = self.empty_char*(self.width - len(full))
        percentage = '{:.1f}'.format(100*self.progress).rjust(5) + '%'

        rate = self.update_rate(info)
        size = f' ({self.humanize_file_size(info.size)})' if info.size > 0 else ''
        filename = click.style(pathlib.Path(info.name).name, fg='cyan', bold=True)
        click.echo(' | '.join([
            f'[{full}{empty}] {percentage}',
            f'ETA: {self.format_eta(self.eta)}, Rate: {self.format_rate(rate)}',
            f'Archived {filename}{size}'
        ]) + '\r', nl=False)


@dataclasses.dataclass(frozen=True)
class Archive:
    DEFAULT_EXCLUDE = tuple(map(re.compile, [
        r'^__pycache__$',
        r'^node_modules$',
        r'^\.cache',
        r'^\.?(v|virtual|)envs?$',
        r'^\.vagrant$',
        r'\.(aux|lof|fls|fdb_latexmk|pdfsync|toc)$',    # TeX
        r'\.synctex(\.gz)?(\(busy\))?$',
        r'^\.DS_Store$',
    ]))

    tar: tarfile.TarFile
    hashing_algorithm: str = 'sha256'
    file_types: typing.Sequence[str] = dataclasses.field(default_factory=list)
    exclude: typing.Sequence[re.Pattern] = dataclasses.field(default=DEFAULT_EXCLUDE)

    def should_index_special(self, info: tarfile.TarInfo) -> bool:
        return any(getattr(info, f'is{file_type}')() for file_type in self.file_types)

    def hash_file(self, file_handle, chunk_size: int = 10*KEBIBYTE) -> str:
        """ Compute the hash of a file. """
        hash = getattr(hashlib, self.hashing_algorithm)()
        while (buf := file_handle.read(chunk_size)):
            hash.update(buf)
        return hash.hexdigest()

    def should_exclude(self, path: pathlib.Path) -> bool:
        return any(pattern.search(path.name) for pattern in self.exclude)

    def scan(self, source: pathlib.Path) -> typing.Iterable[tarfile.TarInfo]:
        if self.should_exclude(source):
            return
        info = self.tar.gettarinfo(source)
        if not info:  # Cannot archive sockets
            return
        elif info.isdir():
            yield info
            for child in source.iterdir():
                yield from self.scan(child)
        elif info.isfile() or self.should_index_special(info):
            yield info

    def create(self, infos: typing.Iterable[tarfile.TarInfo], bar: ProgressBar):
        root = pathlib.Path('/')
        for info in infos:
            if info.isfile():
                path = root.joinpath(info.name)
                with open(path, 'rb') as file_handle:
                    hash = self.hash_file(file_handle)
                    # The file cache has been warmed up, so re-reading the file
                    # should not be too slow.
                    file_handle.seek(0)
                    self.tar.addfile(info, file_handle)
                    bar.update(info)
            else:
                self.tar.addfile(info)


def filter_redundant_sources(sources: typing.Sequence[pathlib.Path]) \
        -> typing.Iterable[pathlib.Path]:
    if not sources:
        return
    sources = iter(sorted(source.absolute() for source in sources))
    yield (current_path := next(sources))
    for next_path in sources:
        if not next_path.is_relative_to(current_path):
            yield (current_path := next_path)


@click.group(context_settings={'max_content_width': 120})
@click.option('--archive', default=str(pathlib.Path.cwd()), callback=as_path,
              type=click.Path(file_okay=False, exists=True),
              help='Directory the backups and metadata are written to.')
@click.option('--dry-run', is_flag=True, help='Do not make persistent changes.')
@click.version_option(version='0.0.1', message='v%(version)s')
@click.pass_context
def cli(ctx, **options):
    """
    Create incremental encrypted backups.
    """
    (options['archive'] / METADATA_NAME).mkdir(parents=True, exist_ok=True)
    ctx.ensure_object(dict)
    ctx.obj.update(options)


@cli.command()
@click.option('--source', default=[str(pathlib.Path.home())], callback=as_paths,
              show_default=True, type=click.Path(exists=True), multiple=True,
              help='Directories to backup.')
@click.option('--compression', type=click.Choice(['gz', 'bz2', 'xz']),
              help='Compression method (no compression by default).')
@click.option('--hash', default='sha256',
              type=click.Choice(['sha256', 'sha384', 'sha512']),
              help='Hashing algorithm used to check file equality.')
@click.option('--type', default=['sym'], show_default=True, multiple=True,
              type=click.Choice(['sym', 'lnk', 'chr', 'blk', 'fifo']),
              help='Special file types to archive.')
@click.pass_context
def create(ctx, **options):
    """ Create a backup. """
    compression = options['compression'] or ''
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H%M%S')
    filename = f'{timestamp}-backup.tar{"." + compression if compression else ""}'

    sources = tuple(filter_redundant_sources(options['source']))
    with tarfile.open(str(ctx.obj['archive'] / filename), 'w|' + compression) as tar:
        archive = Archive(tar, options['hash'], options['type'])
        infos = list(itertools.chain(*(archive.scan(source) for source in sources)))
        for info in infos:
            print(info.name)
        total_bytes = sum(info.size for info in infos)
        with ProgressBar(total_bytes) as bar:
            archive.create(infos, bar)


@cli.command()
@click.pass_context
def restore(ctx):
    """ Restore a backup. """


@cli.command('list')
@click.pass_context
def list_backups(ctx):
    """ List available backups. """


@cli.command()
@click.pass_context
def remove(ctx):
    """ Remove backup. """


@cli.command()
@click.pass_context
def check(ctx):
    pass


# @click.option('-m', '--max-size', default=100*MEBIBYTE)
# @click.option('-e', '--exclude', multiple=True, default=DEFAULT_EXCLUDE)
# @click.option('--encrypt/--no-encrypt', default=True, help='Encrypt archive')
# @click.option('--sign/--no-sign', default=True)
# traverse_tree(pathlib.Path(options['source']), [re.compile(pattern) for pattern in options['exclude']])


if __name__ == '__main__':
    cli()
