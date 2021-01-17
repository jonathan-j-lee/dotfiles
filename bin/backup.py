#!/usr/bin/env python3

import collections.abc
import contextlib
import dataclasses
import datetime
import functools
import hashlib
import itertools
import json
from pathlib import Path
import re
import tarfile
import typing

import click


ROOT = Path('/')
BYTE_UNITS: dict[str, int] = {
    'k': (KILOBYTE := 10**3),
    'M': (MEGABYTE := 10**6),
    'G': (GIGABYTE := 10**9),
}


def parse_file_size(size: str) -> int:
    """
    Parse a string for a number of bytes, respecting SI prefixes.

    >>> parse_file_size('100')
    100
    >>> parse_file_size('1k')
    1000
    >>> parse_file_size('1.1 M')
    1100000
    """
    if size == 'inf':
        return float('inf')
    size = size.strip().removesuffix('B')
    try:
        return int(size)
    except ValueError:
        value, unit = float(size[:-1].strip()), size[-1]
        return int(value*BYTE_UNITS[unit])


def format_file_size(size: int, rounding: int = 1) -> str:
    """
    Format a number of bytes as a human-readable string using SI prefixes.

    >>> format_file_size(100)
    '100 B'
    >>> format_file_size(1000)
    '1.0 kB'
    >>> format_file_size(1_001_000, rounding=3)
    '1.001 MB'
    """
    units = {'': 1, **BYTE_UNITS}
    prefixes, sizes = zip(*sorted(units.items(), key=lambda unit: unit[1]))
    for prefix, divisor, limit in zip(prefixes, sizes, sizes[1:] + (float('inf'),)):
        if size < limit:
            if divisor > 1:
                size = round(size/divisor, rounding)
            return f'{size} {prefix}B'


def format_duration(duration: datetime.timedelta) -> str:
    """
    Format a timedelta as a human-readable string in the HH:MM:SS format.

    >>> format_duration(datetime.timedelta(seconds=5))
    '0:00:05'
    >>> format_duration(datetime.timedelta(hours=100, minutes=5, seconds=5))
    '100:05:05'
    """
    if duration == datetime.timedelta.max:
        return ':'.join(3*['--'])
    seconds = int(duration.total_seconds())
    seconds, minutes = seconds%60, seconds//60
    minutes, hours = minutes%60, minutes//60
    return '{}:{:0>2}:{:0>2}'.format(hours, minutes, seconds)


class AbortException(Exception):
    """ Raised whenever the user aborts an operation by choosing not to confim. """


@dataclasses.dataclass
class FileProgressBar:
    """ A CLI-rendered progress bar representing work done on files. """
    total_bytes: int
    width: int = 40
    fill_char: str = '#'
    empty_char: str = '.'
    slow_rate: float = 8*MEGABYTE
    medium_rate: float = 16*MEGABYTE
    rate_decay: float = 0.9
    bytes_processed: int = dataclasses.field(default=0, init=False, repr=False)
    time_started: datetime.datetime = \
        dataclasses.field(default=datetime.datetime.min, init=False, repr=False)
    last_update: datetime.datetime = \
        dataclasses.field(default=datetime.datetime.min, init=False, repr=False)
    current_rate: float = dataclasses.field(default=0, init=False, repr=False)

    def __enter__(self):
        self.bytes_processed = self.current_rate = 0
        self.time_started = self.last_update = datetime.datetime.now()
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        click.echo()

    @property
    def progress(self) -> float:
        """ Fraction of bytes processed. """
        return self.bytes_processed/self.total_bytes

    @property
    def duration(self) -> datetime.timedelta:
        return self.last_update - self.time_started

    def update_rate(self, size: int) -> float:
        """
        Compute a rate in bytes per second.

        The rate is smoothed using an exponential weighted moving average (EWMA).
        """
        now = datetime.datetime.now()
        delta, self.last_update = now - self.last_update, now
        if size > 0:
            new_rate = size/delta.total_seconds()
            self.current_rate = (1 - self.rate_decay)*new_rate + self.rate_decay*self.current_rate
        return self.current_rate

    def format_rate(self, rate: float) -> str:
        if rate < self.slow_rate:
            fg = 'red'
        elif rate < self.medium_rate:
            fg = 'yellow'
        else:
            fg = 'green'
        return click.style(format_file_size(rate) + '/s', fg=fg, bold=True)

    @property
    def eta(self) -> datetime.timedelta:
        if self.bytes_processed == 0:
            return datetime.timedelta.max
        long_term_rate = self.bytes_processed/self.duration.total_seconds()
        bytes_remaining = self.total_bytes - self.bytes_processed
        return datetime.timedelta(seconds=bytes_remaining/long_term_rate)

    def clear(self):
        width, _ = click.get_terminal_size()
        click.echo(' '*width + '\r', nl=False)

    def update(self, name: str, size: int = 0):
        if size == 0:   # Can result in screen flicker
            return
        self.clear()
        self.bytes_processed += size
        full = self.fill_char*int(self.width*self.progress)
        empty = self.empty_char*(self.width - len(full))
        percentage = '{:.1f}%'.format(100*self.progress).rjust(5)

        rate = self.update_rate(size)
        filename = click.style(name, fg='cyan', bold=True)
        if size > 0:
            filename += f' ({format_file_size(size)})'
        click.echo(' | '.join([
            f'[{full}{empty}] {percentage}',
            f'Runtime: {format_duration(self.duration)}, '
            f'ETA: {format_duration(self.eta)}, Rate: {self.format_rate(rate)}',
            filename,
        ]) + '\r', nl=False)


class Mount(typing.NamedTuple):
    src: Path
    dst: typing.Optional[Path]
    DELIMETER = ':'

    @classmethod
    def parse(cls, text) -> 'Mount':
        src, dst = text.split(cls.DELIMETER)
        return cls(Path(src), Path(dst) if dst else None)

    def substitute(self, path: Path) -> typing.Optional[Path]:
        try:
            suffix = path.relative_to(self.src)
        except ValueError:
            return path
        if self.dst:
            return self.dst.joinpath(suffix)


def make_option_parser(callback, exceptions: tuple[type] = (ValueError,)):
    @functools.wraps(callback)
    def wrapper(_ctx, value):
        try:
            if isinstance(value, tuple):
                return tuple(map(callback, value))
            return callback(value)
        except exceptions as exc:
            raise click.BadParameter(repr(value)) from exc
    return wrapper


def parse_permission(permissions: str) -> list[tuple[str, str, str]]:
    if not (match := re.match(r'^([ugo]+)([\+\-])([rwx]+)$', permissions.lower())):
        raise ValueError
    owners, present, actions = match.groups()
    return [(owner, present, action) for owner in owners for action in actions]


@dataclasses.dataclass(frozen=True)
class FileFilter(typing.Callable[[tarfile.TarInfo], bool]):
    """
    Filter files by their attributes (name, size, type, user/group, permissions, etc).

    >>> path = Path('/var/log/pacman.log')
    >>> info = tarfile.TarInfo(path)
    >>> Filter = functools.partial(FileFilter, file_types=frozenset({'file', 'dir'}))
    >>> Filter()(info)
    True
    >>> Filter(exclude_patterns=tuple(['*.log']))(info)
    False
    >>> Filter = functools.partial(Filter, users=frozenset({'me'}))
    >>> Filter()(info)
    False
    >>> info.uname = 'me'
    >>> Filter()(info)
    True
    """
    mounts: tuple[Mount] = dataclasses.field(default_factory=tuple)
    exclude_patterns: tuple[str] = dataclasses.field(default_factory=tuple)
    max_size: int = float('inf')
    file_types: tuple[str] = dataclasses.field(default_factory=tuple)
    users: frozenset[str] = dataclasses.field(default_factory=frozenset)
    groups: frozenset[str] = dataclasses.field(default_factory=frozenset)
    permissions: frozenset[tuple[str, str, str]] = dataclasses.field(default_factory=frozenset)
    min_mtime: datetime.datetime = datetime.datetime.min
    max_mtime: datetime.datetime = datetime.datetime.max

    _datetime_option = functools.partial(
        click.option,
        metavar='[YYYY-MM-DDTHH:MM:SS]',
        callback=make_option_parser(datetime.datetime.fromisoformat),
    )
    OPTIONS = [
        click.option('--mount', metavar='[SRC]:[DST]', multiple=True,
                     callback=make_option_parser(Mount.parse), help='Alternate mount points.'),
        click.option('--exclude', metavar='[PATTERN]', multiple=True,
                     help='Glob-style pattern of files to exclude.'),
        click.option('--max-size', default='inf', metavar='[SIZE]', show_default=True,
                     callback=make_option_parser(parse_file_size, (ValueError, KeyError)),
                     help='Maximum file size.'),
        click.option('--type', default=['file', 'dir', 'sym'], multiple=True, show_default=True,
                     type=click.Choice(['file', 'dir', 'sym', 'lnk', 'chr', 'blk', 'fifo']),
                     help='File types to archive.'),
        click.option('--user', multiple=True, help='Users owning files to operate on.'),
        click.option('--group', multiple=True, help='Groups owning files to operate on.'),
        click.option('--permission', metavar='[ugo][+-][rwx]', multiple=True,
                     callback=make_option_parser(parse_permission),
                     help='Permission bit constraints.'),
        _datetime_option('--min-mtime', default=datetime.datetime.min.isoformat(),
                         show_default=True, help='Minimum modified time.'),
        _datetime_option('--max-mtime', default=datetime.datetime.max.isoformat(),
                         show_default=True, help='Maximum modified time.'),
    ]

    @classmethod
    def decorate(cls, fn):
        for option in cls.OPTIONS:
            fn = option(fn)
        return fn

    @classmethod
    def from_options(cls, **options) -> 'FileFilter':
        return cls(
            mounts=tuple(sorted(options['mount'], key=lambda mount: mount.src, reverse=True)),
            exclude_patterns=options['exclude'],
            max_size=options['max_size'],
            file_types=options['type'],
            users=frozenset(options['user']),
            groups=frozenset(options['group']),
            permissions=frozenset(sum(options['permission'], [])),
            min_mtime=options['min_mtime'],
            max_mtime=options['max_mtime'],
        )

    def get_mounted_path(self, path: Path) -> typing.Optional[Path]:
        for mount in self.mounts:
            try:
                suffix = path.relative_to(mount.src)
            except ValueError:
                continue
            else:
                return mount.dst.joinpath(suffix) if mount.dst else None
        return path

    def allow_name(self, info: tarfile.TarInfo) -> bool:
        path = ROOT.joinpath(info.name)
        return not any(path.match(pattern) for pattern in self.exclude_patterns)

    def allow_size(self, info: tarfile.TarInfo) -> bool:
        return info.size <= self.max_size

    def allow_type(self, info: tarfile.TarInfo) -> bool:
        return any(getattr(info, f'is{file_type}')() for file_type in self.file_types)

    def allow_ownership(self, info: tarfile.TarInfo) -> bool:
        return not self.users or info.uname in self.users \
            and not self.groups or info.gname in self.groups

    def allow_permissions(self, info: tarfile.TarInfo) -> bool:
        for owner, constraint, action in self.permissions:
            shift = 3*'ogu'.index(owner) + 'xwr'.index(action)
            if ((info.mode >> shift) & 1) != int(constraint == '+'):
                return False
        return True

    def allow_mtime(self, info: tarfile.TarInfo) -> bool:
        return self.min_mtime <= datetime.datetime.fromtimestamp(info.mtime) <= self.max_mtime

    def __call__(self, info: typing.Optional[tarfile.TarInfo]) -> bool:
        allow_checks = [self.allow_name, self.allow_size, self.allow_type,
                        self.allow_ownership, self.allow_permissions, self.allow_mtime]
        return info and all(allow(info) for allow in allow_checks)


def compute_hash(*sources: typing.Union[typing.ByteString, typing.BinaryIO],
                 hash_alg: str = 'sha256', buf_size: int = 10*KILOBYTE) -> str:
    hash_obj = getattr(hashlib, hash_alg)()
    for source in sources:
        if isinstance(source, typing.ByteString):
            hash_obj.update(source)
        else:
            buf = bytearray(buf_size)
            while source.readinto(buf):
                hash_obj.update(buf)
    return hash_obj.hexdigest()


T = typing.TypeVar('T')
PathLike = typing.Union[str, Path]

@dataclasses.dataclass
class FileTree(collections.abc.MutableMapping[PathLike, typing.Optional[T]]):
    """
    A nested dictionary that uses filesystem paths as keys.

    >>> tree = FileTree()
    >>> tree['a/b/c'] = 1
    >>> len(tree)
    4
    >>> tree['a/b/d'] = 2
    >>> tree['a/b'] is None
    True
    >>> sorted(tree) == [Path(), Path('a'), Path('a/b'), Path('a/b/c'), Path('a/b/d')]
    True
    >>> del tree['a/b']
    >>> sorted(tree) == [Path(), Path('a')]
    True
    """
    element: typing.Optional[T] = None
    children: dict[str, 'FileTree'] = dataclasses.field(default_factory=dict)

    @staticmethod
    def _make_path_relative(path: PathLike) -> Path:
        if isinstance(path, str):
            path = Path(path)
        return path.relative_to(ROOT) if path.is_absolute() else path

    @staticmethod
    def _split_path(path: Path) -> tuple[str, Path]:
        name, *rest = path.parts
        return name, Path().joinpath(*rest)

    def __getitem__(self, path: PathLike) -> T:
        path = self._make_path_relative(path)
        if not path.parts:
            return self.element
        name, path = self._split_path(path)
        return self.children[name][path]

    def __setitem__(self, path: PathLike, element: T):
        name, path = self._split_path(self._make_path_relative(path))
        if (child := self.children.get(name)) is None:
            child = self.children[name] = FileTree()
        if not path.parts:
            child.element = element
        else:
            child[path] = element

    def __delitem__(self, path: PathLike):
        name, path = self._split_path(self._make_path_relative(path))
        if not path.parts:
            del self.children[name]
        else:
            del self.children[name][path]

    def __len__(self) -> int:
        return 1 + sum(map(len, self.children.values()))

    def __iter__(self) -> typing.Iterable[Path]:
        yield Path()
        for name, child in sorted(self.children.items()):
            for descendent in child:
                yield name / descendent

    def to_dict(self, serialize=None):
        node = {'elem': serialize(self.element) if serialize else self.element}
        if self.children:
            node['children'] = {name: child.to_dict(serialize=serialize)
                                for name, child in self.children.items()}
        return node

    @classmethod
    def from_dict(cls, node, deserialize=None) -> 'BackupIncrement':
        element, children = node['elem'], node.get('children') or {}
        return cls(element=(deserialize(element) if deserialize else element),
                   children={name: cls.from_dict(child, deserialize=deserialize)
                             for name, child in children.items()})


@dataclasses.dataclass
class BackupIncrement:
    HASH_ALGORITHMS = ('sha256', 'sha384', 'sha512')
    COMPRESSION_OPTIONS = ('none', 'gz', 'bz2', 'xz')
    TIMESTAMP_FORMAT = '%Y-%m-%dT%H%M%S'
    METADATA_DIR_NAME = '.backup'

    hash_alg: str = HASH_ALGORITHMS[0]
    compression: str = COMPRESSION_OPTIONS[0]
    timestamp: datetime.datetime = \
        dataclasses.field(default_factory=datetime.datetime.utcnow)
    size: int = 0
    root: FileTree[typing.ByteString] = dataclasses.field(default_factory=FileTree)
    prev: typing.Optional['BackupIncrement'] = None

    def __post_init__(self):
        if self.compression == 'none':
            self.compression = ''

    def __iter__(self) -> typing.Iterable['BackupIncrement']:
        yield self
        if self.prev:
            yield from self.prev

    def __len__(self) -> int:
        return 1 + (0 if self.prev is None else len(self.prev))

    @property
    def fmt_timestamp(self) -> str:
        return self.timestamp.strftime(self.TIMESTAMP_FORMAT)

    @property
    def tar_filename(self) -> str:
        filename = f'{self.fmt_timestamp}-backup.tar'
        return filename + '.' + self.compression if self.compression else filename

    @property
    def metadata_filename(self) -> str:
        return f'{self.fmt_timestamp}-metadata.json'

    @property
    def signature(self) -> str:
        return compute_hash(*(f'{ROOT.joinpath(path)}:{digest}'.encode()
                              for path, digest in self.root.items() if digest))

    def scan(self, tar: tarfile.TarFile, file_filter: FileFilter, source: Path) \
            -> typing.Iterable[tuple[Path, tarfile.TarInfo]]:
        if mounted_path := file_filter.get_mounted_path(source):
            info = tar.gettarinfo(source, mounted_path)
            if file_filter(info):
                self.size += info.size
                yield source, info
                if source.is_dir():
                    for child in source.iterdir():
                        yield from self.scan(tar, file_filter, child)

    def scan_chain(self, tar: tarfile.TarFile, file_filter: FileFilter,
                   *sources: Path) -> list[tarfile.TarInfo]:
        scans = (self.scan(tar, file_filter, source) for source in filter_prefixes(sources))
        return list(itertools.chain(*scans))

    def get_last_hash(self, path: PathLike) -> typing.Optional[str]:
        if self.prev is not None:
            for increment in self.prev:
                if digest := increment.root.get(path):
                    return digest

    def add(self, tar: tarfile.TarFile, path: Path, info: tarfile.TarInfo):
        last_hash = self.get_last_hash(path)
        cm = open(path, 'rb') if path.is_file() else contextlib.nullcontext()
        with cm as handle:
            buf = [handle] if handle else []
            digest = compute_hash(info.tobuf(), *buf, hash_alg=self.hash_alg)
            if digest != self.get_last_hash(info.name):
                if handle:
                    handle.seek(0)  # File cache should be warmed up.
                    tar.addfile(info, handle)
                else:
                    tar.addfile(info)
        self.root[info.name] = digest


@dataclasses.dataclass
class Backup:
    """
    A backup storage layer for reading and writing metadata and TARs.
    """
    path: Path
    stack: contextlib.ExitStack = dataclasses.field(default_factory=contextlib.ExitStack)
    tars: dict[str, tarfile.TarFile] = dataclasses.field(default_factory=dict)
    last: typing.Optional[BackupIncrement] = None

    @property
    def _metadata_path(self) -> Path:
        return self.path / '.backup'

    def read_metadata(self, filename: str) -> BackupIncrement:
        with open(self._metadata_path / filename) as metadata_file:
            metadata = json.load(metadata_file)
        return BackupIncrement(
            hash_alg=metadata['hash_alg'],
            compression=metadata['compression'],
            timestamp=datetime.datetime.fromisoformat(metadata['timestamp']),
            size=metadata['size'],
            root=FileTree.from_dict(metadata['root']),
        )

    def write_metadata(self, filename: str, increment: BackupIncrement):
        with open(self._metadata_path / filename, 'w+') as metadata_file:
            metadata = {
                'hash_alg': increment.hash_alg,
                'compression': increment.compression,
                'timestamp': increment.timestamp.isoformat(),
                'size': increment.size,
                'root': increment.root.to_dict(),
            }
            json.dump(metadata, metadata_file, separators=(',', ':'))

    def push(self, increment: BackupIncrement) -> BackupIncrement:
        """ Push a new backup increment into the history. """
        self.last, increment.prev = increment, self.last
        return increment

    def __enter__(self):
        self._metadata_path.mkdir(parents=True, exist_ok=True)
        increments = [self.read_metadata(path.name) for path in self._metadata_path.iterdir()]
        for increment in sorted(increments, key=lambda increment: increment.timestamp):
            self.push(increment)
        self.stack = self.stack.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.stack.__exit__(exc_type, exc, tb)
        self.last = None
        if exc_type:
            for filename, tar in self.tars.items():
                if tar.mode.startswith('w'):
                    (self.path / filename).unlink(missing_ok=True)
        return exc_type is AbortException

    def get_tar(self, increment: BackupIncrement, mode: str) -> tarfile.TarFile:
        tar = self.tars.get(filename := increment.tar_filename)
        if not tar:
            tar = tarfile.open(str(self.path / filename), mode)
            tar = self.tars[filename] = self.stack.enter_context(tar)
        return tar

    def get_increment(self, signature: bytes) -> typing.Optional[BackupIncrement]:
        if signature and self.last is not None:
            for increment in self.last:
                if increment.signature == signature:
                    return increment
        else:
            return self.last

    def find_tar(self, path: Path, last: typing.Optional[BackupIncrement] = None) \
            -> typing.Optional[tuple[tarfile.TarInfo, tarfile.TarInfo]]:
        if last is None:
            last = self.last
        for increment in last:
            tar = self.get_tar(increment, 'r:*')
            with contextlib.suppress(KeyError):
                return tar.getmember(str(path))

    def extract(self, last: BackupIncrement, file_filter: FileFilter, path: Path) -> int:
        for increment in last:
            tar = self.get_tar(increment, 'r:*')
            try:
                info = tar.getmember(str(path))
            except KeyError:
                continue
            path = ROOT.joinpath(path)
            if not (mounted_path := file_filter.get_mounted_path(path)) or not file_filter(info):
                return info.size
            mounted_path, info.name = mounted_path.parent, mounted_path.name
            tar.extract(info, mounted_path)
            return info.size
        raise ValueError('File not found')


def filter_prefixes(sources: typing.Iterable[Path]) -> typing.Iterable[Path]:
    """
    Filter a list of paths such that no path is a prefix of any other.

    Returns:
        The filtered paths in sorted order, coerced as absolute paths.
    """
    if not (sources := sorted(source.absolute() for source in sources)):
        return
    yield (current_path := sources[0])
    for next_path in sources[1:]:
        if not next_path.is_relative_to(current_path):
            yield (current_path := next_path)


@click.group(context_settings=dict(max_content_width=100))
@click.option('--archive', default=str(Path.cwd()), callback=make_option_parser(Path),
              type=click.Path(file_okay=False, exists=True),
              help='Directory to write the backups to.')
@click.option('--confirm/--no-confirm', default=True,
              help='Toggle confirmation of critical tasks.')
@click.option('--dry-run', is_flag=True, help='Do not persist changes.')
@click.version_option(version='1.0.0', message='v%(version)s')
@click.pass_context
def cli(ctx, **options):
    """
    Manage incremental compressed backups.

    This tool stores each backup as a pair of files: a metadata file (JSON) and
    a possibly compressed tar. The metadata records a hash of each backed-up
    file's attributes and contents. The tar only contains backed-up files that
    have been added or modified since the last backup, reducing the time and
    space needed to back up largely unmodified file trees.
    """
    ctx.ensure_object(dict)
    ctx.obj.update(options)
    if not options['confirm']:
        click.confirm = lambda *args, **kwargs: True


# TODO: consider encryption/signing archives.
@cli.command()
@click.option('--compression', default=BackupIncrement.COMPRESSION_OPTIONS[0],
              show_default=True, type=click.Choice(BackupIncrement.COMPRESSION_OPTIONS),
              help='Archive compression method.')
@click.option('--hash-alg', default=BackupIncrement.HASH_ALGORITHMS[0],
              show_default=True, type=click.Choice(BackupIncrement.HASH_ALGORITHMS),
              help='Hashing algorithm for checking file equality.')
@FileFilter.decorate
@click.argument('source', nargs=-1, type=click.Path(exists=True),
                callback=make_option_parser(Path))
@click.pass_context
def create(ctx, **options):
    """
    Create a backup.
    """
    with Backup(ctx.obj['archive']) as backup:
        increment = backup.push(BackupIncrement(options['hash_alg'], options['compression']))
        tar = backup.get_tar(increment, 'w|' + increment.compression)
        file_filter = FileFilter.from_options(**options)
        infos = increment.scan_chain(tar, file_filter, *options['source'])
        click.secho(f'Scanned {len(infos)} files ({format_file_size(increment.size)}).',
                    fg='cyan', bold=True)
        click.echo(f'Ready to write archive to {increment.tar_filename!r}.')
        if not click.confirm('Commit to disk?'):
            raise AbortException

        with FileProgressBar(increment.size) as bar:
            for path, info in infos:
                increment.add(tar, path, info)
                bar.update(Path(info.name).name, info.size)
        signature = increment.signature
        if increment.prev and increment.prev.signature == signature:
            click.secho('No modified files to archive.', fg='yellow', bold=True)
            raise AbortException
        backup.write_metadata(increment.metadata_filename, increment)
        click.echo(f'Wrote metadata to {increment.metadata_filename!r}.')
        click.secho(f'Backup created (signature: {signature}).', fg='green', bold=True)


@cli.command()
@FileFilter.decorate
@click.argument('hash', required=False)
@click.pass_context
def restore(ctx, **options):
    """
    Restore a backup.
    """
    with Backup(ctx.obj['archive']) as backup:
        if not (increment := backup.get_increment(signature := options['hash'])):
            if signature:
                message = f'No backup found with signature: {signature!r}.'
            else:
                message = 'No backups available.'
            click.secho(message, fg='red', bold=True)
            return
        file_filter = FileFilter.from_options(**options)
        with FileProgressBar(increment.size) as bar:
            paths = list(filter(increment.root.get, increment.root))
            for path in reversed(paths):
                size = backup.extract(increment, file_filter, path)
                bar.update(path.name, size)


@cli.command('list')
@click.pass_context
def list_backups(ctx):
    """ List available backups. """
    with Backup(ctx.obj['archive']) as backup:
        if backup.last is not None:
            click.secho('Backups:', bold=True)
            for increment in backup.last:
                columns = [increment.fmt_timestamp, increment.hash_alg,
                           increment.compression, increment.signature,
                           format_file_size(increment.size)]
                click.echo(f'  {" ".join(columns)}')
        else:
            click.secho('No backups found.', fg='yellow', bold=True)


@cli.command()
@click.argument('hash', required=False)
@click.pass_context
def remove(ctx):
    """ Remove and merge a backup. """


if __name__ == '__main__':
    cli()
