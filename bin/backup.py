#!/usr/bin/env python3

"""
backup -- A script for creating incremental compressed backups.
"""

import collections.abc
import contextlib
import dataclasses
import datetime
import functools
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import string
import random
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


_secho = click.secho
@functools.wraps(_secho)
def secho(msg: str, /, *args, prefix: str = '=> ', **kwargs):
    if kwargs.get('fg') and kwargs.get('bold'):
        msg = prefix + msg
    return _secho(msg, *args, **kwargs)
click.secho = secho


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


def random_str(alphabet: str = string.ascii_letters, size: int = 8) -> str:
    return ''.join(random.choice(alphabet) for _ in range(size))


def make_relative(path: Path) -> Path:
    return path.relative_to(ROOT) if path.is_absolute() else path


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


@contextlib.contextmanager
def replace_rollback(path: Path):
    """ A context manager for possibly replacing a path. """
    targets = [parent for parent in [path] + list(path.parents) if not parent.exists()]
    backup_path = path.with_name(f'.backup-{random_str()}-{path.name}')
    assert not backup_path.exists()
    try:
        if path.exists() and not path.is_dir():
            path.rename(backup_path)
        yield
    except:
        for target in filter(Path.exists, targets):
            with contextlib.suppress(PermissionError):
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=True)
        if backup_path.exists():
            backup_path.rename(path)
        raise
    else:
        backup_path.unlink(missing_ok=True)


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
    FILE_TYPES = ['file', 'dir', 'sym', 'lnk', 'chr', 'blk', 'fifo']
    OPTIONS = [
        click.option('--mount', metavar='[SRC]:[DST]', multiple=True,
                     callback=make_option_parser(Mount.parse), help='Alternate mount points.'),
        click.option('--exclude', metavar='[PATTERN]', multiple=True,
                     help='Glob-style pattern of files to exclude.'),
        click.option('--max-size', default='inf', metavar='[SIZE]', show_default=True,
                     callback=make_option_parser(parse_file_size, (ValueError, KeyError)),
                     help='Maximum file size.'),
        click.option('--type', default=['file', 'dir', 'sym'], multiple=True, show_default=True,
                     type=click.Choice(FILE_TYPES), help='File types to archive.'),
        click.option('--user', multiple=True, help='Users owning files to operate on.'),
        click.option('--group', multiple=True, help='Groups owning files to operate on.'),
        click.option('--permission', metavar='[ugo][+-][rwx]', multiple=True,
                     callback=make_option_parser(parse_permission),
                     help='Permission constraints.'),
        _datetime_option('--min-mtime', default=datetime.datetime.min.isoformat(),
                         show_default=True, help='Minimum modified time.'),
        _datetime_option('--max-mtime', default=datetime.datetime.max.isoformat(),
                         show_default=True, help='Maximum modified time.'),
    ]

    @classmethod
    def get_file_type(cls, info: tarfile.TarInfo) -> str:
        for file_type in cls.FILE_TYPES:
            if getattr(info, 'is' + file_type)():
                return file_type
        return '?'

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
        return self.get_file_type(info) in self.file_types

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
    def _split_path(path: Path) -> tuple[str, Path]:
        """ Split a path into the next name and rest of the path. """
        name, *rest = path.parts
        return name, Path().joinpath(*rest)

    def __getitem__(self, path: PathLike) -> T:
        path = make_relative(Path(path))
        if not path.parts:
            return self.element
        name, path = self._split_path(path)
        return self.children[name][path]

    def __setitem__(self, path: PathLike, element: T):
        name, path = self._split_path(make_relative(Path(path)))
        if (child := self.children.get(name)) is None:
            child = self.children[name] = FileTree()
        if not path.parts:
            child.element = element
        else:
            child[path] = element

    def __delitem__(self, path: PathLike):
        name, path = self._split_path(make_relative(Path(path)))
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
        """ Convert this tree into a nested dictionary. """
        node = {'elem': serialize(self.element) if serialize else self.element}
        if self.children:
            node['children'] = {name: child.to_dict(serialize=serialize)
                                for name, child in self.children.items()}
        return node

    @classmethod
    def from_dict(cls, node, deserialize=None) -> 'FileTree':
        """ Convert a nested dictionary into a tree. """
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

    def signature(self) -> str:
        return compute_hash(*(f'{path}:{digest}'.encode()
                              for path, digest in self.root.items() if digest))

    def get_last_hash(self, path: PathLike) -> typing.Optional[str]:
        if self.prev is not None:
            for increment in self.prev:
                if digest := increment.root.get(path):
                    return digest

    def add(self, info: tarfile.TarInfo, path: Path, tar: typing.Optional[tarfile.TarFile] = None) -> bool:
        cm = path.open('rb') if path.is_file() else contextlib.nullcontext()
        with cm as handle:
            buf = [handle] if handle else []
            digest = compute_hash(info.tobuf(), *buf, hash_alg=self.hash_alg)
            modified = digest != self.get_last_hash(info.name)
            if tar and modified:
                if handle:
                    handle.seek(0)  # File cache should be warmed up.
                    tar.addfile(info, handle)
                else:
                    tar.addfile(info)
        self.root[info.name] = digest
        return modified

    def extract(self, tar: tarfile.TarFile, info: tarfile.TarInfo, path: Path):
        info.name = path.name
        tar.extract(info, path=path.parent)


ScanResult = typing.Iterable[tuple[tarfile.TarFile, tarfile.TarInfo, Path]]


@dataclasses.dataclass
class Backup:
    path: Path
    file_filter: FileFilter = dataclasses.field(
        default_factory=functools.partial(FileFilter, file_types={'file', 'dir', 'sym'}))
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
        return exc_type is AbortException

    @contextlib.contextmanager
    def open_tar(self, filename: str, mode: str) -> tarfile.TarFile:
        """ Open a tar file that is unlinked if an exception occurs while writing. """
        path = self.path / filename
        try:
            with tarfile.open(str(path), mode) as tar:
                yield tar
        except:
            if mode.startswith('w'):
                path.unlink(missing_ok=True)
            raise

    def get_tar(self, filename: str, mode: str) -> tarfile.TarFile:
        tar = self.tars.get((filename, mode))
        if not tar:
            tar = self.open_tar(filename, mode)
            tar = self.tars[filename, mode] = self.stack.enter_context(tar)
        return tar

    def get_increment(self, signature: bytes) -> typing.Optional[BackupIncrement]:
        if signature and self.last is not None:
            for increment in self.last:
                if increment.signature() == signature:
                    return increment
        else:
            return self.last

    def _scan_archive(self, increment: BackupIncrement,
                      path: Path) -> tuple[tarfile.TarFile, tarfile.TarInfo]:
        name = str(make_relative(path))
        for current in increment:
            tar = self.get_tar(current.tar_filename, 'r:*')
            with contextlib.suppress(KeyError):
                return tar, tar.getmember(name)
        raise ValueError(name)

    def scan_archive(self, increment: BackupIncrement) -> ScanResult:
        paths = list(map(ROOT.joinpath, filter(increment.root.get, increment.root)))
        for path in reversed(paths):
            tar, info = self._scan_archive(increment, path)
            if (real_path := self.file_filter.get_mounted_path(path)) and self.file_filter(info):
                yield tar, info, real_path

    def _scan_filesystem(self, tar: tarfile.TarFile,
                         path: Path) -> typing.Iterable[tuple[tarfile.TarInfo, Path]]:
        if real_path := self.file_filter.get_mounted_path(path):
            info = tar.gettarinfo(path, real_path)
            if self.file_filter(info):
                yield info, path
                # FIXME: circular links
                if path.is_dir():
                    for child in path.iterdir():
                        yield from self._scan_filesystem(tar, child)

    def scan_filesystem(self, increment: BackupIncrement, *paths: Path) -> ScanResult:
        tar = self.get_tar(increment.tar_filename, 'w|' + increment.compression)
        for path in filter_prefixes(paths):
            for info, real_path in self._scan_filesystem(tar, path):
                increment.size += info.size
                yield tar, info, real_path


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


def render_dry_run(scan: ScanResult, modify_columns=None, indent: int = 2):
    click.echo()
    colors = {'file': 'cyan', 'dir': 'blue', 'sym': 'magenta', 'lnk': 'yellow',
              'chr': 'red', 'blk': 'red', 'fifo': 'yellow'}
    for _, info, path in scan:
        file_type = FileFilter.get_file_type(info)
        fg = colors.get(file_type, 'white')
        columns = [datetime.datetime.fromtimestamp(int(info.mtime)).isoformat(),
                   click.style(f'[{file_type.rjust(4)}]', fg=fg, bold=True),
                   oct(info.mode)[-3:], f'{info.uname}:{info.gname}', str(path)]
        if modify_columns:
            modify_columns(info, path, columns)
        click.echo(' '*indent + ' '.join(columns))
    click.echo()


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
    with Backup(ctx.obj['archive'], FileFilter.from_options(**options)) as backup:
        increment = backup.push(BackupIncrement(options['hash_alg'], options['compression']))
        scan = list(backup.scan_filesystem(increment, *options['source']))
        click.secho(f'Ready to add {len(scan)} files ({format_file_size(increment.size)}) '
                    f'to {increment.tar_filename!r}.', fg='cyan', bold=True)
        if ctx.obj['dry_run']:
            def add_status(info: tarfile.TarInfo, path: Path, columns: list[str]):
                if increment.add(info, path, tar=None):
                    status = click.style('[added]'.rjust(11), fg='green', bold=True)
                else:
                    status = click.style('[no change]', fg='blue', bold=True)
                columns.insert(0, status)
            render_dry_run(scan, modify_columns=add_status)
            raise AbortException
        else:
            if not click.confirm('Commit to disk?'):
                raise AbortException
            with FileProgressBar(increment.size) as bar:
                for tar, info, path in scan:
                    bar.update(path.name, info.size)
                    increment.add(info, path, tar=tar)
            signature = increment.signature()
            if increment.prev and increment.prev.signature() == signature:
                click.secho('No modified files to archive.', fg='yellow', bold=True)
                raise AbortException
            backup.write_metadata(increment.metadata_filename, increment)
            click.secho(f'Backup created (signature: {signature}).', fg='green', bold=True)


# TODO: More robust checks (permissions, files that exist, etc)
@cli.command()
@click.option('--rollback/--no-rollback', default=True, help='')
@click.option('--overwrite/--no-overwrite', default=True, help='')
@FileFilter.decorate
@click.argument('hash', required=False)
@click.pass_context
def restore(ctx, **options):
    """
    Restore a backup.
    """
    with Backup(ctx.obj['archive'], FileFilter.from_options(**options)) as backup:
        if not (increment := backup.get_increment(signature := options['hash'])):
            if signature:
                message = f'No backup found with signature: {signature!r}.'
            else:
                message = 'No backups available.'
            click.secho(message, fg='red', bold=True)
            return
        scan = list(backup.scan_archive(increment))
        size = sum(info.size for _, info, _ in scan)
        click.secho(f'Ready to extract {len(scan)} files ({format_file_size(size)}).',
                    fg='cyan', bold=True)
        if ctx.obj['dry_run']:
            render_dry_run(scan)
        else:
            if not click.confirm('Commit to disk?'):
                raise AbortException
            with FileProgressBar(size) as bar:
                for tar, info, path in scan:
                    bar.update(path.name, info.size)
                    if options['rollback']:
                        backup.stack.enter_context(replace_rollback(path))
                    increment.extract(tar, info, path)


@cli.command('list')
@click.pass_context
def list_backups(ctx):
    """ List available backups. """
    with Backup(ctx.obj['archive']) as backup:
        if backup.last is not None:
            click.secho('Backups:', bold=True)
            for increment in backup.last:
                columns = [increment.timestamp.isoformat(), increment.hash_alg,
                           increment.compression, format_file_size(increment.size),
                           click.style(increment.signature(), fg='blue', bold=True)]
                click.echo(f'  {" ".join(columns)}')
        else:
            click.secho('No backups found.', fg='yellow', bold=True)


@cli.command()
@click.argument('hash', required=False)
@click.pass_context
def remove(ctx):
    """ Remove and merge a backup. """
    with Backup(ctx.obj['archive']) as backup:
        pass


if __name__ == '__main__':
    cli()
