#!/usr/bin/env python3

import collections.abc
import contextlib
import dataclasses
import datetime
import functools
import hashlib
import io
import itertools
import json
import operator
import pathlib
import queue
import tarfile
import typing
import re

import click


KIBIBYTE, MEBIBYTE, GIBIBYTE = 2**10, 2**20, 2**30
as_path = lambda _ctx, path: pathlib.Path(path)


def humanize_file_size(byte_count: int, rounding: int = 1) -> str:
    prefixes = ['', 'Ki', 'Mi', 'Gi']
    sizes = [1, KIBIBYTE, MEBIBYTE, GIBIBYTE, float('inf')]
    for prefix, divisor, limit in zip(prefixes, sizes[:-1], sizes[1:]):
        if byte_count < limit:
            value = byte_count if divisor == 1 else round(byte_count/divisor, rounding)
            return f'{value} {prefix}B'


class AbortException(Exception):
    pass


@dataclasses.dataclass
class ProgressBar:
    total_bytes: int
    width: int = 40
    fill_char: str = '#'
    empty_char: str = '.'
    slow_rate: float = 8*MEBIBYTE  # About 0.533 GiB/min
    medium_rate: float = 16*MEBIBYTE  # About 1.067 GiB/min
    bytes_processed: int = dataclasses.field(default=0, init=False, repr=False)
    time_started: datetime.datetime = dataclasses.field(default=datetime.datetime.min, init=False, repr=False)
    last_update: datetime.datetime = dataclasses.field(default=datetime.datetime.min, init=False, repr=False)
    current_rate: float = dataclasses.field(default=0, init=False, repr=False)

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

    @property
    def duration(self) -> datetime.timedelta:
        return self.last_update - self.time_started

    def update_rate(self, info, default: float = KIBIBYTE) -> float:
        """ Computes the archive rate in bytes per second. """
        now = datetime.datetime.now()
        delta, self.last_update = now - self.last_update, now
        if info.size:
            new_rate = info.size/delta.total_seconds()
            self.current_rate = (1 - self.RATE_DECAY)*new_rate + self.RATE_DECAY*self.current_rate
        return self.current_rate

    def format_rate(self, rate: float) -> str:
        if rate < self.slow_rate:
            fg = 'red'
        elif rate < self.medium_rate:
            fg = 'yellow'
        else:
            fg = 'green'
        return click.style(humanize_file_size(rate) + '/s', fg=fg, bold=True)

    @property
    def eta(self) -> datetime.timedelta:
        if self.bytes_processed == 0:
            return datetime.timedelta.max
        long_term_rate = self.bytes_processed/(self.last_update - self.time_started).total_seconds()
        return datetime.timedelta(seconds=(self.total_bytes - self.bytes_processed)/long_term_rate)

    def format_duration(self, duration: datetime.timedelta) -> str:
        if duration == datetime.timedelta.max:
            return ':'.join(3*['--'])
        seconds = int(duration.total_seconds())
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
        filename = click.style(pathlib.Path(info.name).name, fg='cyan', bold=True)
        if info.size > 0:
            filename += f' ({humanize_file_size(info.size)})'
        click.echo(' | '.join([
            f'[{full}{empty}] {percentage}',
            f'Runtime: {self.format_duration(self.duration)}, '
            f'ETA: {self.format_duration(self.eta)}, Rate: {self.format_rate(rate)}',
            filename,
        ]) + '\r', nl=False)


Exclude = typing.Callable[[pathlib.Path, tarfile.TarInfo], bool]


@dataclasses.dataclass(frozen=True)
class FileHashTree(collections.abc.Mapping[pathlib.Path, 'FileHashTree']):
    """
    A recursive data structure containing file metadata and hashes to detect changes.

    The hash digest at a node is dependent on the Tar info buffer, the file
    contents (if the node is a regular file), and the digests of all the node's
    children (if the node is a directory). The childrens' digests are ordered
    by name to ensure the preimage is well-defined.

    Attributes:
        digest: The hash value. May be empty for non-archived files.
        children: Maps names to child files. Only nonempty for directories.
        info: An optional `tarfile.TarInfo` containing metadata written to a
            Tar file. May be missing because the node represents a directory
            not being archived, or because the tree is deserialized. Because
            the Tar info is used to compute the digest, this field is not used
            for comparison.
    """
    info: typing.Optional[tarfile.TarInfo] = \
        dataclasses.field(default=None, repr=False, compare=False)
    children: dict[str, 'FileHashTree'] = dataclasses.field(default_factory=dict)
    digest: bytes = b''

    ROOT: typing.ClassVar[pathlib.Path] = pathlib.Path('/')

    @classmethod
    def _normalize_path(cls, path: typing.Union[str, pathlib.Path]) -> pathlib.Path:
        if isinstance(path, str):
            path = pathlib.Path(path)
        return path.relative_to(cls.ROOT) if path.is_absolute() else path

    @staticmethod
    def _digest(source: typing.Union[bytes, bytearray, io.FileIO],
                chunk_size: int = 10*KIBIBYTE, hash_alg: str = 'sha256') -> bytes:
        make_hash = getattr(hashlib, hash_alg)
        if isinstance(source, (bytes, bytearray)):
            hash_obj = make_hash(source)
        else:
            hash_obj, buf = make_hash(), bytearray(chunk_size)
            while source.readinto(buf):
                hash_obj.update(buf)
        return hash_obj.digest()

    def __getitem__(self, path: typing.Union[str, pathlib.Path]) -> 'FileHashTree':
        path = self._normalize_path(path)
        if not path.parts:
            return self
        name, *remainder = path.parts
        return self.children[name][pathlib.Path().joinpath(*remainder)]

    def __iter__(self):
        yield self
        for part, child in sorted(self.children.items()):
            yield from child

    def __len__(self) -> int:
        return bool(self.info) + sum(map(len, self.children.values()))

    def flatten(self, cwd: pathlib.Path = ROOT) -> typing.Mapping[pathlib.Path, 'FileHashTree']:
        path_table = {cwd: self}
        for part, child in sorted(self.children.items()):
            path_table.update(child.flatten(cwd=cwd.joinpath(part)))
        return path_table

    @classmethod
    def scan(cls, tar: tarfile.TarFile, path: pathlib.Path,
             base: typing.Optional[pathlib.Path] = None,
             exclude: typing.Optional[Exclude] = None) -> typing.Optional['FileHashTree']:
        base = base or path
        with contextlib.suppress(PermissionError):
            if not path.exists() or not (info := tar.gettarinfo(path)):
                return
            if exclude and exclude(path, info):
                return
            node = FileHashTree(info)
            if path.is_dir():
                for child_path in path.iterdir():
                    if child := FileHashTree.scan(tar, child_path, base=base, exclude=exclude):
                        node.children[child_path.name] = child
            if base == path:
                for part in reversed(base.relative_to(cls.ROOT).parts):
                    node = FileHashTree(children={part: node})
            return node

    @property
    def size(self):
        size = self.info.size if self.info else 0
        return size + sum(child.size for child in self.children.values())

    def with_digests(self, path: pathlib.Path = ROOT, hook=None,
                     hash_alg: str = 'sha256', sep: bytes = b'|') -> 'FileHashTree':
        children = {part: child.with_digests(path.joinpath(part), hook, hash_alg, sep)
                    for part, child in sorted(self.children.items())}
        make_digest = functools.partial(self._digest, hash_alg=hash_alg)
        if self.info:
            info_digest = digest(self.info.tobuf())
            if self.info.isfile():
                with open(path, 'rb') as file_handle:
                    content_digest = digest(file_handle)
                    # File cache has been warmed up, so re-reading should not be too slow.
                    if hook:
                        file_handle.seek(0)
                        hook(self.info, file_handle)
            elif hook:
                hook(self.info)
                content_digest = b''
            parts = [info_digest, content_digest] + [child.digest for child in children.values()]
            digest = make_digest(sep.join(parts))
        else:
            digest = b''
        return FileHashTree(self.info, children, digest)

    def __or__(self, other: typing.Optional['FileHashTree']) -> 'FileHashTree':
        """
        Merge two trees. The latest (right) operand takes precedence.

        Some nodes may have blank digests because of new info/children combinations.
        """
        if not other:
            return self
        children = {part: (self.children.get(part) | other.children.get(part))
                    for part in set(self.children) | set(other.children)}
        return FileHashTree(other.info or self.info, children)

    __ror__ = __or__

    def __sub__(self, other: typing.Optional['FileHashTree']) -> typing.Optional['FileHashTree']:
        if other is None:
            return self
        if self.digest != other.digest:
            children = {part: diff for part, child in self.children.items()
                        if (diff := child - other.children.get(part)) is not None}
            return FileHashTree(self.info, children, self.digest)

    def to_dict(self) -> dict:
        node = {}
        if digest := self.digest.hex():
            node['digest'] = digest
        if children := {part: child.to_dict() for part, child in self.children.items()}:
            node['children'] = children
        return node

    @classmethod
    def from_dict(cls, data) -> 'FileHashTree':
        children = data.get('children') or {}
        return FileHashTree(
            children={part: cls.from_dict(child) for part, child in children.items()},
            digest=bytes.fromhex(data.get('digest', '')),
        )


@dataclasses.dataclass
class Backup:
    DEFAULT_EXCLUDE = [
        r'^__pycache__$',                               # Python
        r'\.pyc$',                                      # Python cache
        r'^\.?(v|virtual|)envs?$',                      # Python virtual environments
        r'^node_modules$',                              # NodeJS
        r'^\.cache',                                    # Caches
        r'^\.vagrant$',                                 # Vagrant
        r'\.(aux|lof|fls|fdb_latexmk|pdfsync|toc)$',    # TeX
        r'\.synctex(\.gz)?(\(busy\))?$',                # SyncTeX
        r'^\.DS_Store$',                                # macOS
    ]
    HASH_ALGORITHMS = ('sha256', 'sha384', 'sha512')
    COMPRESSION_OPTIONS = ('none', 'gz', 'bz2', 'xz')
    TIMESTAMP_FORMAT = '%Y-%m-%dT%H%M%S'

    hash_alg: str = HASH_ALGORITHMS[0]
    compression: str = COMPRESSION_OPTIONS[0]
    exclude: typing.Sequence[re.Pattern] = \
        dataclasses.field(default_factory=functools.partial(list, DEFAULT_EXCLUDE))
    file_types: set[str] = dataclasses.field(default_factory=set)
    timestamp: datetime.datetime = dataclasses.field(
        default_factory=lambda: datetime.datetime.utcnow().replace(microsecond=0))
    root: FileHashTree = dataclasses.field(default_factory=FileHashTree)

    def __post_init__(self):
        self.file_types.update({'file', 'dir'})
        if self.compression == 'none':
            self.compression = ''

    def should_exclude(self, path: pathlib.Path, info: tarfile.TarInfo) -> bool:
        if any(pattern.search(path.name) for pattern in self.exclude):
            return True
        return not any(getattr(info, f'is{file_type}')() for file_type in self.file_types)

    @functools.cached_property
    def fmt_timestamp(self) -> str:
        return self.timestamp.strftime(self.TIMESTAMP_FORMAT)

    def to_dict(self) -> dict:
        return {
            'hash_alg': self.hash_alg,
            'compression': self.compression,
            'exclude': [pattern.pattern for pattern in self.exclude],
            'file_types': sorted(self.file_types),
            'timestamp': self.fmt_timestamp,
            'root': self.root.to_dict(),
        }

    @classmethod
    def from_dict(cls, data) -> 'Backup':
        fields = {field: value for field in ('hash_alg', 'compression') if (value := data.get(field))}
        if (exclude := data.get('exclude')) is not None:
            fields['exclude'] = tuple(map(re.compile, exclude))
        if (file_types := data.get('file_types')) is not None:
            fields['file_types'] = set(file_types)
        if root := data.get('root'):
            fields['root'] = FileHashTree.from_dict(root)
        if timestamp := data.get('timestamp'):
            fields['timestamp'] = datetime.datetime.strptime(timestamp, cls.TIMESTAMP_FORMAT)
        return Backup(**fields)

    def scan(self, tar: tarfile.TarFile, sources: typing.Sequence[pathlib.Path]):
        trees = (FileHashTree.scan(tar, source, exclude=self.should_exclude)
                 for source in filter_prefixes(sources))
        self.root = functools.reduce(operator.or_, trees, self.root)

    def digest(self, *args, **kwargs):
        self.root = self.root.with_digests(*args, hash_alg=self.hash_alg, **kwargs)

    @functools.cached_property
    def tar_filename(self) -> str:
        filename = f'{self.fmt_timestamp}-backup.tar'
        return filename + '.' + self.compression if self.compression else filename

    @functools.cached_property
    def metadata_filename(self) -> str:
        return f'{self.fmt_timestamp}-metadata.json'


@dataclasses.dataclass(frozen=True)
class Archive:
    path: pathlib.Path
    metadata: list[Backup] = dataclasses.field(default_factory=list, init=False, repr=False)

    METADATA_DIR_NAME = '.backup'

    @functools.cached_property
    def _metadata_path(self) -> pathlib.Path:
        return self.path / self.METADATA_DIR_NAME

    @property
    def last_backup(self) -> typing.Optional[Backup]:
        if self.metadata:
            return self.metadata[-1]

    def read_metadata(self, path: pathlib.Path):
        with open(path) as metadata_file:
            backup = Backup.from_dict(json.load(metadata_file))
            if backup.root.digest:
                self.metadata.append(backup)

    def write_metadata(self, backup: Backup):
        with open(self._metadata_path / backup.metadata_filename, 'w+') as metadata_file:
            json.dump(backup.to_dict(), metadata_file, separators=(',', ':'))

    def __enter__(self):
        self._metadata_path.mkdir(parents=True, exist_ok=True)
        for path in sorted(self._metadata_path.iterdir()):
            self.read_metadata(path)
        self.metadata.sort(key = lambda backup: backup.timestamp)
        return self

    def __exit__(self, _exc, _exc_type, _tb):
        self.metadata.clear()

    @contextlib.contextmanager
    def open_tar(self, filename: str, mode: str):
        path = self.path / filename
        try:
            with tarfile.open(path, mode) as tar:
                yield tar
        except AbortException:
            if mode.startswith('w'):
                path.unlink(missing_ok=True)

    @staticmethod
    def bar_update_hook(bar: ProgressBar, info: tarfile.TarInfo,
                        _file_handle: typing.Optional[io.FileIO] = None):
        if info.size > 0:
            bar.update(info)

    def add_files(self, tar: tarfile.TarFile, diff: FileHashTree,
                  bar: typing.Optional[ProgressBar] = None):
        for node in diff:
            if node.info:
                path = FileHashTree.ROOT.joinpath(node.info.name)
                if node.info.isfile():
                    with open(path, 'rb') as file_handle:
                        tar.addfile(node.info, file_handle)
                else:
                    tar.addfile(node.info)
                if bar and node.info.size > 0:
                    bar.update(node.info)

    def find_backup(self, digest: bytes) -> typing.Optional[Backup]:
        for backup in reversed(self.metadata):
            if backup.root.digest == digest:
                return backup

    def partition(self, backup: Backup) -> typing.Mapping[bytes, typing.Set[pathlib.Path]]:
        targets, partitions = backup.root.flatten(), collections.defaultdict(set)
        sentinel = FileHashTree()
        for base, current in list(zip([None] + self.metadata[:-1], self.metadata))[::-1]:
            if (diff := current.root - (base.root if base else None)) is not None:
                for path, node in diff.flatten().items():
                    if any(path in paths for paths in partitions.values()):
                        continue
                    if node.digest == targets.get(path, sentinel).digest:
                        partitions[current.root.digest].add(path)
                        del targets[path]
        if targets:
            raise ValueError('Not all files found in backups')
        return partitions


def filter_prefixes(sources: typing.Iterable[pathlib.Path]) \
        -> typing.Iterable[pathlib.Path]:
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


@click.group(context_settings={'max_content_width': 120})
@click.option('--archive', default=str(pathlib.Path.cwd()), callback=as_path,
              type=click.Path(file_okay=False, exists=True),
              help='Directory the backups and metadata are written to.')
@click.option('--confirm/--no-confirm', default=True,
              help='Toggle confirmation prompts of critical tasks.')
@click.version_option(version='0.0.1', message='v%(version)s')
@click.pass_context
def cli(ctx, **options):
    """
    Create incremental compressed backups.
    """
    ctx.ensure_object(dict)
    ctx.obj.update(options)
    if not options['confirm']:
        click.confirm = lambda *args, **kwargs: True


# TODO: consider encryption/signing archives.
@cli.command()
@click.option('--compression', default=Backup.COMPRESSION_OPTIONS[0], show_default=True,
              type=click.Choice(Backup.COMPRESSION_OPTIONS), help='Compression method.')
@click.option('--hash-alg', default=Backup.HASH_ALGORITHMS[0],
              type=click.Choice(Backup.HASH_ALGORITHMS),
              help='Hashing algorithm used to check file equality.')
@click.option('--type', default=['sym'], show_default=True, multiple=True,
              type=click.Choice(['sym', 'lnk', 'chr', 'blk', 'fifo']),
              help='Special file types to archive.')
@click.option('--exclude', metavar='[PATTERN]', default=Backup.DEFAULT_EXCLUDE,
              multiple=True, help='Regular expression of files to exclude.')
@click.option('--max-size', type=int, default=100*MEBIBYTE,
              help='Maximum file size. [default: 100 MiB]')
@click.argument('source', nargs=-1, type=click.Path(exists=True),
                callback = lambda _ctx, values: tuple(map(pathlib.Path, values)))
@click.pass_context
def create(ctx, **options):
    """ Create a backup. """
    with Archive(ctx.obj['archive']) as archive:
        backup = Backup.from_dict(options)
        with archive.open_tar(backup.tar_filename, 'w|' + backup.compression) as tar:
            backup.scan(tar, options['source'])
            with ProgressBar(backup.root.size, slow_rate=96*MEBIBYTE, medium_rate=128*MEBIBYTE) as bar:
                backup.digest(hook=functools.partial(Archive.bar_update_hook, bar))

            click.secho(f'Scanned {len(backup.root)} files ({humanize_file_size(backup.root.size)}).',
                        fg='cyan', bold=True)
            click.echo(f'Ready to write archive to {backup.tar_filename!r}.')
            if not click.confirm('Commit to disk?'):
                raise AbortException

            base = last.root if (last := archive.last_backup) else None
            if diff := backup.root - base:
                archive.write_metadata(backup)
                click.echo(f'Wrote metadata to {backup.metadata_filename!r}')
                with ProgressBar(diff.size) as bar:
                    archive.add_files(tar, diff, bar)
                click.secho(f'Added {len(diff)} modified files '
                            f'({humanize_file_size(diff.size)}) to archive.',
                            fg='green', bold=True)
            else:
                click.secho('No modified files to archive.', fg='yellow', bold=True)
                raise AbortException


def parse_hash(_ctx, value: typing.Optional[str]) -> bytes:
    try:
        return bytes.fromhex(value or '')
    except ValueError as exc:
        raise click.BadParameter(f'Hash is not a hexadecimal string: {value!r}') from exc


hash_argument = click.argument('hash', required=False, callback=parse_hash)
Mount = tuple[pathlib.Path, typing.Optional[pathlib.Path]]


def parse_mounts(_ctx, values: tuple[str, ...]) -> list[Mount]:
    mounts = []
    for mount in values:
        src, dst = mount.split(':')
        mounts.append((pathlib.Path(src), pathlib.Path(dst) if dst else None))
    return mounts


def substitute_mounts(path: pathlib.Path, mounts: list[Mount]) -> typing.Optional[pathlib.Path]:
    for src, dst in mounts:
        if path.is_relative_to(src):
            return dst.joinpath(path.relative_to(src)) if dst else None
    return path


def get_mounted_targets(tar: tarfile.TarFile, targets: set[pathlib.Path], mounts: list[Mount]) \
        -> typing.Iterable[tuple[pathlib.Path, pathlib.Path, tarfile.TarInfo]]:
    for info in tar:
        path = FileHashTree.ROOT.joinpath(info.name)
        if path in targets and (mounted_path := substitute_mounts(path, mounts)):
            info.name = mounted_path.name
            yield mounted_path, path, info


@cli.command()
@click.option('--dry-run', is_flag=True, help='Do not persist changes.')
@click.option('--destructive', is_flag=True, help='Destroy existing files.')
@click.option('--mount', metavar='[SRC]:[DST]', callback=parse_mounts,
              multiple=True, help='Alternate mount points.')
@hash_argument
@click.pass_context
def restore(ctx, **options):
    """ Restore a backup. """
    with Archive(ctx.obj['archive']) as archive:
        if not (last := archive.last_backup):
            click.secho('No backups available.', fg='red', bold=True)
            return
        if not (backup := archive.find_backup(digest := options['hash'] or last.root.digest)):
            click.secho(f'No backup found with digest: {digest.hex()!r}', fg='red', bold=True)
            return
        partitions = archive.partition(backup)
        for backup in archive.metadata:
            if targets := partitions.get(backup.root.digest):
                with archive.open_tar(backup.tar_filename, 'r:*') as tar:
                    mounted_targets = get_mounted_targets(tar, targets, options['mount'])
                    for mounted_path, path, info in sorted(mounted_targets, reversed=True):
                        if options['dry_run']:
                            click.echo(f'{path!s} -> {mounted_path!s}')
                        else:
                            tar.extract(info, path=mounted_path.parent)


@cli.command('list')
@click.pass_context
def list_backups(ctx):
    """ List available backups. """
    with Archive(ctx.obj['archive']) as archive:
        if archive.metadata:
            click.secho('Backups:', bold=True)
            for backup in archive.metadata:
                click.echo(f'  {backup.fmt_timestamp} {backup.hash_alg} {backup.root.digest.hex()}')
        else:
            click.secho('No backups found.', fg='yellow', bold=True)


@cli.command()
@hash_argument
@click.pass_context
def remove(ctx):
    """ Remove and merge a backup. """


if __name__ == '__main__':
    cli()
