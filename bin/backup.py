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
import pathlib
import queue
import tarfile
import typing
import re

import click


KIBIBYTE, MEBIBYTE, GIBIBYTE = 2**10, 2**20, 2**30
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
        sizes = [1, KIBIBYTE, MEBIBYTE, GIBIBYTE, float('inf')]
        for prefix, divisor, limit in zip(prefixes, sizes[:-1], sizes[1:]):
            if byte_count < limit:
                value = byte_count if divisor == 1 else round(byte_count/divisor, rounding)
                return f'{value} {prefix}B'

    def update_rate(self, info, default: float = KIBIBYTE) -> float:
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
class FileHashTree(collections.abc.Mapping[pathlib.Path, 'FileHashTree']):
    """
    A recursive data structure containing file metadata and hashes to detect changes.

    The hash digest at a node is dependent on the Tar info buffer, the file
    contents (if the node is a regular file), and the digests of all the node's
    children (if the node is a directory). The childrens' digests are ordered
    by name to ensure the preimage is well-defined.

    Attributes:
        digest: The hash value. May be empty.
        children: Maps names to child files. Only nonempty for directories.
        info: An optional `tarfile.TarInfo` containing metadata written to a
            Tar file. May be missing because the node represents a parent
            directory not being archived, or because the tree is deserialized.
            Because the Tar info is used to compute the digest, this field is
            not used for comparison.

    """
    info: typing.Optional[tarfile.TarInfo] = \
        dataclasses.field(default=None, repr=False, compare=False)
    children: typing.MutableMapping[str, 'FileHashTree'] = dataclasses.field(default_factory=dict)
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
        return bool(self.info) + sum(map(len, self.children))

    @classmethod
    def scan(cls, tar: tarfile.TarFile, path: pathlib.Path,
             base: typing.Optional[pathlib.Path] = None) -> typing.Optional['FileHashTree']:
        base = base or path
        with contextlib.suppress(PermissionError):
            if not path.exists() or not (info := tar.gettarinfo(path)):
                return
            # TODO: add exclude
            node = FileHashTree(info)
            if path.is_dir():
                for child_path in path.iterdir():
                    if child := FileHashTree.scan(tar, child_path, base=base):
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
        digest = functools.partial(self._digest, hash_alg=hash_alg)
        info_digest = content_digest = b''
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
        digests = [info_digest, content_digest] + [child.digest for child in children.values()]
        return FileHashTree(self.info, children, digest(sep.join(digests)))

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
        if not other:
            return self
        if self.digest != other.digest:
            children = {part: diff for part, child in self.children.items()
                        if (diff := child - other.children.get(part))}
            return FileHashTree(self.info, children, self.digest)

    def to_dict(self) -> dict:
        node = {'digest': self.digest.hex()}
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

#     def create_archive(self, tar: tarfile.TarFile, bar: ProgressBar):
#         def archive_hook(info, file_handle: typing.Optional[io.FileIO] = None):
#             # File cache has been warmed up, so rereading should not be too slow.
#             tar.addfile(info, file_handle)
#             if info.size > 0:
#                 bar.update(info)
#         self.update_hashes(archive_hook)


@dataclasses.dataclass(frozen=True)
class Archive:
    """
    """
    DEFAULT_EXCLUDE = [
        r'^__pycache__$',                               # Python
        r'^\.?(v|virtual|)envs?$',                      # Python virtual environments
        r'^node_modules$',                              # NodeJS
        r'^\.cache',                                    # Caches
        r'^\.vagrant$',                                 # Vagrant
        r'\.(aux|lof|fls|fdb_latexmk|pdfsync|toc)$',    # TeX
        r'\.synctex(\.gz)?(\(busy\))?$',                # SyncTeX
        r'^\.DS_Store$',                                # macOS
    ]

    HASH_ALGORITHMS = ['sha256', 'sha384', 'sha512']
    METADATA_DIR_NAME = '.backup'

    # tar: tarfile.TarFile
    path: pathlib.Path
    hash_alg: str = HASH_ALGORITHMS[0]
    exclude: typing.Sequence[re.Pattern] = dataclasses.field(default_factory=tuple)
    file_types: typing.Sequence[str] = dataclasses.field(default_factory=list)

    @functools.cached_property
    def _metadata_path(self) -> pathlib.Path:
        return self.path / self.METADATA_DIR_NAME

    def _initialize(self, name='.backup'):
        self._metadata_path.mkdir(parents=True, exist_ok=True)

    def load_backup_metadata(self):
        pass

    # def exclude(self):
    #     pass
    #
    # @contextlib.contextmanager
    # @staticmethod

    def should_index_special(self, info: tarfile.TarInfo) -> bool:
        return any(getattr(info, f'is{file_type}')() for file_type in self.file_types)

    def should_exclude(self, path: pathlib.Path) -> bool:
        return any(pattern.search(path.name) for pattern in self.exclude)


def filter_prefixes(sources: typing.Sequence[pathlib.Path]) \
        -> typing.Iterable[pathlib.Path]:
    """
    Filter a list of paths such that no path is a prefix of any other.

    Returns:
        The filtered paths in sorted order, coerced as absolute paths.
    """
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
    Create incremental compressed backups.
    """
    ctx.ensure_object(dict)
    ctx.obj.update(options)


@cli.command()
@click.option('--source', default=[str(pathlib.Path.home())], callback=as_paths,
              show_default=True, type=click.Path(exists=True), multiple=True,
              help='Directories to backup.')
@click.option('--compression', type=click.Choice(['gz', 'bz2', 'xz']),
              help='Compression method (no compression by default).')
@click.option('--hash', default=Archive.HASH_ALGORITHMS[0],
              type=click.Choice(Archive.HASH_ALGORITHMS),
              help='Hashing algorithm used to check file equality.')
@click.option('--type', default=['sym'], show_default=True, multiple=True,
              type=click.Choice(['sym', 'lnk', 'chr', 'blk', 'fifo']),
              help='Special file types to archive.')
@click.option('--exclude',
              multiple=True, help='Regular expression of files to exclude.')
@click.pass_context
def create(ctx, **options):
    """ Create a backup. """
    compression = options['compression'] or ''
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H%M%S')
    filename = f'{timestamp}-backup.tar{"." + compression if compression else ""}'

    sources = tuple(filter_prefixes(options['source']))
    with tarfile.open(str(ctx.obj['archive'] / filename), 'w|' + compression) as tar:
        pass

        root = None
        for source in sources:
            root |= FileHashTree.scan(tar, source)
        root = root.with_digests()
        print(json.dumps((root - FileHashTree.scan(tar, sources[0]).with_digests()).to_dict(), indent=2))

        # print(root.digest)
        # for x in root:
        #     print(x.info)
        # node = root['/home/jonathanlee/uc-berkeley/2016-fall']
        # print(node.digest)
        # print(json.dumps(root.to_dict(), indent=2))
        # print(FileHashTree.from_dict(root.to_dict()) == root)

        # archive = Archive(tar, options['hash'], options['type'])
        #     with ProgressBar(total_bytes) as bar:
        #         archive.create(infos, bar, executor)


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
