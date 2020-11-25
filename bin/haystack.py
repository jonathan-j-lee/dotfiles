#!/usr/bin/env python3

import collections
import contextlib
import dataclasses
import datetime
import enum
import functools
import math
import numbers
import typing
import re
import warnings

import click

EPOCH = datetime.datetime.fromtimestamp(0)
SCRIPTLET_STYLE = dict(fg='blue', bold=True)
WARNING_STYLE = dict(fg='red', bold=True)
MATCH_STYLE = dict(fg='green', bold=True)


class LogSource(enum.Enum):
    PACMAN = 'PACMAN'
    ALPM = 'ALPM'
    ALPM_SCRIPTLET = 'ALPM-SCRIPTLET'


@dataclasses.dataclass(frozen=True)
class LogRecord:
    """
    A single line in a pacman log.

    For example:

        [2018-09-24 12:19] [PACMAN] Running 'pacman -Syu'

    The timestamp is "2018-09-24 12:19", the source of the event is "PACMAN",
    and the message is "Running 'pacman -Syu'".

    This low-level API is largely unstructured (human-readable). Use
    the structured `Operation` for automated processing.
    """
    timestamp: datetime.datetime
    source: LogSource
    message: str

    PATTERN = re.compile(r'\[(.*)\] \[([a-zA-Z\-_]*)\] (.*)')
    NAIVE_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M'
    AWARE_TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S%z'

    def append(self, line: str, delimeter: str = ' ') -> 'LogRecord':
        return LogRecord(self.timestamp, self.source, self.message + delimeter + line)

    @classmethod
    def format_timestamp(cls, timestamp: datetime.datetime, justify: int = 24) -> str:
        aware = timestamp.tzinfo is not None and timestamp.tzinfo.utcoffset(timestamp) is not None
        fmt = cls.AWARE_TIMESTAMP_FORMAT if aware else cls.NAIVE_TIMESTAMP_FORMAT
        return timestamp.strftime(fmt).rjust(justify)

    def __str__(self) -> str:
        return f'[{self.format_timestamp(self.timestamp, 0)}] [{self.source.value}] {self.message}'

    @classmethod
    def parse_timestamp(cls, timestamp: str) -> datetime.datetime:
        """
        Parse a timestamp (either a subset of RFC 3339, or a similar legacy format).
        """
        for fmt in (cls.AWARE_TIMESTAMP_FORMAT, cls.NAIVE_TIMESTAMP_FORMAT):
            with contextlib.suppress(ValueError):
                return datetime.datetime.strptime(timestamp, fmt)
        raise ValueError('No recognized timestamp format.')

    @classmethod
    def from_file(cls, log) -> typing.List['LogRecord']:
        """
        Parse a pacman log into records.

        Raises::
            ValueError: Corrupt log file. Reasons may include unknown log
                source, bad timestamp format, or first line does not follow the
                record format.
        """
        records = []
        for line_num, line in enumerate(log):
            if (match := cls.PATTERN.match(line)):
                timestamp, source, message = match.groups()
                records.append(LogRecord(
                    cls.parse_timestamp(timestamp),
                    LogSource(source),
                    message.strip(),
                ))
            elif records:
                records[-1] = records[-1].append(line.strip())
            else:
                raise ValueError
        return records


class TransactionStatus(enum.Enum):
    STARTED = 'started'
    COMPLETED = 'completed'
    INTERRUPTED = 'interrupted'
    FAILED = 'failed'


class PackageAction(enum.Enum):
    INSTALL = 'installed'
    REINSTALL = 'reinstalled'
    UPGRADE = 'upgraded'
    DOWNGRADE = 'downgraded'
    REMOVE = 'removed'

    def format_name(self, justify: typing.Optional[int] = None) -> str:
        justify = self._MAX_WIDTH if justify is None else justify
        return click.style(self.value.capitalize().rjust(justify),
                           fg=self.COLORS[self], bold=True)

PackageAction._MAX_WIDTH = max(len(action.value) for action in PackageAction)
PackageAction.COLORS = {
    PackageAction.INSTALL: 'green',
    PackageAction.REINSTALL: 'yellow',
    PackageAction.UPGRADE: 'cyan',
    PackageAction.DOWNGRADE: 'magenta',
    PackageAction.REMOVE: 'red',
}


@dataclasses.dataclass(frozen=True)
class PackageVersion:
    timestamp: datetime.datetime
    version: str
    action: PackageAction
    warning: typing.List[str] = dataclasses.field(default_factory=list)
    scriptlet: typing.List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class HookExecution:
    timestamp: datetime.datetime
    scriptlet: typing.List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Operation:
    command: str
    packages: typing.Mapping[str, PackageVersion] = dataclasses.field(default_factory=dict)
    hooks: typing.Mapping[str, HookExecution] = dataclasses.field(default_factory=dict)
    sync: bool = False
    upgrade: bool = False
    complete: bool = True

    @functools.cached_property
    def duration(self) -> datetime.timedelta:
        return self.end - self.start

    @property
    def chronological_packages(self) -> typing.Iterable[str]:
        return sorted(self.packages, key=lambda pkg: self.packages[pkg].timestamp)


class OperationBuffer(list):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.warning_buffer = []
        self.tx_status = self.last_pkg_or_hook = None

    COMMAND_PATTERN = re.compile(r"Running '(?P<command>.*)'")
    HOOK_PATTERN = re.compile(r"running '(?P<hook>[\w\.\-]+)\.hook'\.{3}")
    VERSION_PATTERN = re.compile(r'\(([\w\.\-\:\+\~]+ \-> )?(?P<version>[\w\.\-:\+\~]+)\)')

    @property
    def transaction_started(self):
        return self.tx_status is TransactionStatus.STARTED

    @property
    def transaction_incomplete(self):
        return (self.tx_status is TransactionStatus.INTERRUPTED
                or self.tx_status is TransactionStatus.FAILED)

    def _update(self, record):
        operation = self[-1]
        if record.source is LogSource.PACMAN:
            if record.message == 'synchronizing package lists':
                operation.sync = True
            elif record.message == 'starting full system upgrade':
                operation.upgrade = True
            else:
                warnings.warn(f'Unrecognized PACMAN message: {record}')
        elif record.source is LogSource.ALPM:
            if record.message.startswith('error:') or record.message.startswith('warning:'):
                self.warning_buffer.append(record.message)
            elif record.message.startswith('transaction'):
                self.tx_status = TransactionStatus(record.message.split()[1])
                if self.transaction_incomplete:
                    operation.complete = False
            elif (hook := self.HOOK_PATTERN.match(record.message)):
                hook = hook.group('hook')
                self.last_pkg_or_hook = operation.hooks[hook] = HookExecution(record.timestamp)
            elif self.transaction_started:
                action, package, version = record.message.split(maxsplit=2)
                if not (match := self.VERSION_PATTERN.match(version)):
                    raise ValueError(f'Unable to read version number: {record.message!r}')
                action = PackageAction(action)
                self.last_pkg_or_hook = operation.packages[package] = PackageVersion(
                    record.timestamp,
                    match.group('version') if action is not PackageAction.REMOVE else None,
                    action,
                    list(self.warning_buffer),
                )
                self.warning_buffer.clear()
            else:
                warnings.warn(f'Unrecognized ALPM message: {record}')
        elif record.source is LogSource.ALPM_SCRIPTLET:
            if self.last_pkg_or_hook:
                self.last_pkg_or_hook.scriptlet.append(record.message)
            else:
                warnings.warn(f'Could not identify package/hook for scriptlet: {record}')

    def reset(self):
        self.warning_buffer.clear()
        self.tx_status = self.last_pkg_or_hook = None

    def parse(self, records: typing.List[LogRecord]):
        for record in records:
            if (match := self.COMMAND_PATTERN.match(record.message)):
                self.append(Operation(match.group('command')))
                self.reset()
            elif self:
                self._update(record)
            else:
                warnings.warn('Log record before any operations.')
        self.reset()

    def get_versions_by_package(self, package: str) -> typing.Iterable[PackageVersion]:
        for operation in self:
            version = operation.packages.get(package)
            if version:
                yield version

    def get_diff(self, end: datetime.datetime, start: datetime.datetime = EPOCH) \
            -> typing.MutableMapping[str, typing.Sequence[PackageVersion]]:
        packages = collections.defaultdict(list)
        start, end = start.timestamp(), end.timestamp()
        for operation in self:
            for package in operation.chronological_packages:
                version = operation.packages[package]
                if (timestamp := version.timestamp.timestamp()) > end:
                    return packages
                if start <= timestamp:
                    packages[package].append(version)
        return packages


@click.group(context_settings={'max_content_width': 120})
@click.option('--log', default='/var/log/pacman.log', show_default=True,
              type=click.Path(exists=True, dir_okay=False), help='Log file location.')
@click.version_option(version='0.0.1', message='v%(version)s')
@click.pass_context
def cli(ctx, log: str):
    """ pacman log parser. """
    ctx.ensure_object(dict)
    warnings.filterwarnings('ignore')

    try:
        with open(log, newline='\n') as log_file:
            records = LogRecord.from_file(log_file)
    except ValueError as exc:
        raise click.ClickException(f'Corrupt log {log!r}') from exc
    ctx.obj['operations'] = operations = OperationBuffer()
    operations.parse(records)


def parse_timestamp(ctx, timestamp: typing.Union[str, datetime.datetime]) -> datetime.datetime:
    if isinstance(timestamp, datetime.datetime):
        return timestamp
    try:
        return LogRecord.parse_timestamp(timestamp)
    except ValueError as exc:
        raise click.BadParameter(f'Unable to parse timestamp: {timestamp}') from exc


def parse_actions(ctx, actions: str) -> typing.Set[PackageAction]:
    try:
        return {PackageAction(action.strip().lower()) for action in actions.split(',')}
    except ValueError as exc:
        raise click.BadParameter(f'Unable to parse actions: {actions!r}') from exc


def compile_pattern(ctx, pattern: typing.Optional[str]) -> typing.Optional[re.Pattern]:
    if not pattern:
        return
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise click.BadParameter(f'Unable to compile regex pattern: {pattern!r}') from exc


def display_block(lines: typing.Iterable[str], indent: int = 10, prefix: str = '|'):
    if lines:
        for line in lines:
            click.echo(' '*indent + prefix + ' ' + line)
        click.echo()


@cli.command()
@click.option('--start', default=EPOCH, callback=parse_timestamp,
              help='The time of the starting database state. Defaults to UNIX epoch.')
@click.option('--end', default=datetime.datetime.now(), callback=parse_timestamp,
              help='The time of the ending database state. Defaults to the current time.')
@click.option('--intermediate/--no-intermediate',
              help='Show all intermediate package versions, not just the net delta.')
@click.option('--hide/--no-hide', default=True, help='Hide packages with no version change.')
@click.pass_context
def diff(ctx, start, end, intermediate, hide):
    """
    Get the change in package versions between two times.

    Examples:

    List all packages currently available:

    \b
      $ haystack diff

    List all packages modified in the last week:

    \b
      $ haystack diff --start="$(date --date='1 week ago' +'%Y-%m-%d %H:%M')" --intermediate
    """
    operations = ctx.obj['operations']

    base, delta = operations.get_diff(start), operations.get_diff(end, start)
    packages = {}
    for package, versions in delta.items():
        base_version = base[package][-1].version if package in base else None
        packages[package] = [base_version] + [version.version for version in versions]
    for package, versions in base.items():
        if package not in packages and versions[-1].action is not PackageAction.REMOVE:
            packages[package] = [versions[-1].version]
    if hide:
        for package, versions in list(packages.items()):
            if versions[0] == versions[-1]:
                del packages[package]

    package_width = max(map(len, packages))
    click.secho(f'Packages ({LogRecord.format_timestamp(start, 0)} '
                f'-> {LogRecord.format_timestamp(end, 0)}):\n', bold=True)
    for package in sorted(packages):
        versions = packages[package]
        if not intermediate and len(versions) >= 2:
            versions = [versions[0], versions[-1]]
        if all(version is None for version in versions):
            continue
        click.echo(' '*2, nl=False)
        click.echo(package.rjust(package_width), nl=False)
        click.echo(' '*2, nl=False)
        if versions[0] is None and versions[-1] is not None:
            status, color = 'installed', 'green'
        elif versions[0] is not None and versions[-1] is None:
            status, color = 'removed', 'red'
        elif versions[0] == versions[-1]:
            status, color = 'no change', 'blue'
        else:
            status, color = 'modified', 'cyan'
        click.secho(status.capitalize().rjust(9), fg=color, bold=True, nl=False)
        click.echo(' '*2, nl=False)
        click.echo(' -> '.join(map(str, versions)), nl=False)
        click.echo()
    click.echo()


@cli.command()
@click.option('--scriptlet/--no-scriptlet', help='Show scriptlet output.')
@click.argument('package', nargs=-1)
@click.pass_context
def package(ctx, scriptlet, package):
    """ Get the version history of packages. """
    operations = ctx.obj['operations']
    for pkg in package:
        click.secho(f'Package: {pkg}\n', bold=True)
        versions = list(operations.get_versions_by_package(pkg))
        if versions:
            current_version = None
            for version in versions:
                click.echo(' '*2, nl=False)
                click.echo(LogRecord.format_timestamp(version.timestamp), nl=False)
                click.echo(' '*2, nl=False)
                click.secho(version.action.format_name(), nl=False)
                click.echo(' '*2, nl=False)
                next_version = version.version
                click.secho(f'{current_version} -> {next_version}')
                current_version = next_version
                if scriptlet:
                    display_block([click.style(line, **SCRIPTLET_STYLE)
                                   for line in version.scriptlet])
        else:
            click.echo(' '*2, nl=False)
            click.secho('No versions found.', fg='red', bold=True)
        click.echo()


def format_matches(line: str, matches: typing.Iterable[re.Match],
                   match_style=MATCH_STYLE, default_style=None) -> str:
    current, buf, default_style = 0, [], default_style or {}
    for match in matches:
        start, end = match.start(), match.end()
        buf.append(click.style(line[current:start], **default_style))
        buf.append(click.style(line[start:end], **match_style))
        current = end
    buf.append(click.style(line[current:], **default_style))
    return ''.join(buf)


def search_text(lines: typing.Sequence[str], pattern: typing.Optional[re.Pattern], **styles) \
        -> typing.Sequence[str]:
    if not pattern:
        return lines
    matches = [list(pattern.finditer(line)) for line in lines]
    if all(not match for match in matches):
        raise ValueError
    return [format_matches(line, match, **styles) for line, match in zip(lines, matches)]


@cli.command()
@click.option('--start', default=EPOCH, callback=parse_timestamp,
              help='Filter by minimum transaction time. Defaults to UNIX epoch.')
@click.option('--end', default=datetime.datetime.now(), callback=parse_timestamp,
              help='Filter by maximum transaction time. Defaults to current time.')
@click.option('--command', callback=compile_pattern, help='Command regex pattern.')
@click.option('--package', callback=compile_pattern, help='Package name regex pattern.')
@click.option('--action', default=','.join(action.value for action in PackageAction),
              callback=parse_actions, help='Comma-separated list of package actions.',
              show_default=True)
@click.option('--version', callback=compile_pattern, help='Version regex pattern.')
@click.option('--scriptlet', callback=compile_pattern, help='Scriptlet output regex pattern.')
@click.option('--warning', callback=compile_pattern, help='Warnings regex pattern.')
@click.option('--sync/--no-sync', default=None,
              help='Filter by whether package lists were synchronized.')
@click.option('--upgrade/--no-upgrade', default=None,
              help='Filter by whether a full system upgrade was run.')
@click.option('--complete/--incomplete', default=None,
              help='Filter by whether the transaction completed.')
@click.pass_context
def query(ctx, **options):
    """
    Query for transactions.

    The boolean flags (sync, upgrade, complete) or their negatives are ignored
    if omitted.

    Examples:

    Find modified packages in the GNOME group:

    \b
      $ haystack query --action=upgraded,downgraded --package='^gnome'

    Find Linux 4.x packages:

    \b
      $ haystack query --version='^4\.' --package='^linux'

    Find keys added or removed from the keyring:

    \b
      $ haystack query --scriptlet='(Locally signing key|Disabling key)'
    """
    flags = ('sync', 'upgrade', 'complete')
    start, end = options['start'].timestamp(), options['end'].timestamp()
    for operation in ctx.obj['operations']:
        if any(getattr(operation, flag_name) != flag
               for flag_name in flags if (flag := options[flag_name]) is not None):
            continue

        try:
            command = search_text([operation.command], options['command'])[0]
        except ValueError:
            continue

        packages = []
        for package, version in operation.packages.items():
            if (not start <= version.timestamp.timestamp() <= end
                    or version.action not in options['action']):
                # TODO: Since operations are ordered by time, we can optimize
                #       this further by exiting early.
                continue
            try:
                package = search_text([package], options['package'])[0]
                ver_num = search_text([version.version or ''], options['version'])[0]
                scriptlet = search_text(version.scriptlet, options['scriptlet'],
                                        default_style=SCRIPTLET_STYLE)
                warning = search_text(version.warning, options['warning'],
                                      default_style=WARNING_STYLE)
            except ValueError:
                continue
            packages.append((version, package, ver_num, scriptlet, warning))

        if packages:
            click.secho('Operation: ', bold=True, nl=False)
            click.echo(command)
            click.echo()
            for version, package, ver_num, scriptlet, warning in packages:
                click.echo(' '*2, nl=False)
                click.echo(LogRecord.format_timestamp(version.timestamp), nl=False)
                click.echo(' '*2, nl=False)
                click.secho(version.action.format_name(), nl=False)
                click.echo(' '*2, nl=False)
                click.secho(f'{package} {ver_num}')
                block = warning if options['warning'] else []
                block += scriptlet if options['scriptlet'] else []
                display_block(block)
            click.echo()


def display_histogram(title: str, labels: typing.Iterable[str],
                      counts: typing.Iterable[numbers.Real], width: int = 100,
                      padding: int = 2, symbol: str = '='):
    click.secho(title, bold=True)
    label_width, max_count, count_total = max(map(len, labels)), max(counts), sum(counts)
    for label, count in zip(labels, counts):
        click.echo(' '*padding, nl=False)
        click.secho(label.rjust(label_width), bold=True, nl=False)
        click.echo(' '*padding, nl=False)
        click.secho('{:.2f}%'.format(100*count/count_total).rjust(7), nl=False)
        click.echo(' '*padding, nl=False)
        click.secho('|' + symbol*int(width*count/max_count))
    click.echo()


Interval, IntegralInterval = typing.Tuple[numbers.Real, numbers.Real], typing.Tuple[int, int]


def bin_count(values: typing.Sequence[numbers.Real],
              intervals: typing.Sequence[Interval]) -> typing.Sequence[int]:
    counts = [0]*len(intervals)
    for value in values:
        for i, (lower, upper) in enumerate(intervals):
            if lower <= value < upper:
                counts[i] += 1
                break
    return counts


def intervals_to_labels(intervals: typing.Sequence[IntegralInterval]) -> typing.Iterable[str]:
    for lower, upper in intervals:
        if math.isinf(upper) and upper > 0:
            yield f'{lower}+'
        else:
            yield f'{lower} - {upper-1}'


@cli.command()
@click.pass_context
def statistics(ctx):
    """ Display usage statistics. """
    operations = ctx.obj['operations']

    pkg_counts = [len(operation.packages) for operation in operations
                  if operation.complete and operation.packages]
    breakpoints = list(range(1, 30, 2)) + [float('inf')]
    intervals = list(zip(breakpoints[:-1], breakpoints[1:]))
    counts = bin_count(pkg_counts, intervals)
    display_histogram(f'Package Count per Transaction (max: {max(pkg_counts)}, '
                      f'mean: {round(sum(pkg_counts)/len(pkg_counts), 2)})',
                      list(intervals_to_labels(intervals)), counts)

    op_times = [min(pkg.timestamp for pkg in operation.packages.values())
                for operation in operations if operation.packages]
    op_hour_hist = collections.Counter([op_time.hour for op_time in op_times])
    labels, counts = [], []
    for hour in range(0, 24):
        labels.append(datetime.time(hour=hour).strftime('%I %p'))
        counts.append(op_hour_hist.get(hour, 0))
    display_histogram('Operation Start by Time of Day', labels, counts)


if __name__ == '__main__':
    cli()
