#!/usr/bin/env python3

import contextlib
import dataclasses
import datetime
import enum
import functools
import typing
import re
import warnings

import click


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

    def append(self, line: str, delimeter: str = '\n') -> 'LogRecord':
        return LogRecord(self.timestamp, self.source, self.message + delimeter + line)

    @classmethod
    def format_timestamp(cls, timestamp: datetime.datetime) -> str:
        aware = timestamp.tzinfo is not None and timestamp.tzinfo.utcoffset(timestamp) is not None
        return timestamp.strftime(cls.AWARE_TIMESTAMP_FORMAT if aware else cls.NAIVE_TIMESTAMP_FORMAT)

    def __str__(self) -> str:
        return f'[{self.format_timestamp(self.timestamp)}] [{self.source.value}] {self.message}'

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
                    message,
                ))
            elif records:
                records[-1] = records[-1].append(line)
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
                self.last_pkg_or_hook = operation.packages[package] = PackageVersion(
                    record.timestamp,
                    match.group('version'),
                    PackageAction(action),
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
            match = self.COMMAND_PATTERN.match(record.message)
            if match:
                self.append(Operation(match.group('command')))
                self.reset()
            elif self:
                self._update(record)
            else:
                warnings.warn('Log record before any operations.')
        self.reset()

    def get_versions(self, package: str) -> typing.Iterable[PackageVersion]:
        for operation in self:
            version = operation.packages.get(package)
            if version:
                yield version


@click.group()
@click.option('--log', default='/var/log/pacman.log',
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
    click.secho(f':: Read {len(records)} records from {log!r}', fg='cyan')

    ctx.obj['operations'] = operations = OperationBuffer()
    operations.parse(records)
    click.secho(f':: Parsed {len(operations)} operations', fg='cyan')


@cli.command('list')
@click.pass_context
def list_transactions(ctx):
    """ List transactions. """


@cli.command()
@click.argument('package', nargs=-1)
@click.pass_context
def history(ctx, package):
    """ Get the version history of packages. """
    operations = ctx.obj['operations']
    action_colors = {
        PackageAction.INSTALL: 'green',
        PackageAction.REINSTALL: 'yellow',
        PackageAction.UPGRADE: 'cyan',
        PackageAction.DOWNGRADE: 'magenta',
        PackageAction.REMOVE: 'red',
    }

    for pkg in package:
        click.secho(f'Package: {pkg}\n', bold=True)
        versions = list(operations.get_versions(pkg))
        if versions:
            current_version = None
            for version in versions:
                click.echo(LogRecord.format_timestamp(version.timestamp).rjust(26), nl=False)
                click.echo(' '*2, nl=False)
                click.secho(version.action.name.capitalize().rjust(9),
                            fg=action_colors[version.action], bold=True, nl=False)
                click.echo(' '*2, nl=False)
                next_version = None if version.action is PackageAction.REMOVE else version.version
                click.secho(f'{current_version} -> {next_version}')
                current_version = next_version
        else:
            click.echo(' '*2, nl=False)
            click.secho('No versions found.', fg='red', bold=True)
        click.echo('')


if __name__ == '__main__':
    cli()
