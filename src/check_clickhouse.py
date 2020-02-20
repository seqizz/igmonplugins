#!/usr/bin/env python
#
# Nagios clickhouse-server check
#
# This check tests multiple clickhouse-server's health metrics
#
# Usage examples:
#
#   check_clickhouse.py clusters -c cluster_name
#   check_clickhouse.py parts
#   check_clickhouse.py replication
#
# For details see --help/-h for each `check_clickhouse.py`a and each check_name
#
# Copyright (c) 2020 InnoGames GmbH
#

from argparse import (
    ArgumentParser, Namespace, ArgumentDefaultsHelpFormatter,
    ArgumentTypeError, _SubParsersAction,
)
# https://pypi.org/project/clickhouse-driver/
from clickhouse_driver import Client  # type: ignore  # missing stubs
from clickhouse_driver.errors import (  # type: ignore  # missing stubs
    NetworkError, ServerException,
)
from pprint import pformat
from typing import Tuple, List

import logging
import sys

# exit code and message
ExitStruct = Tuple[int, str]

logging.basicConfig(
    format='%(levelname)-8s [%(filename)s:%(lineno)d]:\n%(message)s'
)
logger = logging.getLogger(__name__)


def parse_args() -> Namespace:
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '-v', '--verbose', action='count', default=0,
        help='set the script verbosity, could be used multiple',
    )
    parser.add_argument(
        '--host', default='localhost', help='ClickHouse server hostname',
    )
    parser.add_argument(
        '--port', default=9000, type=int, help='ClickHouse server hostname',
    )
    parser.add_argument(
        '-u', '--user', default='default', help='ClickHouse username',
    )
    parser.add_argument(
        '-p', '--password', default='', help='ClickHouse username',
    )

    subparsers = parser.add_subparsers(dest='check_name')
    subparsers.required = True

    add_subparser_clusters(subparsers)
    add_subparser_parts(subparsers)
    add_subparser_replication(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    log_levels = [logging.CRITICAL, logging.WARN, logging.INFO, logging.DEBUG]
    logger.setLevel(log_levels[min(args.verbose, 3)])
    logger.debug('Arguments are {}'.format(pformat(args.__dict__)))
    check = args.check(
        host=args.host, port=args.port, database='system',
        user=args.user, password=args.password,
    )
    try:
        # Each subcommand executes appropriate method of Check
        code, message = check(args.__dict__)
        print(message)
        sys.exit(code)
    except NetworkError as e:
        check.code.current = Code.CRITICAL
        code, message = check.exit(e.message)
        print(message)
        sys.exit(code)


def add_subparser_clusters(subparsers: _SubParsersAction):
    parser_clusters = subparsers.add_parser(
        'clusters', formatter_class=ArgumentDefaultsHelpFormatter,
        help='checks basic availability of Distributed tables',
    )
    parser_clusters.set_defaults(check=CheckClusters)
    parser_clusters.add_argument(
        '-c', '--clusters', action='append', default=[], required=True,
        help='cluster names, could be defined multiple times',
    )


def add_subparser_parts(subparsers: _SubParsersAction):
    parser_parts = subparsers.add_parser(
        'parts', formatter_class=ArgumentDefaultsHelpFormatter,
        help='check if inserts and merges work in normal mode;'
        'warning if (parts_to_delay_insert * delay_factor) <= '
        '(active parts per partition) < throw_factor, critical if '
        '(parts_to_throw_insert * throw_factor) < (active parts per partition)'
    )
    parser_parts.set_defaults(check=CheckParts)
    parser_parts.add_argument(
        '--delay-factor', type=Factor, default=0.9,
        help='raise warning when (parts_to_delay_insert * delay_factor) <= '
        '(active parts per partition) < throw_factor'
    )
    parser_parts.add_argument(
        '--throw-factor', type=Factor, default=0.8,
        help='raise critical when (parts_to_throw_insert * throw_factor) <= '
        '(active parts per partition)'
    )


def add_subparser_replication(subparsers: _SubParsersAction):
    # TODO: Take a look on implementing class Threshold to pass all logic there
    # after (if) helper module will be implemented
    parser_replication = subparsers.add_parser(
        'replication', formatter_class=ArgumentDefaultsHelpFormatter,
        help='check replication health, see https://clickhouse.tech/docs/en/'
        'operations/system_tables/#system_tables-replicas',
    )
    parser_replication.set_defaults(check=CheckReplication)
    parser_replication.add_argument(
        '--future-parts', type=int, default=20,
        help='how many parts could be delayed via inserts and merges',
    )
    parser_replication.add_argument(
        '--parts-to-check', type=int, default=10,
        help='how many parts could be in queue to verify',
    )
    parser_replication.add_argument(
        '--queue-size', type=int, default=20,
        help='how big queue to perform actions on parts could be',
    )
    parser_replication.add_argument(
        '--inserts-in-queue', type=int, default=10,
        help='how many inserts of blocks are delayed',
    )
    parser_replication.add_argument(
        '--merges-in-queue', type=int, default=40,
        help='how many merges are delayed, could be greater then 0 for a long',
    )
    parser_replication.add_argument(
        '--log-delay', type=int, default=10, help='how big difference between '
        'actions log in ZK and locally could be',
    )
    parser_replication.add_argument(
        '--absolute-delay', type=int, default=40,
        help='how big lag in seconds the current replica could have',
    )


class Check(object):
    def __init__(self, *args, **kwargs):
        self.conn = Client(*args, **kwargs)
        self.code = Code()

    def execute(self, *args, **kwargs) -> List[tuple]:
        """
        Wrapper to execute ClickHouse SQL
        """
        return self.conn.execute(*args, **kwargs)

    def execute_dict(self, *args, **kwargs) -> List[dict]:
        """
        Wrapper around execute() to return list of rows as dict
        """
        kwargs['with_column_types'] = True
        rows, columns = self.execute(*args, **kwargs)
        result = [{columns[i][0]: v for i, v in enumerate(r)} for r in rows]
        return result

    def exit(self, message: str) -> ExitStruct:
        message = self.code.name + ': ' + message
        return self.code.current, message

    def check_config(self, config: dict, keys: set):
        """
        Checks if all mandatory keys are presented in the config dict
        """
        keys_in_config = config.keys() & keys
        if keys_in_config != keys:
            raise KeyError('Not all of {} presented in config: {}'
                           .format(keys, config))


class CheckClusters(Check):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, config: dict) -> ExitStruct:
        """
        Accepts args with 'clusters' attribute and checks every related
        Distributed table, if it is readable
        """
        logger.debug('Cluster check, config={}'.format(pformat(config)))
        self.check_config(config, {'clusters'})

        messages = []  # type: List[str]
        # Request config['clusters'] from ClickHouse
        clusters = self.execute_dict(
            r'''
            SELECT
                splitByChar('\'', engine_full)[2] AS cluster,
                groupArray(concat(t.database, '.', t.name)) AS tables
            FROM system.tables AS t
            INNER JOIN
            (
                SELECT cluster
                FROM system.clusters
                WHERE cluster IN %(clusters)s
                GROUP BY cluster
            ) AS c USING (cluster)
            WHERE t.engine = 'Distributed'
            GROUP BY cluster
            ''',
            {'clusters': tuple(config['clusters'])},
        )
        logger.debug(
            'Existing clusters on ClickHouse server are: {}'
            .format(pformat(clusters))
        )

        existing = {c['cluster'] for c in clusters}
        missing = set(config['clusters']) - existing
        if missing:
            self.code.current = Code.CRITICAL
            messages.append('Clusters not found on server: {}'.format(missing))

        def check_tables(tables: List[str]) -> List[str]:
            failed = []
            for t in tables:
                logger.debug('Select from distributed table `{}`'.format(t))
                try:
                    self.execute('SELECT * FROM {} LIMIT 1'.format(t))
                except ServerException as e:
                    logger.warning('Fail to read from `{}`, exception is: {}'
                                   .format(t, e.message))
                    failed.append(t)
            return failed

        for cl in clusters:
            logger.debug('Tables for cluster `{cluster}` are {tables}'
                         .format_map(cl))
            failed_tables = check_tables(cl['tables'])
            if not failed_tables:
                continue
            self.code.current = Code.CRITICAL
            messages.append(
                'Cluster `{}`, failed to query from tables {}'
                .format(cl['cluster'], failed_tables)
            )

        messages = messages or ['All clusters are fine: {}'.format(clusters)]
        return self.exit('; '.join(messages))


class CheckParts(Check):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, config: dict) -> ExitStruct:
        """
        Checks if there are tables:partitions with too many active parts
        config should contain next keys:
            - delay_factor
            - throw_factor
        """

        logger.debug('Parts check, config={}'.format(pformat(config)))
        factors = {'delay_factor', 'throw_factor'}
        self.check_config(config, factors)

        messages = []  # type: List[str]
        rows = self._get_parts(config['delay_factor'], config['throw_factor'])
        logger.debug('Problems from CH are {}'.format(pformat(rows)))

        if not rows:
            return self.exit('There are no *MergeTree tables on server')

        # current thresholds from first result
        delay, throw = rows[0]['delay'], rows[0]['throw']
        logger.info('Thresholds for check are: delay={}, throw={}'
                    .format(delay, throw))

        for r in rows:
            if r['warning']:
                self.code.current = Code.WARNING
                messages.append(
                    'Inserts into the next table:partition:parts will be '
                    'delayed soon since they contain {}<=parts<{}: {}'
                    .format(delay, throw, ','.join(r['tpp']))
                )
            if r['critical']:
                self.code.current = Code.CRITICAL
                messages.append(
                    'Inserts into the next table:partition:parts will '
                    'fail soon since they contain {}<=parts: {}'
                    .format(throw, ','.join(r['tpp']))
                )

        messages = messages or ['Inserts and merges are going fine']
        return self.exit('; '.join(messages))

    def _get_parts(self, delay_factor, throw_factor) -> List[dict]:
        """
        Example of returned value:
            [{'critical': 0,
              'delay': 4.5,
              'tpp': ('system.trace_log:201912:3'),
              'throw': 11.1,
              'warning': 0},
             {'critical': 0,
              'delay': 4.5,
              'tpp': ('system.query_log:20200131:6'),
              'throw': 11.1,
              'warning': 1},
             {'critical': 1,
              'delay': 4.5,
              'tpp': (system.query_log:20200130:12),
              'throw': 11.1,
              'warning': 0}]
        """
        return self.execute_dict(
            r'''
            SELECT
                groupArray(concat(
                    p.table, ':', p.partition, ':', toString(p.parts)
                )) AS tpp, -- table_partition_parts
                (s.delay <= p.parts) AND (p.parts < s.throw) AS warning,
                s.throw <= p.parts AS critical,
                any(s.delay) AS delay,
                any(s.throw) AS throw
            FROM
            (
                SELECT
                    concat(database, '.', table) AS table,
                    count() AS parts,
                    partition
                FROM system.parts
                    WHERE engine LIKE '%%MergeTree' AND active
                GROUP BY
                    table,
                    partition
            ) AS p
            CROSS JOIN
            (
                SELECT
                    anyIf(toUInt32(value) * %(delay_factor)s,
                          name = 'parts_to_delay_insert') AS delay,
                    anyIf(toUInt32(value) * %(throw_factor)s,
                          name = 'parts_to_throw_insert') AS throw
                FROM system.merge_tree_settings
                WHERE name IN ('parts_to_delay_insert',
                               'parts_to_throw_insert')
            ) AS s
                GROUP BY
                    warning, critical
                ORDER BY
                    critical, warning
            ''',
            {'delay_factor': delay_factor, 'throw_factor': throw_factor}
        )


class CheckReplication(Check):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, config: dict) -> ExitStruct:
        """
        Check if replica:
            Is in a wrong state (CRITICAL):
            - is_readonly
            - is_session_expired

            Has delay issues (WARNING):
            - future_parts > 20 (config.future_parts)
            - parts_to_check > 10 (config.parts_to_check)
            - queue_size > 20 (config.queue_size)
            - inserts_in_queue > 10 (config.inserts_in_queue)
            - merges_in_queue > 40 (config.merges_in_queue)
            - (log_max_index-log_pointer) as log_delay > 10 (config.log_delay)
            - absolute_delay > 40 (config.absolute_delay)
        """
        logger.debug('Replication check, config={}'.format(pformat(config)))
        checks = {'future_parts', 'parts_to_check', 'log_delay', 'queue_size',
                  'inserts_in_queue', 'merges_in_queue', 'absolute_delay'}
        self.check_config(config, checks)

        tables = self.execute_dict(
            "SELECT concat(database, '.', table) as name, is_readonly,"
            '   is_session_expired, future_parts, parts_to_check, queue_size, '
            '   inserts_in_queue, merges_in_queue, absolute_delay, '
            '   log_max_index - log_pointer AS log_delay '
            'FROM system.replicas'
        )
        messages = []  # type: List[str]

        for t in tables:
            logger.debug('Check table {}: {}'.format(t['name'], pformat(t)))
            if t['is_readonly'] or t['is_session_expired']:
                self.code.current = Code.CRITICAL
                messages.append(
                    'Table `{name}`: is_readonly={is_readonly}, '
                    'is_session_expired={is_session_expired}'.format_map(t)
                )
                continue

            t_messages = [
                '{}={} (max < {})'.format(c, t[c], config[c]) for c in checks
                if config[c] <= t[c]
            ]
            if not t_messages:
                continue

            self.code.current = Code.WARNING
            message = 'Table `{}`: {}'.format(t['name'], ', '.join(t_messages))
            messages.append(message)

        messages = messages or ['All replicated tables are fine']
        return self.exit('; '.join(messages))


class Code(object):
    """
    Class to handle nagios exit codes. It handles exit codes in next order:
        OK < UNKNOWN < WARNING < CRITICAL
    """
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3
    valid = [OK, WARNING, CRITICAL, UNKNOWN]
    names = {
        OK: 'OK', WARNING: 'WARNING', CRITICAL: 'CRITICAL', UNKNOWN: 'UNKNOWN'
    }

    def __init__(self, code: int = OK):
        """
        Create Code instance with OK current code by default
        """
        self.current = code

    def reset(self, code: int = OK):
        """
        Resets 'current' property to optionally given code, 0 by default
        """
        self._check_code(code)
        self.__current = code

    def _check_code(self, code: int):
        """
        Checks if code is valid
        """
        if code not in self.valid:
            raise Exception('code {} must be in {}'.format(code, self.valid))

    @property
    def name(self):
        """
        Return the text representation of current code
        """
        return self.names[self.current]

    @property
    def current(self):
        """
        Keeps the current exit code and doesn't allow to decrease it
        """
        return self.__current

    @current.setter
    def current(self, code):
        """
        Keeps the current exit code and doesn't allow to decrease it.
        Order: OK < UNKNOWN < WARNING < CRITICAL
        """
        self._check_code(code)
        self.__current = getattr(self, 'current', 0)

        if self.__current == self.OK:
            self.__current = code
            return
        elif (self.__current == self.UNKNOWN and
                code in [self.WARNING, self.CRITICAL, self.UNKNOWN]):
            self.__current = code
            return
        elif (self.__current == self.WARNING and
              code in [self.WARNING, self.CRITICAL]):
            self.__current = code
            return
        elif self.__current == self.CRITICAL:
            return


class Factor(float):
    def __init__(self, value):
        if not 0.0 < self <= 1.0:
            raise ArgumentTypeError('must be in math range (0, 1]')


if __name__ == '__main__':
    main()
