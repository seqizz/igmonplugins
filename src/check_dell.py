#!/usr/bin/env python
#
# Check Dell Hardware
#
# Copyright (c) 2016, InnoGames GmbH
#

'''This script checks some parameters of Dell servers via iDRAC'''

import argparse
import re
import shlex
import sys
import traceback

from subprocess import Popen, PIPE


racadm_commands = {
    'sel':           'getsel -o',
    'active_errors': 'getactiveerrors',
    'redundancy':    'getredundancymode',
    'fans':          'getfanreqinfo',
    'sensors':       'getsensorinfo',
}

ipmi_commands = {
    'sel':     'sel elist',
    'sensors': 'sdr list',
}


class NagiosCodes:
    ok = 0
    warning = 1
    critical = 2
    unknown = 3


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--host',
        default='localhost',
        help='Hostname or IP of DRAC/CMC to scan.',
    )
    parser.add_argument(
        '--command',
        required=True,
        choices=list(racadm_commands) + ['ipmi_' + c for c in ipmi_commands],
        help='Command to run via idracadm.',
    )
    parser.add_argument(
        '--user',
        default='nagios',
        help='IPMI/DRAC username',
    )
    parser.add_argument(
        '--password',
        help='IPMI/DRAC password',
    )

    return parser.parse_args()


def main():
    args = parse_args()
    func = check_hardware
    command = args.command
    if command.startswith('ipmi_'):
        func = check_ipmi
        command = command[len('ipmi_'):]
    ret, out, timeout = func(args.host, args.user, args.password, command)
    print(out)
    sys.exit(ret)


def check_hardware(host, user, password, command):
    """Run the hardware checks

    Returns a tuple (nagios status code, nagios message, if it was timeout).
    """
    try:
        res = idrac_command(host, user, password, racadm_commands[command])
    except OSError:
        out = (NagiosCodes.unknown, 'UNKNOWN: unable to run racadm.')
    else:
        try:
            if len(res):
                if res[0].find('Invalid subcommand specified.') != -1:
                    return (
                        NagiosCodes.unknown,
                        'UNKNOWN: Invalid subcommand specified to DRAC/CMC.',
                        False,
                    )
                if (
                    res[0].find('Unable to connect to RAC at specified IP address') != -1 or
                    res[0].find('Unable to login to RAC using the specified address') != -1
                ):
                    return (
                        NagiosCodes.warning,
                        'WARNING: Unable to connect to RAC!',
                        False,
                    )
            if command == 'active_errors':
                out = check_getactiveerrors(res)
            elif command == 'fans':
                out = check_fans(res)
            elif command == 'redundancy':
                out = check_redundancy(res)
            elif command == 'sensors':
                out = check_sensors(res)
            elif command == 'sel':
                out = check_racadm_sel(host, user, password, res)
            else:
                out = (
                    NagiosCodes.unknown,
                    'UNKNOWN: Invalid subcommand specified to check.',
                )
        except Exception:
            out = (
                NagiosCodes.unknown,
                'UNKNOWN: Caught exception while parsing results.\n' +
                traceback.format_exc(),
            )

    return out[0], out[1], False


def check_ipmi(host, user, password, command):
    """Run the IPMI checks

    Returns a tuple (nagios status code, nagios message, if it was timeout).
    """
    try:
        res = ipmi_command(host, user, password, ipmi_commands[command])
    except OSError:
        return (
            NagiosCodes.unknown, 'UNKNOWN: unable to run ipmitool.', False
        )

    for r1 in res:
        for r2 in r1:
            if r2.find('Insufficient privilege level') != -1:
                return (
                    NagiosCodes.ok,
                    'Ignoring check on this device because of wrong '
                    'privileges: {}'.format(r2),
                    False,
                )
            if (
                r2.find('Invalid user name') != -1 or
                r2.find('command failed') != -1
            ):
                return NagiosCodes.unknown, '{}'.format(r2), False
            if r2.find('Unable to establish IPMI') != -1:
                return NagiosCodes.unknown, '{}'.format(r2), True

    try:
        if command == 'sel':
            out = check_ipmi_sel(res)
        elif command == 'sensors':
            out = check_ipmi_sensors(res)
        else:
            out = (
                NagiosCodes.unknown,
                'UNKNOWN: Invalid subcommand specified to check.'
            )
    except Exception:
        out = (
            NagiosCodes.unknown,
            'UNKNOWN: Caught exception while parsing results.\n' +
            traceback.format_exc(),
        )

    return out[0], out[1], False


def check_getactiveerrors(res):
    """Check the response for active errors"""

    if res[0].strip() == 'There are no messages.':
        return NagiosCodes.ok, 'OK: No CMC Active Errors.'

    msgs = len(res) / 4
    errors = []
    for i in range(msgs):
        if res[i*4+1].split('=')[1].strip() == 'Information':
            continue

        errors.append('{0} - {1}'.format(
            (res[i*4].split('=')[1].strip(), res[i*4+2].split('=')[1].strip())
        ))

    if len(errors):
        return NagiosCodes.warning, 'WARNING: %s' % '; '.join(errors)

    return (
        NagiosCodes.ok,
        'OK: Only informational messages in CMC Active Errors',
    )


def check_fans(res):
    """Check the response for the fans"""
    try:
        fan_req = int(res[1].strip())
    except:
        return NagiosCodes.unknown, 'UNKNOWN: Unable to read fan information.'

    if fan_req > 70:
        return (NagiosCodes.warning, 'WARNING: Fan request: %s%%' % (fan_req))
    if fan_req > 90:
        return NagiosCodes.critical, 'CRITICAL: Fan request: %s%%' % (fan_req)
    return NagiosCodes.ok, 'OK: Fan request: %s%%' % fan_req


def check_redundancy(res):
    """Check the response for redundancy"""
    if res[0].strip() == 'Redundant':
        return NagiosCodes.ok, 'OK: BladeCenter is redundant.'
    return NagiosCodes.warning, 'WARNING: Redundancy lost! %s' % res[0].strip


def check_sensors(res):
    """Check the response for the sensors"""
    errors = []
    st_pos = 0
    for line in res:
        line = re.split('\s+', line.strip())
        st_pos = filter(lambda d: d.strip().lower() == '<status>', line)
        if not st_pos:
            continue
        st_pos = line.index(st_pos[0].strip())

        if (
            len(line) >= st_pos and
            line[st_pos].lower() not in ('ok', 'online', '<status>')
        ):
            errors.append('%s: %s' % (line[0], line[2]))

    if not len(errors):
        return (NagiosCodes.ok, 'OK: All sensors are fine')
    else:
        return (
            NagiosCodes.warning,
            'WARNING: Malfunctioned sensors: %s' % ', '.join(errors),
        )


def check_racadm_sel(host, user, password, res):
    """Check the response for the rack administration SEL"""
    if len(res):
        crit = False
        msgs = []
        head = ''
        for line in res:
            linet = line.split(' ')
            if linet[5].lower() == 'critical':
                crit = True
                head = line

            # reverse order
            msgs.insert(0, line)

        multiline = '\n'.join(msgs)[:2048]

        if head == '':
            head = msgs[0]

        if crit:
            return NagiosCodes.warning, 'WARNING: %s\n\n%s' % (head, multiline)
        else:
            return NagiosCodes.ok, 'OK: %s\n\n%s' % (head, multiline)

    # SEL seems too empty.  There should be at least message saying that it
    # was cleared.  DRACs >= 7 return no SEL at all.  Check size of SEL and
    # complain, if there is more than 1 message.
    out = idrac_command(host, user, password, 'getsel -i')
    numerrors = int(out[0].split(':')[1])

    if numerrors > 1:
        return (
            NagiosCodes.warning,
            'WARNING: SEL contains %d messages which I can not read from '
            'this version of DRAC' % (numerrors),
        )
    return NagiosCodes.ok, 'OK: SEL is truly empty'


def check_ipmi_sel(res):
    """Check the response for the IPMI SEL"""
    msgs = []
    head = ''
    for line in res:
        # Normally line is split by | symbol
        # But we don't need this detail for finding substrings.
        linestr = " ".join(line)
        if linestr.find('Log area reset/cleared') != -1:
            continue
        if linestr.find('SEL has no entries') != -1:
            continue
        if line[4].lower().find('critical') != -1 or \
           line[4].lower().find('to non-recoverable') != -1:
            head = ' '.join(line[1:])
        # Reverse order
        msgs.insert(0, ' '.join(line[1:]))

    if head == '' and msgs:
        head = msgs[0]
    multiline = '\n'.join(msgs)[:2048]

    if len(msgs):
        return(NagiosCodes.warning, 'WARNING: %s\n\n%s' % (head, multiline))
    return(NagiosCodes.ok, 'OK: SEL is empty')


def check_ipmi_sensors(res):
    """Check the reponse for IPMI sensors"""
    crit = False
    msgs = []
    for line in res:
        if line[2] not in ('ok', 'ns'):
            crit = True
            msgs.append(' '.join(line[0:]))

    if crit:
        return NagiosCodes.warning, 'WARNING: %s' % ', '.join(msgs)
    else:
        return NagiosCodes.ok, 'OK: All sensors OK'


def idrac_command(host, user, password, command):
    """Execute IDRAC command"""
    command = '/bin/idracadm -r {0} -u {1} -p {2} {3} '.format(
        host, user, password, command
    )
    command = shlex.split(command)
    (stdout, stderr) = Popen(command, stdout=PIPE, stderr=PIPE).communicate()

    res = stderr if stderr else stdout
    new_res = []
    for line in res.split("\n"):
        line = line.strip()
        if (
            line.find('Certificate is invalid') == -1 and
            line.find('Use -S option for racadm') == -1 and
            line != ''
        ):
            new_res.append(line)
    return new_res


def ipmi_command(host, user, password, command):
    """Execute IPMI command"""
    shcommand = (
        '/usr/bin/ipmitool -I lanplus -H {0} -L USER -U {1} -P {2} {3}'
        .format(host, user, password, command)
    )
    command = shlex.split(shcommand)
    (stdout, stderr) = Popen(command, stdout=PIPE, stderr=PIPE).communicate()
    res = stderr if stderr else stdout
    if res.find('0xd4 Insufficient privilege level') != -1:
        shcommand = (
            '/usr/bin/ipmitool -H {0} -L USER -U {1} -P {2} {3}'
            .format(host, user, password, command)
        )
        command = shlex.split(shcommand)
        stdout, stderr = Popen(command, stdout=PIPE, stderr=PIPE).communicate()
        res = stderr if stderr else stdout

    new_res = []
    for line in res.split("\n"):
            line_list = line.split('|')
            line_list = map(str.strip, line_list)
            if line_list != ['']:
                new_res.append(line_list)

    return new_res


if __name__ == '__main__':
    main()