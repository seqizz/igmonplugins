#!/usr/bin/env python
import json
import subprocess

def main():
    debug = False
    lbpools = get_lbpools()
    pfctl_output, err = subprocess.Popen(['sudo', 'pfctl', '-vsr'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    send_msg = ''
    if debug:
        separator = "\n"
    else:
        separator = "\27"

    for nagios_service in ['check_states_lbpool_4', 'check_states_lbpool_6']:
        send_msg += check_states(lbpools, pfctl_output, nagios_service, separator)

    if debug:
        print send_msg
    else:
        for monitor in ('af-monitor.admin', 'aw-monitor'):
            nsca = subprocess.Popen(
                [
                    '/usr/local/sbin/send_nsca',
                    '-H', '{}.ig.local.'.format(monitor),
                    '-to', '20',
                    '-c', '/usr/local/etc/nagios/send_nsca.cfg',
                ],
                stdin=subprocess.PIPE,
            )
            nsca.communicate(send_msg)

def get_lbpools():
    with open('/etc/iglb/iglb.json') as jsonfile:
        lbpools_obj = json.load(jsonfile)['lbpools']
    return lbpools_obj

def get_allow_from_acls(lb_params):
    # The allow_from field of every lbpool has a number of acl objects with each having its own dedicated state_limit
    ret = {}
    for acl_name, acl_params in lb_params['allow_from'].items():
        ret.update({
            acl_name: acl_params['acls'][-1].strip("acl_ipaddr_dns")
        })
    return ret


def compare_states(line, output_pfctl_list, index, lb_params, allow_from, nagios_service, exit_code):
    cur_protocol = line.split('::')[-2].split(":")[-1]
    cur_port = line.split('::')[-1].strip('"')
    cur_states = output_pfctl_list[(index + 1)].strip('[] ', ).split('States:')[1].strip()
    status = ''
    ret = ' '
    if cur_protocol in line:
        if cur_port in line:
            if not lb_params['state_limit']:
                lb_params['state_limit'] == 1200000

            if int(cur_states) >= (int(lb_params['state_limit']) * 0.85):
                exit_code = 2
            elif int(cur_states) >= (int(lb_params['state_limit']) * 0.70):
                if exit_code != 2: # If already critical, then don't make it warning by other ports/acls
                    exit_code = 1
            elif int(cur_states) < int(lb_params['state_limit'] * 0.70):
                if exit_code not in [1, 2]: # If already critical/warning, then don't make it ok by other ports/acls
                    exit_code = 0

            # To bind the ports to their acl objects, every port has state_limit set separately for each
            # acl object in allow_from attribute
            for acl_name, acl_object_id in allow_from.items():
                if acl_object_id in line:
                    status += '{} Port {} = {}, '.format(acl_name, cur_port, cur_states)
            ret += status
    return ret, exit_code


def check_states(lbpools, pfctl_output, nagios_service, separator):
    msg = ''
    for lbpool, lb_params in lbpools.items():
        status_changed = False
        statuses = 'States: '
        exit_code = None
        output_pfctl_list = pfctl_output.splitlines()
        allow_from = get_allow_from_acls(lb_params)

        for line in output_pfctl_list:
            indx = output_pfctl_list.index(line)
            if lb_params['pf_label'] in line and not ('dns' in line):
                if 'inet6' not in line and nagios_service == 'check_states_lbpool_4':
                    cmp_out, exit_code = compare_states(line, output_pfctl_list, indx, lb_params, allow_from, nagios_service, exit_code)
                    statuses += cmp_out
                    status_changed = True
                elif 'inet6' in line and nagios_service == 'check_states_lbpool_6':
                    cmp_out, exit_code = compare_states(line, output_pfctl_list, indx, lb_params, allow_from, nagios_service, exit_code)
                    statuses += cmp_out
                    status_changed = True

        if status_changed:
            if exit_code == 0:
                statuses = 'Everything is ok | {}'.format(statuses)
            elif exit_code == 1:
                statuses = 'State limit is reaching 85% | {}'.format(statuses)
            elif exit_code == 2:
                statuses = 'State limit has reached 85% | {}'.format(statuses)

            msg += ('{}\t{}\t{}\t{}{}').format(lbpool, nagios_service, exit_code, statuses, separator)
    return msg

if __name__ == "__main__":
    main()