#!/usr/bin/env python
"""
    This script is invoked 'by openvpn' to apply rules upon add/delete
    of a VPN client.
    There are quotes there because this file is INTENDED to be called
    not by openvpn itself, but by a helper script.

    Because we make network calls in most of netfilter_openvpn, querying
    subsystems about user access, and because openvpn does not have a
    forking model/deferred plugin setup for all of its plugin calls,
    this script should be called from a forking synchronous script.

    If not, any lag caused by this script would be felt by every user
    of the VPN.
"""
import os
import sys
import netfilter_openvpn
sys.dont_write_bytecode = True


def main():
    """
        The main function, here we pick up variables from interfacing
        with openvpn itself.
    """
    _usage = 'USAGE: {program} [add|update|delete] address [common_name]'
    #
    # untrusted_ip comes from openvpn itself and is the public IP of the
    # client who is connecting to us is coming from.
    # This is used for logging only, and is not present on 'delete'.
    client_public_ip = os.environ.get('untrusted_ip', '127.0.0.1')
    #
    # untrusted_port comes from openvpn itself and is the port that the
    # client who is connecting to us is coming from.
    # This is used for logging only, and is not present on 'delete'.
    client_port = os.environ.get('untrusted_port', '0')

    if len(sys.argv) < 3:
        print(_usage.format(program=sys.argv[0]))
        return False
    operation = sys.argv[1]
    client_private_ip = sys.argv[2]
    # client_private_ip is the IP that the client will be assigned after
    # all of this is said and done.

    if operation == 'add' or operation == 'update':
        usercn = sys.argv[3]
    else:
        usercn = None

    # Create the object.  Note that there's a "must be root"
    # enforcer in the object initializer.
    nf_object = netfilter_openvpn.NetfilterOpenVPN()
    nf_object.set_targets(user=usercn, client_ip=client_private_ip)

    # This script is forked off from the openvpn process, and as such,
    # multiple copies of this script may be in flight at any one time.
    # They're all going to be "taking a while" to query IAM or get their
    # turn to make edits, and those edits are shell calls out to the
    # iptables and ipset executables.  There's a slim chance that we
    # could see someone connect+disconnect, and that would lead to a
    # case of script A being in the middle of bringup, and B doing
    # takedown.  So we put a lock around this section of main (which,
    # let's be honest, means 'the whole script is locked') because
    # we want each execution (multiple changes to iptables and ipset)
    # to run to completion without races with other instances of this.
    #
    # This is far from perfect.  human interference and/or system
    # management (puppet, ansible) would not respect our lock.  But
    # in theory they shouldn't be doing anything to our chains anyway.
    #
    if not nf_object.acquire_lock():
        # never obtained a lock, get out
        return False
    _log = nf_object.logger

    if operation == 'add':
        _log.summary = ('SUCCESS: VPN netfilter add upon connection for '
                        '{}'.format(usercn))
        _log.details = {'sourceipaddress': client_public_ip,
                        'sourceport': client_port,
                        'vpnip': client_private_ip,
                        'username': usercn,
                        'success': 'true'}
        _log.send()
        chain_work_status = nf_object.add_chain()
    elif operation == 'update':
        _log.summary = ('SUCCESS: VPN netfilter add upon reconnection for '
                        '{}'.format(usercn))
        _log.details = {'sourceipaddress': client_public_ip,
                        'sourceport': client_port,
                        'vpnip': client_private_ip,
                        'username': usercn,
                        'success': 'true'}
        _log.send()
        chain_work_status = nf_object.update_chain()
    elif operation == 'delete':
        # There is no username here.
        # One could be found from the chain before we delete it if we care.
        _log.summary = ('SUCCESS: VPN netfilter deletes upon disconnect')
        _log.details = {'vpnip': client_private_ip,
                        'success': 'true'}
        _log.send()
        chain_work_status = nf_object.del_chain()
    else:
        # There is no username here.
        _log.summary = ('FAIL: VPN netfilter failure due to'
                        'unknown operation "{}"'.format(operation))
        _log.details = {'error': 'true',
                        'success': 'false'}
        _log.send()
        chain_work_status = False

    if nf_object.log_to_stdout:
        print _log.syslog_convert()

    # Print to stdout here because we want a local copy of the results.
    # We could log to syslog, but that separates our files from the
    # openvpn log to syslog.
    nf_object.free_lock()
    return chain_work_status


if __name__ == "__main__":
    if main():
        sys.exit(0)
    else:
        sys.exit(1)
