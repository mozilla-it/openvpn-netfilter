#!/usr/bin/env python
"""
    This script is invoked by openvpn 'to apply rules upon add/delete
    of a VPN client.'
    There are quotes there because this file is INTENDED to be called
    by openvpn itself, but doesn't actually apply the rules.

    Because we make network calls in most of netfilter_openvpn, querying
    subsystems about user access, and because openvpn does not have a
    forking model/deferred plugin setup for all of its plugin calls,
    this script is synchronous with openvpn and seeks to exit fast,
    doing a minimum of work.

    If not, any lag caused by this script would be felt by every user
    of the VPN.

    This script puts a safety block in place, then fork/execs a new
    call to the heavy-lifting async script.
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
    #client_public_ip = os.environ.get('untrusted_ip', '127.0.0.1')
    #
    # untrusted_port comes from openvpn itself and is the port that the
    # client who is connecting to us is coming from.
    # This is used for logging only, and is not present on 'delete'.
    #client_port = os.environ.get('untrusted_port', '0')

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

    if operation == 'add':
        nf_object.add_safety_block()
    elif operation == 'update':
        nf_object.add_safety_block()
    elif operation == 'delete':
        nf_object.remove_safety_block()
    else:
        return False

    # The block is in place synchronous with openvpn.  At this point,
    # the parent is going to do nothing else but fork a child to do
    # the heavy lifting.  The parent needs to gracefully exit back.

    try:
        pid = os.fork()
    except OSError:
        exit("Could not create a child process")

    if pid:
        # This is the parent.
        # The parent just needs to bail out.
        return True
    else:
        # This is the child.
        # This should exec away.
        # IMPROVEME - hardcoded script.
        os.execve('/usr/lib/openvpn/plugins/netfilter_openvpn_async.py',
                  sys.argv, os.environ)
        # We should never get here:
        return False


if __name__ == "__main__":
    if main():
        sys.exit(0)
    else:
        sys.exit(1)
