#! /usr/bin/env python
# pylint: disable=invalid-name
# This is a script, not a module
"""
    Script to execute the delete_chain function and remove leftover
    rule debris as needed.
"""
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the vpn-netfilter-clean-ip.sh for OpenVPN Netfilter.py
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2012
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# gcox@mozilla.com
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.

import sys
import netfilter_openvpn
sys.dont_write_bytecode = True


def main():
    """
        A scripting failure can leave behind debris.
        This script aims to help clean up after accidents in testing.
        Uses the locking mechanism of the library, so should be safe
        to use even on a production system.
    """
    _usage = ('USAGE: {program} user_ip\n'
              'find the firewall rules for a '
              'specific VPN IP and delete them all')
    if len(sys.argv) < 2:
        print(_usage.format(program=sys.argv[0]))
        return False
    userip = sys.argv[1]

    nf_object = netfilter_openvpn.NetfilterOpenVPN()
    nf_object.set_targets(client_ip=userip)

    if not nf_object.acquire_lock():
        # never obtained a lock, get out
        return False

    chain_work_status = nf_object.del_chain()

    nf_object.free_lock()
    return chain_work_status

if __name__ == "__main__":
    if main():
        sys.exit(0)
    else:
        sys.exit(1)
