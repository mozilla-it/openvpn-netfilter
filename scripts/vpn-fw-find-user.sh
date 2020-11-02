#! /usr/bin/env bash
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
# The Original Code is the vpn-fw-find-user.sh for the OpenVPN Netfilter plugin
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2012
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# jvehent@mozilla.com (ulfr)
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
if [ -z "$1" ]; then
    echo "usage: $0 <user cn>"
    echo "search for a vpn user that matches the input, and display all firewall rules"
    exit 1
fi
usercn=$1
useriplist=$(iptables -L -v -n | grep "$usercn" | grep match-set | awk '{print $11}')
groupslist=$(iptables -L -v -n | grep "$usercn" | grep match-set | awk '{print $16}' | tr ";" "\\n")
# FIXME grab not by number?

for userip in $useriplist; do
    echo -e "\\n--- $usercn has IP $userip ---"
    echo -e "ldap groups:\\n$(for g in $groupslist; do echo "- $g";done)"
    echo -e "\\n--- IPTABLES RULES ---"
    for chain in INPUT OUTPUT FORWARD; do
        iptables -L $chain -v -n | grep -E "Chain $chain|$userip"
    done
    iptables -L "$userip" -v -n
    echo
    echo -e "\\n--- IPSET HASH TABLE ---"
    ipset -s --list "$userip"
    echo -e "--- end of $usercn $userip ---\\n\\n"
done
