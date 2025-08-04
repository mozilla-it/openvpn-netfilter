#!/bin/bash
# This is a simple sudo wrapper for the synchronous part of the learn script.
# This avoids us putting a sudo into the VPN config directly.
#
# This is required so that we can escalate to root and do OS-level activities.
SUDO=/usr/bin/sudo

${SUDO} /usr/lib/openvpn/plugins/netfilter_openvpn_sync.py "$@"
exit $?
