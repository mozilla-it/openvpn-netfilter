# This is so openvpn can call the main python script with enough permissions
# to do iptables efforts within it.
openvpn           ALL=NOPASSWD: /usr/lib/openvpn/plugins/netfilter_openvpn_async.py
# This is for the sync script to do initial quick lockdowns via iptables.
openvpn           ALL=NOPASSWD: /usr/lib/openvpn/plugins/netfilter_openvpn_sync.py
