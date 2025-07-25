#
# Preserve the untrusted_ip and untrusted_port variables so that the
# netfilter scripts have access to them for reporting purposes.
# username is passed in as the pathway to 'sudo' within the VPN.
Defaults:openvpn  env_keep += "untrusted_ip untrusted_port username"
#
# This is so openvpn can call the main python script with enough permissions
# to call system-binary for OS-level changes.
openvpn           ALL=NOPASSWD: /usr/lib/openvpn/plugins/netfilter_openvpn_async.py
# This is for the sync script to do initial quick lockdowns.
openvpn           ALL=NOPASSWD: /usr/lib/openvpn/plugins/netfilter_openvpn_sync.py
