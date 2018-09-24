openvpn-netfilter
=================

Per-VPN-user network ACLs using Netfilter and OpenVPN.

Setup
=====

There are effectively two packages to this repo.
* python-openvpn-netfilter - a python library that does all of the filtering
* openvpn-netfilter - a series of scripts and configurations to allow integration with openvpn.

openvpn integration:
.. code::

   learn-address /usr/lib/openvpn/plugins/netfilter_openvpn.sh

This shell wrapper makes a sudo call to one of the scripts, ```netfilter_openvpn_sync.py```
While these scripts are fast, there are calls to IAM systems that may hang, and that would be felt by all VPN users.
To minimize that impact, the synchronous script blocks all connections from the client IP, forks a call to ```netfilter_openvpn_async.py```, and returns control to openvpn.
The forked ```netfilter_openvpn_async.py``` then finishes the rule setup.

Change the settings in /etc/netfilter_openvpn.conf if needed.
Make sure that the paths of the 'iptables' and 'ipset' are correct for your OS.  Somewhat-conventional defaults are present without a config.

Obviously this filtering depends on having proper client routes for the network/IPs you allow, so consider the routes.

Script logic
============

learn-address is an OpenVPN hook called when the remote client is allocated an IP address by the VPN server side.  Given the user and now-allocated client IP, we load the netfilter (iptables/ipset) rules for that user and apply them to that client IP address.

If the script fails for any reason, OpenVPN will deny packets to come through.

When a user successfully connects to OpenVPN, netfilter.py will create a set for firewall rules for this user.
The custom rules are added into a new chain named after the VPN IP of the user.

.. code::

    Chain 172.16.248.50 (3 references)
     pkts bytes target     prot opt in     out     source               destination
     5925  854K ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           ctstate ESTABLISHED /* ulfr at 172.16.248.50 */
      688 46972 ACCEPT     all  --  *      *       172.16.248.50        0.0.0.0/0           match-set 172.16.248.50 dst /* ulfr groups: vpn_caribou;vpn_pokemon;vpn_ninjas; */
       24  2016 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0           /* ulfr at 172.16.248.50 */ LOG flags 0 level 4 prefix `DROP 172.16.248.50'
       24  2016 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0           /* ulfr at 172.16.248.50 */


A jump target is added to INPUT, OUTPUT and FORWARD to send all traffic originating from the VPN IP to the custom chain:

.. code::

    Chain INPUT (policy ACCEPT 92762 packets, 15M bytes)
     3320  264K 172.16.248.50  all  --  *      *       172.16.248.50         0.0.0.0/0
    Chain OUTPUT (policy ACCEPT 136K packets, 138M bytes)
     2196  549K 172.16.248.50  all  --  *      *       0.0.0.0/0            172.16.248.50
    Chain FORWARD (policy ACCEPT 126K packets, 127M bytes)
     1120 90205 172.16.248.50  all  --  *      *       172.16.248.50         0.0.0.0/0


You'll notice the comments are there for ease of troubleshooting, you can grep through "iptables -L -n" and find out which user or group has access to what easily.

To reduce the amount of rules created, when a user ACL only contains a list of destination subnets (no ports), these subnets are added into an IPSet.  The IPSet is named after the VPN IP of the user.

.. code::

    --- IPSET HASH TABLE ---
    Name: 172.16.248.50
    Type: hash:net
    Header: family inet hashsize 1024 maxelem 65536
    Size in memory: 17968
    References: 1
    Members:
    172.39.72.0/24
    172.31.0.0/16
    172.11.92.150
    42.89.217.202

Maintenance
===========
You can list the rules and sets of a particular user with the script named 'vpn-fw-find-user.sh'.

You can delete all of the rules and sets of a given VPN IP using the script named 'vpn-netfilter-cleanup-ip.py'.

Updates
=======

The async script may be invoked by hand to refresh a user's rules while they are still connected / so they do not have to reconnect to the VPN

.. code::

       netfilter_openvpn_async.py update 172.16.248.50 ulfr
