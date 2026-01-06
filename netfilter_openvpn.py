"""
    This is a librarification of the commands that should add/delete
    netfilter rules for someone connecting to OpenVPN.  This applies
    iptables and ipset rules, aimed at their client IP, to prevent
    a remote user from having full reign over the local environment.

    Determination of WHAT to connect to is not this code's job.
    The iamvpnlibrary code provides that information.
"""
# vim: set noexpandtab:ts=4
# Requires:
# python-iamvpnlibrary
#
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
# The Original Code is the netfilter.py for OpenVPN learn-address.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2012
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# gdestuynder@mozilla.com (initial author)
# jvehent@mozilla.com (ipset support)
# gcox@mozilla.com (repackaging as class + LDAP extraction)
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

import os
import sys
import fcntl
import signal
import datetime
import socket
import json
import syslog
import configparser
from contextlib import contextmanager
import nftables
import iamvpnlibrary
sys.dont_write_bytecode = True


class IptablesFailure(Exception):
    """
        A named Exception to raise upon an iptables failure
    """


class IpsetFailure(Exception):
    """
        A named Exception to raise upon an ipset failure
    """


class NftablesFailure(Exception):
    ''' A named Exception to raise upon an nftables failure '''


class NetfilterOpenVPN:  # pylint: disable=too-many-instance-attributes
    """
        This class exists to make a more testable interface into the
        adding and removing of per-user ACL rules.
    """

    CONFIG_FILE_LOCATIONS = ['netfilter_openvpn.conf',
                             '/usr/local/etc/netfilter_openvpn.conf',
                             '/etc/netfilter_openvpn.conf']

    def __init__(self):
        """
            ingest the config file, then
            establish our variables based on it.
        """
        self.configfile = self._ingest_config_from_file()

        try:
            self.nf_framework = self.configfile.get(
                'openvpn-netfilter', 'framework')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.nf_framework = 'iptables'

        try:
            self.iptables_executable = self.configfile.get(
                'openvpn-netfilter', 'iptables_executable')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.iptables_executable = '/sbin/iptables'

        try:
            self.ipset_executable = self.configfile.get(
                'openvpn-netfilter', 'ipset_executable')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.ipset_executable = '/usr/sbin/ipset'

        try:
            self.nftables_table = self.configfile.get(
                'openvpn-netfilter', 'nftables_table')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.nftables_table = 'openvpn_netfilter'

        try:
            self.lockpath = self.configfile.get(
                'openvpn-netfilter', 'LOCKPATH')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.lockpath = '/var/run/openvpn_netfilter.lock'

        try:
            self.lockwaittime = self.configfile.getint(
                'openvpn-netfilter', 'LOCKWAITTIME')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.lockwaittime = 2  # this is in seconds

        try:
            self.lockretriesmax = self.configfile.getint(
                'openvpn-netfilter', 'LOCKRETRIESMAX')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.lockretriesmax = 10

        try:
            self.event_send = self.configfile.getboolean(
                'openvpn-netfilter', 'syslog-events-send')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.event_send = False

        try:
            _base_facility = self.configfile.get(
                'openvpn-netfilter', 'syslog-events-facility')
        except (configparser.NoOptionError, configparser.NoSectionError):
            _base_facility = 'auth'
        try:
            self.event_facility = getattr(syslog, f'LOG_{_base_facility.upper()}')
        except AttributeError:
            self.event_facility = syslog.LOG_AUTH

        self._lock = None
        self.username_is = None
        self.username_as = None
        self.client_ip = None
        self.iam_object = None
        if os.geteuid() != 0:
            # Since everything in this class will modify iptables/ipset,
            # this library pretty much must run as root.
            #
            # Side note:
            # Since it's called from learn-address, that means you need
            # to have a sudo allowance for the openvpn user.
            raise Exception('You must be root to use this library.')

        if self.nf_framework == 'nftables':
            self.nft = nftables.Nftables()
        else:
            self.nft = None


    def send_event(self, summary, details, severity='INFO'):
        '''
            Send an event to our syslog setting, if set
        '''
        if not self.event_send:
            return
        output_json = {
            'category': 'authentication',
            'processid': os.getpid(),
            'severity': severity,
            'processname': sys.argv[0],
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'details': details,
            'hostname': socket.getfqdn(),
            'summary': summary,
            'tags': ['vpn', 'netfilter'],
            'source': 'openvpn',
        }
        syslog_message = json.dumps(output_json)
        syslog.openlog(facility=self.event_facility)
        syslog.syslog(syslog_message)

    def _ingest_config_from_file(self):
        """
            pull in config variables from a system file
        """
        config = configparser.ConfigParser()
        for filename in self.__class__.CONFIG_FILE_LOCATIONS:
            if os.path.isfile(filename):
                try:
                    config.read(filename)
                    break
                except configparser.Error:
                    pass
        else:
            # Normally we demand there be a config, but in this case this
            # config is only for overriding otherwise-sane defaults.
            # raise IOError('Config file not found')
            pass
        return config

    def set_targets(self, username_is=None, username_as=None, client_ip=None):
        """
            Scope this object's target user/client IP.
            We don't do this in __init__ because, in testing, we want to
            get our targets from the config file.  In production,
            it could be in init, but, let's make life easy.
        """
        # username_is/username_as can be None in a delete
        self.client_ip = client_ip
        self.username_is = username_is
        self.username_as = username_is
        # Yes, '_as' is BY DEFAULT set to '_is', because sudo'ing is a rare case.
        # We will override this only after going through a gauntlet:
        if username_is and username_as:
            # ^ bypass on deletes
            self.iam_object = iamvpnlibrary.IAMVPNLibrary()
            self.username_as = self.iam_object.verify_sudo_user(username_is, username_as)

    def username_string(self):
        """ Provide a human-readable string describing the user situation """
        if not self.username_is:
            return ''
        if not self.username_as:
            return self.username_is
        if self.username_is == self.username_as:
            return self.username_is
        return f'{self.username_is}-sudoing-as-{self.username_as}'

    @contextmanager
    def _lock_timeout(self):
        """ A function to do timeouts """
        def __timeout_handler(_signum, _frame):
            """ Convert SIGALRM to Exception """
            #raise TimeoutError('SIGALRM timeout')
            raise OSError('SIGALRM timeout')

        # Save off the original signal handler for alarm, add in an exception-throwing function.
        original_handler = signal.signal(signal.SIGALRM, __timeout_handler)
        try:
            # Set an alarm for a few seconds out...
            signal.alarm(self.lockwaittime)
            # Then yield the flow here, because we want the flow to continue
            # and let things run while that alarm ticks on.
            yield
        finally:
            # If we got here, cancel the alarm...
            signal.alarm(0)
            # ... and restore any old handler.
            signal.signal(signal.SIGALRM, original_handler)

    def acquire_lock(self):
        """
            This is a time-bound means of waiting for an exclusive lock.
            Reason for doing so is down in the main() section
            Returns True if locked, False if not
        """
        acquired = False
        retries = 0
        while not acquired:
            with self._lock_timeout():
                try:
                    # Open our lockfile...
                    self._lock = open(self.lockpath, 'a+', encoding='utf-8')  # pylint: disable=consider-using-with
                    # ... and try to lock it.
                    # The encoding doesn't matter, it's just to shut pylint up
                    fcntl.flock(self._lock, fcntl.LOCK_EX)
                except (IOError, OSError):
                    # We didn't lock this time.  Don't react.
                    # We'll try again.
                    # Close out the FH we opened but couldn't lock...
                    self._lock.close()
                else:
                    acquired = True
                if retries >= self.lockretriesmax:
                    # We have given up because we've tried too long.
                    # reset _lock because we don't have one.
                    self._lock = None
                    # Tell the world we failed.
                    self.send_event(summary=('FAIL: internal netfilter issue '
                                             f'on lock acquisition of {self.lockpath}'),
                                    details={'error': 'true',
                                             'success': 'false',
                                             # There is no username here
                                            })
                    break
                retries += 1
        return acquired

    def free_lock(self):
        """
            Releases the lock that we held
        """
        fcntl.flock(self._lock, fcntl.LOCK_UN)
        self._lock.close()
        self._lock = None
        return True

    def _chain_name(self):
        """
            OK, you're looking at this and saying "WTF?"
            There is an awful name collision all through this library.
            Someone coming from a source IP of X, gets an iptables
            chain called X, and that chain jumps out to an ipset
            also called X.  But that might change someday.
            So for right now, this exists so that we can have a
            different variable scattered in the code in the right places
            to indicate whether this means the IP or the chain name.
        """
        return self.client_ip

    def iptables(self, argstr, raiseexception=True):
        """
            Load the firewall rule received as argument on the local system,
            using the iptables binary

            Return: True on success
                    Exception on error if raiseexception=True
                    False on error if raiseexception=False
        """
        command = f'{self.iptables_executable} {argstr}'
        if not raiseexception:
            command = command + ' >/dev/null 2>&1'
        # IMPROVEME: replace os.system
        status = os.system(command)
        if status == -1:
            # This would require a test case where we misset iptables
            raise IptablesFailure(f'failed to invoke iptables ({command})')
        status = os.WEXITSTATUS(status)
        if raiseexception and (status != 0):
            raise IptablesFailure(f'iptables exited with status {status} ({command})')
        if status != 0:
            return False
        return True

    def ipset(self, argstr, raiseexception=True):
        """
            Manages an IP Set using the ipset binary

            Return: True on success,
                    Exception on error if raiseexception=True
                    False on error if raiseexception=False
        """
        command = f'{self.ipset_executable} {argstr}'
        if not raiseexception:
            command = command + ' >/dev/null 2>&1'
        # IMPROVEME: replace os.system
        status = os.system(command)
        if status == -1:
            # This section covers an OS failure, this is almost
            # impossible to simulate.
            raise IpsetFailure('failed to invoke ipset ({command})')
        status = os.WEXITSTATUS(status)
        if raiseexception and (status != 0):
            raise IpsetFailure(f'ipset exited with status {status} ({command})')
        if status != 0:
            return False
        return True

    def _build_firewall_rule_iptables(self, name, usersrcip, protocol, acl):
        """
            This function will select the best way to insert the rule
            in iptables.
            If protocol and destination port are defined, create a
            simple iptables rule.
            If only a destination net is set, insert it into the user's
            ipset so as to be less unreadable in iptables.

            This function assumes that an iptable/ipset has been created
            for a rule to land into.  As such, this is intended to be an
            internal-only function.
        """
        if self.nf_framework != 'iptables':  # pragma: no cover
            raise RuntimeError('invalid call into _build_firewall_rule_iptables')
        comment = ''
        if acl.description:
            _commentstring = f'{self.username_is}:{acl.rule} ACL {acl.description}'
        if protocol and acl.portstring:
            if acl.description:
                comment = f'-m comment --comment "{_commentstring}"'
            destport = f'-m multiport --dports {acl.portstring}'
            protocol = f'-p {protocol}'
            rulestr = (f'-A {name} -s {usersrcip} -d {acl.address} '
                       f'{protocol} {destport} {comment} -j ACCEPT')
            self.iptables(rulestr)
        else:
            if acl.description:
                comment = f' comment "{_commentstring}"'
            else:
                comment = ''
            entry = f'--add {name} {acl.address}{comment}'
            self.ipset(entry)

    def _build_firewall_rule_nftables(self, name, usersrcip, protocol, acl):
        """
            This function will select the best way to insert the rule
            in nftables.
            If protocol and destination port are defined, create a
            simple rule.
            If only a destination net is set, insert it into the user's
            chain's set.

            This function assumes that a chain and set haive been created
            for a rule to land into.  As such, this is intended to be an
            internal-only function.
        """
        if self.nf_framework != 'nftables':  # pragma: no cover
            raise RuntimeError('invalid call into _build_firewall_rule_nftables')
        if protocol and acl.portstring:
            dports = [int(x) for x in acl.portstring.split(',')]
            comment = None
            if acl.description:
                comment = f'{self.username_is}:{acl.rule} ACL {acl.description}'
            rule_def = {
                'rule': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'chain': name,
                    'comment': comment,
                    'expr': [
                        { 'match': {
                            'op': '==',
                            'left': { 'payload': { 'protocol': 'ip', 'field': 'saddr' }},
                            'right': usersrcip,
                        }},
                        { 'match': {
                            'op': '==',
                            'left': { 'payload': { 'protocol': 'ip', 'field': 'daddr' }},
                            'right': str(acl.address),
                        }},
                        { 'match': {
                            'op': '==',
                            'left': { 'payload': { 'protocol': protocol, 'field': 'dport' }},
                            'right': { 'set': dports }
                        }},
                        { 'drop': None }
                    ],
                }
            }
            add_cmd = { 'nftables': [ { 'add':  rule_def } ] }
            nft_rc, _output, error = self.nft.json_cmd(add_cmd)
            if nft_rc != 0:
                # IMPROVEME: this add shouldn't fail, we should log more about it.
                raise NftablesFailure(f'rule add failed, ({error})')
        else:
            # set elements can't have comments in nftables
            if len(acl.address) == 1:
                # This is a single host.
                elem_item = [ str(acl.address.network) ]
            else:
                # This is a range.
                elem_item = [ { 'prefix': { 'addr': str(acl.address.network),
                                            'len': acl.address.prefixlen } } ]
            element_def = {
                'element': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'name': name,
                    'elem': elem_item,
                }
            }
            add_cmd = { 'nftables': [ { 'add': element_def } ] }
            nft_rc, _output, error = self.nft.json_cmd(add_cmd)
            if nft_rc != 0:
                # IMPROVEME: this add shouldn't fail, we should log more about it.
                raise NftablesFailure(f'set add failed, ({error})')

    def create_user_rules(self, user_acls):
        """
            Given the ACLs for a particular user, create the rules that will
            limit their access
            Inputs: a list of [ParsedACL, ParsedACL, ...]
            Output: None.
            Changes: box will have an iptables+ipset for the user's IP.
        """
        unique_rules_string = ';'.join(sorted({x.rule for x in user_acls}))
        # The semicolon-delimited list of rules is used by the
        # vpn-fw-find-user utility script.
        chain = self._chain_name()
        if self.nf_framework == 'iptables':
            # First thing, create empty placeholders:
            self.iptables('-N ' + chain)
            self.ipset('--create ' + chain + ' hash:net comment')
            # Now, iterate over the list, which we sort by address
            # This assumes that all of the items in user_acls are
            # accepts, and thus order won't matter.
            for acl in sorted(user_acls, key=lambda acl: acl.address):
                if bool(acl.portstring):
                    protocols = ['tcp', 'udp']
                else:
                    protocols = ['']

                for protocol in protocols:
                    self._build_firewall_rule_iptables(chain, self.client_ip,
                                                       protocol, acl)

            _commentstring = f'{self.username_is} groups: {unique_rules_string}'
            rules_comment = f'-m comment --comment "{_commentstring[:255]}"'
            username_comment = f'-m comment --comment "{self.username_is} at {self.client_ip}"'

            # Insert glue to have the user's ipset high up...
            use_ipset_rule = (f'-I {chain} -s {self.client_ip} -m set --match-set {chain} dst '
                              f'{rules_comment} -j ACCEPT')
            self.iptables(use_ipset_rule, True)
            # ... and also "accept any established connections" early on.
            # This is actually THE first, since it's an Insert after
            # another Insert.  In case that matters to you later.
            allow_established_rule = (f'-I {chain} -m conntrack --ctstate ESTABLISHED '
                                      f'{username_comment} -j ACCEPT')
            self.iptables(allow_established_rule, True)
            log_drops_rule = (f'-A {chain} {username_comment} '
                              f'-j LOG --log-prefix "DROP {self.username_is[:23]} "')
            # log-prefix needs a space at the end                                ^
            self.iptables(log_drops_rule, True)
            drop_rule = (f'-A {chain} {username_comment} '
                         '-j REJECT --reject-with icmp-admin-prohibited')
            self.iptables(drop_rule, True)
        elif self.nf_framework == 'nftables':
            self._ensure_nftables_framework()
            base_chain_def = {
                'chain': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'name': chain,
                }
            }
            base_set_def = {
                'set': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    # CAUTION: v4-only here:
                    'type': 'ipv4_addr',
                    'name': chain,
                    # flags interval means the set can contain CIDRs
                    'flags': [ 'interval' ],
                }
            }
            add_cmd = { 'nftables': [ { 'add': base_chain_def }, { 'add': base_set_def } ] }
            nft_rc, _output, error = self.nft.json_cmd(add_cmd)
            if nft_rc != 0:
                raise NftablesFailure(f'chain creation failed, ({error})')

            # Now, iterate over the list, which we sort by address
            # This assumes that all of the items in user_acls are
            # accepts, and thus order won't matter.
            for acl in sorted(user_acls, key=lambda acl: acl.address):
                if bool(acl.portstring):
                    protocols = ['tcp', 'udp']
                else:
                    protocols = ['']

                for protocol in protocols:
                    self._build_firewall_rule_nftables(chain, self.client_ip,
                                                       protocol, acl)

            # Now begins the glue.
            #
            # Note, this chain is entered twice from the forward chain.
            # 1  when client_ip is the saddr: this is the obvious case.
            # 2  when client_ip is the daddr: this is less obvious.
            #
            # Why put the user rules all in one chain?  Well.  'Housekeeping, sorta'.
            # We COULD do separate chains but that's kinda 'complexity for no reason'
            # but I could be argued off that.
            #
            # First rule: "accept any established connections" early on.  This is
            # primarily helpful for when you have an 'established' connection, so "it was okay
            # before, should still be okay" in case 1, but also when DNS replies are headed
            # back in, the 'related' kicks in on case 2.
            #
            # After that is the rule that says this client can go out to where it's allowed to.
            # That's useful for case 1 but totally useless for case 2.  But it'll get skipped
            # over quickly as not-applicable in evaluations, so, we just leave it here.
            rule_established_def = {
                'rule': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'chain': chain,
                    'comment': f'{self.username_is} at {self.client_ip}',
                    'expr': [
                        { 'match': {
                            'op': 'in',
                            'left': { 'ct': {
                                'key': 'state',
                            }},
                            'right': [
                                'established',
                                'related',
                            ],
                        }},
                        { 'accept': None }
                    ],
                }
            }
            rule_set_def = {
                'rule': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'chain': chain,
                    'expr': [
                        { 'match': {
                            'op': '==',
                            'left': { 'payload': {
                                'protocol': 'ip',
                                'field': 'saddr'
                            }},
                            'right': self.client_ip,
                        }},
                        { 'match': {
                            'op': '==',
                            'left': { 'payload': {
                                'protocol': 'ip',
                                'field': 'daddr'
                            }},
                            # 'chain' is also the name of the set:
                            'right': f'@{chain}',
                        }},
                        { 'accept': None }
                    ],
                }
            }
            rule_log_def = {
                'rule': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'chain': chain,
                    'expr': [
                        { 'log': {
                            'prefix': f'DROP {self.username_is[:23]} '
                        }},
                    ],
                }
            }
            rule_drop_def = {
                'rule': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'chain': chain,
                    'expr': [
                        { 'reject': {
                            'type': 'icmp',
                            'expr': 'admin-prohibited'
                        }},
                    ],
                }
            }
            add_cmd = { 'nftables': [ { 'add': rule_established_def },
                                      { 'add': rule_set_def },
                                      { 'add': rule_log_def },
                                      { 'add': rule_drop_def } ] }
            nft_rc, _output, error = self.nft.json_cmd(add_cmd)
            if nft_rc != 0:
                raise NftablesFailure(f'failed to add glue rules ({error})')
        else:  # pragma: no cover
            # Should be unreachable:
            raise RuntimeError('invalid self.nf_framework')

    def _ensure_nftables_framework(self):
        '''
            In iptables, we have a main table and forward chain;
            In nftables, we have to make it.  This is us laying the foundation.
            This is invoked from a couple of places to make sure we're okay.
        '''
        if self.nf_framework != 'nftables':  # pragma: no cover
            raise RuntimeError('invalid call into _ensure_nftables_framework')
        table_def = {
            'table': {
                'family': 'inet',
                'name': self.nftables_table,
            }
        }
        list_table_cmd = { 'nftables': [ { 'list': table_def } ] }
        nft_rc, _output, _error = self.nft.json_cmd(list_table_cmd)
        if nft_rc != 0:
            # Couldn't list the table.  It's probably not there.
            add_table_cmd = { 'nftables': [ { 'add': table_def } ] }
            _nft_rc, _output, _error = self.nft.json_cmd(add_table_cmd)
            # IMPROVEME: what if this is bad?
        chain_def = {
            'chain': {
                'family': 'inet',
                'table': self.nftables_table,
                'name': 'FORWARD',
                'type': 'filter',
                'hook': 'forward',
                # Just before 'filter' priority:
                'prio': -10,
                'policy': 'drop',
            }
        }
        list_chain_cmd = { 'nftables': [ { 'list': chain_def } ] }
        nft_rc, _output, _error = self.nft.json_cmd(list_chain_cmd)
        if nft_rc != 0:
            # Couldn't list the chain.  It's probably not there.
            add_chain_cmd = { 'nftables': [ { 'add': chain_def } ] }
            _nft_rc, _output, _error = self.nft.json_cmd(add_chain_cmd)
            # IMPROVEME: what if this is bad?
        return True

    def get_acls_for_user(self):
        """
            Fetch the ACLs that a user is allowed to connect to.
            Input: None (uses self.username_as)
            Return: [ParsedACL, ParsedACL, ...]
        """
        # Get the user's ACLs:
        raw_acls = self.iam_object.get_allowed_vpn_acls(self.username_as)
        # Now, sort those.  We sort low to high based on netmask and network
        # This is a little odd to follow.  It's basically doing a sort that
        # is size largest-to-smallest then, within networks of the same size,
        # doing network in numerical order.  This makes sure a /16 comes
        # before a /24, and all /16's are in readable order.
        # We do this so that we look at smaller items last, because small
        # ACLs may be subsumed by larger ones that we've already seen.
        raw_acls.sort(key=lambda x: (x.address.netmask, x.address.network))

        acls = []
        _seen_nets = []
        for acl in raw_acls:

            if acl.address.version == 4:
                pass
            elif acl.address.version == 6:
                # IMPROVEME: handle ipv6 ; silent noop for now
                continue
            else:  # pragma: no cover
                self.send_event(summary=(f'WARNING: unknown IP address, {acl.address} '
                                         f'version {acl.address.version}'),
                                details={'error': 'false',
                                         'success': 'false',
                                        })
                continue

            for _prev_acl in _seen_nets:
                if acl.address in _prev_acl:
                    # This ACL's address space is fully contained
                    # within a rule we've already permitted.
                    break
            else:
                # We have not seen this before.
                if not acl.portstring:
                    # When there's a portstring, the rule is always
                    # port specific.  So we don't assume we can do anything
                    # with it (like, you can get to blah port 80, but that
                    # has no bearing on getting to blah port 22).  But when
                    # portstring is missing, it refers to the whole IP range.
                    # We add this address to our list, because it means that
                    # future users who want to use this network already have
                    # a rule to handle it.
                    _seen_nets.append(acl.address)
                # and at this point, append the acl to our list of things
                # acls to pass upstream
                acls.append(acl)

        return acls

    def chain_exists(self):
        """
            Test existance of 'a chain' in the vague sense,
            as there are cases of botched/partial cleanup
        """
        if self.nf_framework == 'iptables':
            return self.chain_exists_iptables() or self.chain_exists_ipset()
        if self.nf_framework == 'nftables':
            return self.chain_exists_nftables()
        # Should be unreachable:
        raise RuntimeError('invalid self.nf_framework')  # pragma: no cover

    def chain_exists_iptables(self):
        """
            Test existance of a chain via the iptables binary
        """
        chain = self._chain_name()
        return self.iptables('-L ' + chain, False)

    def chain_exists_ipset(self):
        """
            Test existance of a chain via the ipset binary
        """
        chain = self._chain_name()
        return self.ipset('list ' + chain, False)

    def chain_exists_nftables(self):
        ''' Test existance of a chain via the iptables library '''
        chain = self._chain_name()
        chain_def = {
            'chain': {
                'family': 'inet',
                'table': self.nftables_table,
                'name': chain,
            }
        }
        list_cmd = { 'nftables': [ { 'list': chain_def } ] }
        nft_rc, _output, _error = self.nft.json_cmd(list_cmd)
        if nft_rc == 0:
            return True
        return False

    def add_safety_block(self):
        """
            This function adds an iptables block against the vpn IP.

            caution: overload of the word 'block'.
            The script that the VPN calls puts in an iptables forwarding
            block upon add/update.  This is done because we want the script
            that is blocking openvpn to finish FAST, but we don't want any
            traffic flowing until the (much-slower-to-generate) IAM rules are
            put in place (OR it fails, whichever may be the case)

            That script blocks the incoming IP and forks to do the real work
            so that openvpn doesn't block.  But we don't know if the operation
            will succeed yet, so it doesnt allow traffic just to be safe.
            This function drops the blocked traffic.  Make sure this func
            is THE EXACT OPPOSITE of the delete below
        """
        # If this fails, we will raise, because something
        # is severely messed up.
        if self.nf_framework == 'iptables':
            return self.iptables(f'-I FORWARD -s {self.client_ip} -j DROP')
        if self.nf_framework == 'nftables':
            self._ensure_nftables_framework()
            rule_def = {
                'rule': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'chain': 'FORWARD',
                    'expr': [
                        { 'match': {
                            'op': '==',
                            'left': { 'payload': {
                                'protocol': 'ip',
                                'field': 'saddr'
                            }},
                            'right': self.client_ip,
                        }},
                        { 'drop': None }
                    ],
                }
            }
            add_cmd = { 'nftables': [ { 'add': rule_def } ] }
            nft_rc, _output, error = self.nft.json_cmd(add_cmd)
            if nft_rc == 0:
                return True
            raise NftablesFailure(f'failed to add safety block ({error})')
        # Should be unreachable:
        raise RuntimeError('invalid self.nf_framework')  # pragma: no cover

    def remove_safety_block(self):
        """
            This function removes the iptables block against the vpn IP.
        """
        if self.nf_framework == 'iptables':
            try:
                if self.iptables(f'-C FORWARD -s {self.client_ip} -j DROP', False):
                    # If there was nothing there, there's nothing to do.
                    # This function can be called when there is or is not
                    # a block in place, so, only complain if there was one
                    # which we could not delete.
                    self.iptables(f'-D FORWARD -s {self.client_ip} -j DROP >/dev/null 2>&1', True)
                return True
            except IptablesFailure:
                # This is an almost-impossible exception to throw, as it would be
                # a 'we saw it but couldn't delete it' situation.
                self.send_event(summary=('FAIL: did not delete blocking rule, '
                                         'potential security issue'),
                                details={'error': 'true',
                                         'success': 'false',
                                         'vpnip': self.client_ip,
                                         'username': self.username_is,
                                        },
                                severity='CRITICAL',)
                return False
        if self.nf_framework == 'nftables':
            # Someday we'll be able to delete by reference.
            #rule_def = {
            #    'rule': {
            #        'family': 'inet',
            #        'table': self.nftables_table,
            #        'chain': 'FORWARD',
            #        'expr': [
            #            { 'match': {
            #                'op': '==',
            #                'left': { 'payload': {
            #                    'protocol': 'ip',
            #                    'field': 'saddr'
            #                }},
            #                'right': self.client_ip,
            #            }},
            #            { 'drop': None }
            #        ],
            #    }
            #}
            # Til then, we have to look up the rules:
            chain_holder_def = {
                'chain': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'name': 'FORWARD',
                }
            }
            list_cmd = { 'nftables': [ { 'list': chain_holder_def } ] }
            nft_rc, output, error = self.nft.json_cmd(list_cmd)
            if nft_rc != 0:
                # If you don't get any rules back from the FORWARD chain, you
                # kinda have to assume everything is busted.  I mean, this is not
                # a complex search here that should ever fail.  So you're into
                # edge cases like "out of memory" or "all of the table got deleted
                # by a rogue actor.  At that point everything is suspect so even
                # though we're aborting early and not looking for the user's
                # chain+set, we're already so busted it's not tenable.
                raise NftablesFailure(f'failed to list safety block ({error})')
            expr_def = [
                { 'match': {
                    'op': '==',
                    'left': { 'payload': {
                        'protocol': 'ip',
                        'field': 'saddr'
                    }},
                    'right': self.client_ip,
                }},
                { 'drop': None }
            ]
            delete_def = None
            for chain_obj in output['nftables']:
                rule = chain_obj.get('rule')
                if not rule:
                    continue
                expr = rule.get('expr')
                if (not expr) or (expr != expr_def):
                    # "peephole" optimization breaks coverage tests if we don't put in a dummy
                    # instruction here, unfixable bug in py: http://bugs.python.org/issue2506
                    _x = 1
                    continue
                delete_def = {
                    'rule': {
                        'family': rule['family'],
                        'table': rule['table'],
                        'chain': rule['chain'],
                        'handle': rule['handle'],
                    }
                }
                break
            else:
                # Couldn't find a rule to delete, must not be one?
                return True
            delete_cmd = { 'nftables': [ { 'delete': delete_def } ] }
            nft_rc, _output, error = self.nft.json_cmd(delete_cmd)
            if nft_rc != 0:
                raise NftablesFailure(f'failed to delete safety block ({error})')
            return True
        # Should be unreachable:
        raise RuntimeError('invalid self.nf_framework')  # pragma: no cover

    def add_chain(self):
        """
            Create a custom chain for the VPN user, named based around
            their source IP.
            Load the VPN ACL rules into the custom chain
            Jump traffic to the custom chain from the
            INPUT, OUTPUT & FORWARD chains
        """
        if self.chain_exists():
            # This is a dubious little section of code.
            # In reality, you should never get here.  It means someone is
            # trying to create a user chain, for a chain that already exists.
            #
            # So, NOW what?
            # OBVIOUSLY we need to take extraordinary measures here.
            # we don't want new rules in the preexisting chain to come
            # along and ruin a legit session.
            # But really, we shouldn't be here in the first place.  openvpn
            # shouldn't be handing out an IP it hasn't reclaimed through
            # keepalive.  So that we're here means something is wrong,
            # probably a blowup in testing.  But, speculation: likely we
            # have a chain that got brought up on boot.
            #
            # We can't append to / edit the existing rules.  That's right
            # out.  That leaves us with two awful options:
            #
            # * leave the rules in place.  If, by some slim chance, the
            # existing chain belongs to a legit user and this is a hack
            # attempt, this would be the right call, as it prevents a hack
            # causing a DoS of kicking off a legit user.  However, if it
            # is a mistake / abandoned rule, it would block a new connection
            # every time it were attempted.
            # There's an assumption here that anyone in a position to do
            # a malicious hack can do SO much worse that I can't care about
            # this edge case, and as such, we don't choose this route.
            # Instead we...
            #
            # * kill the rules.  If the chain is abandoned, nothing is going
            # to ever clean it up except someone finding the bad setup.  And
            # to date, nobody ever has, which means this is a thin case and
            # nobody looks for it.  Log that this happened and then wipe it.
            self.send_event(summary='FAIL: Collision of adding a VPN ACL',
                            details={'error': 'true',
                                     'success': 'false',
                                     'vpnip': self.client_ip,
                                     'username': self.username_is,
                                    },
                            severity='WARNING',)
            self.del_chain()
            # having now wiped the chain, check again:
            if self.chain_exists():
                # It didn't delete.  Severe problem.
                # This is almost impossible to test, as it means we
                # tried to delete a chain, but it couldn't be deleted.
                self.send_event(summary='FAIL: Undeletable VPN ACL',
                                details={'error': 'true',
                                         'success': 'false',
                                         'vpnip': self.client_ip,
                                         'username': self.username_is,
                                        },
                                severity='ERROR',)
                return False
            # We cleaned the chain out, proceed with a new add.
        user_acls = self.get_acls_for_user()
        self.create_user_rules(user_acls)
        # At this point, a chain and set for usersrcip are now in place.
        # This function continues on to tie them to the OS:

        chain = self._chain_name()
        if self.nf_framework == 'iptables':
            self.iptables(f'-A OUTPUT -d {self.client_ip} -j {chain}', True)
            self.iptables(f'-A INPUT -s {self.client_ip} -j {chain}', True)
            self.iptables(f'-A FORWARD -s {self.client_ip} -j {chain}', True)
            # fallthrough
        elif self.nf_framework == 'nftables':
            rule_out_def = {
                'rule': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'chain': 'FORWARD',
                    'expr': [
                        { 'match': {
                            'op': '==',
                            'left': { 'payload': {
                                'protocol': 'ip',
                                'field': 'saddr'
                            }},
                            'right': self.client_ip,
                        }},
                        { 'jump': { 'target': chain } }
                    ],
                }
            }
            rule_in_def = {
                'rule': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'chain': 'FORWARD',
                    'expr': [
                        { 'match': {
                            'op': '==',
                            'left': { 'payload': {
                                'protocol': 'ip',
                                'field': 'daddr'
                            }},
                            'right': self.client_ip,
                        }},
                        { 'jump': { 'target': chain } }
                    ],
                }
            }
            add_cmd = { 'nftables': [ { 'add': rule_out_def }, { 'add': rule_in_def } ] }
            nft_rc, _output, error = self.nft.json_cmd(add_cmd)
            if nft_rc != 0:
                raise NftablesFailure(f'failed to add chaining rules: ({error})')
            # fallthrough
        else:  # pragma: no cover
            # Should be unreachable:
            raise RuntimeError('invalid self.nf_framework')
        self.remove_safety_block()
        return True

    def del_chain(self):
        """
            Delete the custom chain and all associated rules

            We have to clean up the linking rules from add_chain
            as well as the user items from create_user_rules
        """
        chain = self._chain_name()
        if self.nf_framework == 'iptables':
            self.iptables(f'-D OUTPUT -d {self.client_ip} -j {chain}', False)
            self.iptables(f'-D INPUT -s {self.client_ip} -j {chain}', False)
            self.iptables(f'-D FORWARD -s {self.client_ip} -j {chain}', False)
            self.iptables(f'-F {chain}', False)
            self.iptables(f'-X {chain}', False)
            self.ipset(f'--destroy {chain}', False)
        elif self.nf_framework == 'nftables':
            # We can get rid of the user's chain and set by name,
            # But we have to get the FORWARD rules by handle.

            # First thing, let's look up and remove the 'FORWARD' rules.

            chain_holder_def = {
                'chain': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'name': 'FORWARD',
                }
            }
            list_cmd = { 'nftables': [ { 'list': chain_holder_def } ] }
            nft_rc, output, error = self.nft.json_cmd(list_cmd)
            if nft_rc != 0:
                # If you don't get any rules back from the FORWARD chain, you
                # kinda have to assume everything is busted.  I mean, this is not
                # a complex search here that should ever fail.  So you're into
                # edge cases like "out of memory" or "all of the table got deleted
                # by a rogue actor.  At that point everything is suspect so even
                # though we're aborting early and not looking for the user's
                # chain+set, we're already so busted it's not tenable.
                raise NftablesFailure(f'failed to list FORWARD ({error})')
            delete_defs = []

            expr_out_def = [
                { 'match': {
                    'op': '==',
                    'left': { 'payload': {
                        'protocol': 'ip',
                        'field': 'saddr'
                    }},
                    'right': self.client_ip,
                }},
                { 'jump': { 'target': chain } }
            ]
            expr_in_def = [
                { 'match': {
                    'op': '==',
                    'left': { 'payload': {
                        'protocol': 'ip',
                        'field': 'daddr'
                    }},
                    'right': self.client_ip,
                }},
                { 'jump': { 'target': chain } }
            ]
            for chain_obj in output['nftables']:
                rule = chain_obj.get('rule')
                if not rule:
                    continue
                expr = rule.get('expr')
                if (not expr) or (expr not in (expr_out_def, expr_in_def)):
                    # "peephole" optimization breaks coverage tests if we don't put in a dummy
                    # instruction here, unfixable bug in py: http://bugs.python.org/issue2506
                    _x = 1
                    continue
                delete_defs.append({
                    'rule': {
                        'family': rule['family'],
                        'table': rule['table'],
                        'chain': rule['chain'],
                        'handle': rule['handle'],
                    }
                })
            # Here's a fallthrough.  We could've matched nothing.  That would be unusual,
            # but if there's nothing to delete, then there's nothing to delete.
            for delete_def in delete_defs:
                del_cmd = { 'nftables': [ { 'delete': delete_def } ] }
                _nft_rc, _output, _error = self.nft.json_cmd(del_cmd)
                # IMPROVEME

            # After those two rules are gone, we can do the delete of the user's
            # chain and set by name.

            base_chain_def = {
                'chain': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    'name': chain,
                }
            }
            base_set_def = {
                'set': {
                    'family': 'inet',
                    'table': self.nftables_table,
                    # CAUTION: v4-only here:
                    'type': 'ipv4_addr',
                    'name': chain,
                }
            }
            del_cmd = { 'nftables': [ { 'delete': base_chain_def },
                                      { 'delete': base_set_def } ] }
            _nft_rc, _output, _error = self.nft.json_cmd(del_cmd)
            # We don't check the output here; these 'just work'
        else:  # pragma: no cover
            # Should be unreachable:
            raise RuntimeError('invalid self.nf_framework')
        return True

    def update_chain(self):
        """
            Wrapper function around add and delete
        """
        self.del_chain()
        return self.add_chain()
