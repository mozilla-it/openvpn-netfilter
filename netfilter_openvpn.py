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
# python-mozdef_client_config
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
from contextlib import contextmanager
import iamvpnlibrary
import mozdef_client_config
from six.moves import configparser
sys.dont_write_bytecode = True


class IptablesFailure(Exception):
    """
        A named Exception to raise upon an iptables failure
    """


class IpsetFailure(Exception):
    """
        A named Exception to raise upon an ipset failure
    """


class NetfilterOpenVPN(object):  # pylint: disable=too-many-instance-attributes
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
            self.log_to_stdout = self.configfile.getboolean(
                'openvpn-netfilter', 'log_to_stdout')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.log_to_stdout = True

        self._lock = None
        self.username_is = None
        self.username_as = None
        self.client_ip = None
        self.iam_object = None
        self.logger = mozdef_client_config.ConfigedMozDefEvent()
        # While 'authorization' might seem more correct (we are layering
        # access upon a user after they have been authenticated), we are
        # asked to put all login-related info under the category of
        # 'authentication'.  So, don't change this without an EIS consult.
        self.logger.category = 'authentication'
        self.logger.source = 'openvpn'
        self.logger.tags = ['vpn', 'netfilter']
        if os.geteuid() != 0:
            # Since everything in this class will modify iptables/ipset,
            # this library pretty much must run as root.
            #
            # Side note:
            # Since it's called from learn-address, that means you need
            # to have a sudo allowance for the openvpn user.
            raise Exception('You must be root to use this library.')

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
                except (configparser.Error):
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
        return '{user_is}-sudoing-as-{user_as}'.format(user_is=self.username_is,
                                                       user_as=self.username_as)

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
                    self._lock = open(self.lockpath, 'a+')
                    # ... and try to lock it.
                    fcntl.flock(self._lock, fcntl.LOCK_EX)
                except (IOError, OSError):
                    # We didn't lock this time.  Don't react.
                    # We'll try again.
                    pass
                else:
                    acquired = True
                if retries >= self.lockretriesmax:
                    # We have given up because we've tried too long.
                    # reset _lock because we don't have one.
                    self._lock = None
                    # Tell the world we failed.
                    self.logger.summary = ('FAIL: internal netfilter issue '
                                           'on lock acquisition '
                                           'of {}'.format(self.lockpath))
                    self.logger.details = {
                        # There is no username here
                        'error': 'true',
                        'success': 'false', }
                    self.logger.send()
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
        command = '{program} {arg}'.format(
            program=self.iptables_executable, arg=argstr)
        if not raiseexception:
            command = command + ' >/dev/null 2>&1'
        # IMPROVEME: replace os.system
        status = os.system(command)
        if status == -1:
            # This would require a test case where we misset iptables
            raise IptablesFailure(
                'failed to invoke iptables ({c})'.format(c=command))
        status = os.WEXITSTATUS(status)
        if raiseexception and (status != 0):
            raise IptablesFailure(
                'iptables exited with status {status} ({c})'.format(
                    status=status, c=command))
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
        command = '{program} {arg}'.format(
            program=self.ipset_executable, arg=argstr)
        if not raiseexception:
            command = command + ' >/dev/null 2>&1'
        # IMPROVEME: replace os.system
        status = os.system(command)
        if status == -1:
            # This section covers an OS failure, this is almost
            # impossible to simulate.
            raise IpsetFailure(
                'failed to invoke ipset ({c})'.format(c=command))
        status = os.WEXITSTATUS(status)
        if raiseexception and (status != 0):
            raise IpsetFailure(
                'ipset exited with status {status} ({c})'.format(
                    status=status, c=command))
        if status != 0:
            return False
        return True

    def _build_firewall_rule(self, name, usersrcip, protocol, acl):
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
        comment = ''
        if acl.description:
            _commentstring = '{user}:{group} ACL {desc}'.format(
                user=self.username_is,
                group=acl.rule,
                desc=acl.description,
            )
        if protocol and acl.portstring:
            if acl.description:
                comment = '-m comment --comment "{comment}"'.format(
                    comment=_commentstring
                )
            destport = '-m multiport --dports {ports}'.format(
                ports=acl.portstring
            )
            protocol = '-p ' + protocol
            rulestr = ('-A {name} -s {srcip} -d {dstip} '
                       '{proto} {dport} {comment} -j ACCEPT')
            self.iptables(rulestr.format(
                name=name,
                srcip=usersrcip,
                dstip=acl.address,
                dport=destport,
                proto=protocol,
                comment=comment))
        else:
            if acl.description:
                comment = ' comment "{comment}"'.format(
                    comment=_commentstring
                )
            else:
                comment = ''
            entry = '--add {name} {dstip}{comment}'.format(
                name=name,
                dstip=acl.address,
                comment=comment
            )
            self.ipset(entry)

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
                self._build_firewall_rule(chain, self.client_ip,
                                          protocol, acl)

        _commentstring = '{user} groups: {rulestr}'.format(
            rulestr=unique_rules_string, user=self.username_is)
        rules_comment = '-m comment --comment "{comment}"'.format(
            comment=_commentstring[:255])
        username_comment = '-m comment --comment "{user} at {ip}"'.format(
            ip=self.client_ip, user=self.username_is)

        # Insert glue to have the user's ipset high up...
        use_ipset_rule = ('-I {chain} -s {ip} '
                          '-m set --match-set {chain} dst '
                          '{comment} '
                          '-j ACCEPT')
        self.iptables(use_ipset_rule.format(
            ip=self.client_ip,
            comment=rules_comment,
            chain=chain), True)
        # ... and also "accept any established connections" early on.
        # This is actually THE first, since it's an Insert after
        # another Insert.  In case that matters to you later.
        allow_established_rule = ('-I {chain} '
                                  '-m conntrack --ctstate ESTABLISHED '
                                  '{comment} '
                                  '-j ACCEPT')
        self.iptables(allow_established_rule.format(
            comment=username_comment, chain=chain), True)
        log_drops_rule = ('-A {chain} '
                          '{comment} '
                          '-j LOG --log-prefix "DROP {user} "')
        # log-prefix needs a space at the end              ^
        self.iptables(log_drops_rule.format(
            comment=username_comment,
            chain=chain,
            user=self.username_is[:23]), True)
        drop_rule = ('-A {chain} '
                     '{comment} '
                     '-j REJECT --reject-with icmp-admin-prohibited')
        self.iptables(drop_rule.format(
            comment=username_comment, chain=chain), True)

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
            Test existance of a chain via the iptables binary
        """
        chain = self._chain_name()
        return self.iptables('-L ' + chain, False)

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
        self.iptables('-I FORWARD -s {ip} -j DROP'.format(
            ip=self.client_ip))

    def remove_safety_block(self):
        """
            This function removes the iptables block against the vpn IP.
        """
        try:
            if self.iptables(
                    '-C FORWARD -s {ip} -j DROP'.format(
                        ip=self.client_ip), False):
                # If there was nothing there, there's nothing to do.
                # This function can be called when there is or is not
                # a block in place, so, only complain if there was one
                # which we could not delete.
                self.iptables(
                    '-D FORWARD -s {ip} -j DROP >/dev/null 2>&1'.format(
                        ip=self.client_ip), True)
        except IptablesFailure:
            # This is an almost-impossible exception to throw, as it would be
            # a 'we saw it but couldn't delete it' situation.
            self.logger.summary = ('FAIL: did not delete blocking rule, '
                                   'potential security issue')
            self.logger.set_severity_from_string('CRITICAL')
            self.logger.details = {'vpnip': self.client_ip,
                                   'error': 'true',
                                   'username': self.username_is,
                                   'success': 'false'}
            self.logger.send()

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
            # have an iptables chain that got brought up on boot.
            #
            # We can't append to / edit the existing rules.  That's right
            # out.  That eaves us with two awful options:
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
            self.logger.summary = 'FAIL: Collision of adding a VPN ACL'
            self.logger.details = {'vpnip': self.client_ip,
                                   'error': 'true',
                                   'username': self.username_is,
                                   'success': 'false'}
            self.logger.set_severity_from_string('WARNING')
            self.logger.send()
            self.del_chain()
            # having now wiped the chain, check again:
            if self.chain_exists():
                # It didn't delete.  Severe problem.
                # This is almost impossible to test, as it means we
                # tried to delete a chain, but it couldn't be deleted.
                self.logger.summary = 'FAIL: Undeletable VPN ACL'
                self.logger.details = {'vpnip': self.client_ip,
                                       'error': 'true',
                                       'username': self.username_is,
                                       'success': 'false'}
                self.logger.set_severity_from_string('ERROR')
                self.logger.send()
                return False
            # We cleaned the chain out, proceed with a new add.
        user_acls = self.get_acls_for_user()
        self.create_user_rules(user_acls)
        # At this point, an iptable and ipset for usersrcip are now in place.
        # This function continues on to tie them to the OS:

        chain = self._chain_name()
        self.iptables('-A OUTPUT -d {ip} -j {chain}'.format(
            ip=self.client_ip, chain=chain), True)
        self.iptables('-A INPUT -s {ip} -j {chain}'.format(
            ip=self.client_ip, chain=chain), True)
        self.iptables('-A FORWARD -s {ip} -j {chain}'.format(
            ip=self.client_ip, chain=chain), True)
        self.remove_safety_block()
        return True

    def del_chain(self):
        """
            Delete the custom chain and all associated rules
        """
        chain = self._chain_name()
        self.iptables('-D OUTPUT -d {ip} -j {chain}'.format(
            ip=self.client_ip, chain=chain), False)
        self.iptables('-D INPUT -s {ip} -j {chain}'.format(
            ip=self.client_ip, chain=chain), False)
        self.iptables('-D FORWARD -s {ip} -j {chain}'.format(
            ip=self.client_ip, chain=chain), False)
        self.iptables('-F {chain}'.format(chain=chain), False)
        self.iptables('-X {chain}'.format(chain=chain), False)
        self.ipset('--destroy {chain}'.format(chain=chain), False)
        return True

    def update_chain(self):
        """
            Wrapper function around add and delete
        """
        self.del_chain()
        return self.add_chain()
