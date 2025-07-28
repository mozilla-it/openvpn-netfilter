# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
"""
   script testing script
"""
# This test file calls protected methods on the vpn
# file, so, we tell pylint that we're cool with it globally:

import unittest
import os
import syslog
import test.context  # pylint: disable=unused-import
import mock
import iamvpnlibrary
from netfilter_openvpn import IptablesFailure, IpsetFailure, NetfilterOpenVPN


class TestExceptionsiptables(unittest.TestCase):
    """
        These are the tests for the class-defined Exceptions.
    """

    def test_exceptions(self):
        """ Verify that the self object was initialized """
        self.assertIsInstance(IptablesFailure(), IptablesFailure,
                              'IptablesFailure does not exist')
        self.assertIsInstance(IptablesFailure(), Exception,
                              'IptablesFailure is not an Exception')
        self.assertIsInstance(IpsetFailure(), IpsetFailure,
                              'IpsetFailure does not exist')
        self.assertIsInstance(IpsetFailure(), Exception,
                              'IpsetFailure is not an Exception')


class TestNetfilterOpenVPNiptables(unittest.TestCase):
    '''
        Test the NetfilterOpenVPN class against iptables.
    '''

    def setUp(self):
        # We create a library that pretends it was done by root.
        # If you notice in the module, this exists as a simple early filter and prevents scripts
        # from going into cases where root is needed.  Since we're mocking here, the worry is
        # "well, now you can get into situations where you wouldn't otherwise.
        # True, but that's the point.
        test_reading_file = '/tmp/test-reader.txt'  # nosec hardcoded_tmp_directory
        with open(test_reading_file, 'w', encoding='utf-8') as filepointer:
            filepointer.write('[openvpn-netfilter]\n')
            filepointer.write('framework = iptables\n')
        filepointer.close()
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[test_reading_file]), \
                mock.patch('os.geteuid', return_value=0):
            self.library = NetfilterOpenVPN()

    def test_07a_ingest_variables_bad(self):
        """ With a poor config file, check we get the right things. """
        test_reading_file = '/tmp/test-reader.txt'  # nosec hardcoded_tmp_directory
        with open(test_reading_file, 'w', encoding='utf-8') as filepointer:
            filepointer.write('[openvpn-netfilter]\n')
            filepointer.write('framework = iptables\n')
            filepointer.write('syslog-events-facility = blah\n')
        filepointer.close()
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[test_reading_file]), \
                mock.patch('os.geteuid', return_value=0):
            library = NetfilterOpenVPN()
        os.remove(test_reading_file)
        self.assertEqual(library.nf_framework, 'iptables')
        self.assertEqual(library.nft, None)
        self.assertEqual(library.iptables_executable, '/sbin/iptables')
        self.assertEqual(library.ipset_executable, '/usr/sbin/ipset')
        #self.assertEqual(library.nftables_table, 'openvpn_netfilter')
        self.assertEqual(library.lockpath, '/var/run/openvpn_netfilter.lock')
        self.assertEqual(library.lockwaittime, 2)
        self.assertEqual(library.lockretriesmax, 10)
        self.assertEqual(library.event_send, False)
        self.assertEqual(library.event_facility, syslog.LOG_AUTH)

    def test_07b_ingest_variables_good(self):
        """ With an actual config file, check we get the right things. """
        test_reading_file = '/tmp/test-reader.txt'  # nosec hardcoded_tmp_directory
        with open(test_reading_file, 'w', encoding='utf-8') as filepointer:
            filepointer.write('[openvpn-netfilter]\n')
            filepointer.write('framework = iptables\n')
            filepointer.write('iptables_executable = /foo/bar\n')
            filepointer.write('ipset_executable = /foo/baz\n')
            filepointer.write('nftables_table = some_tablename\n')
            filepointer.write('LOCKPATH = /some/lock\n')
            filepointer.write('LOCKWAITTIME = 6\n')
            filepointer.write('LOCKRETRIESMAX = 12\n')
            filepointer.write('syslog-events-send = True\n')
            filepointer.write('syslog-events-facility = local0\n')
        filepointer.close()
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[test_reading_file]), \
                mock.patch('os.geteuid', return_value=0):
            library = NetfilterOpenVPN()
        os.remove(test_reading_file)
        self.assertEqual(library.nf_framework, 'iptables')
        self.assertEqual(library.nft, None)
        self.assertEqual(library.iptables_executable, '/foo/bar')
        self.assertEqual(library.ipset_executable, '/foo/baz')
        #self.assertEqual(library.nftables_table, 'some_tablename')
        self.assertEqual(library.lockpath, '/some/lock')
        self.assertEqual(library.lockwaittime, 6)
        self.assertEqual(library.lockretriesmax, 12)
        self.assertEqual(library.event_send, True)
        self.assertEqual(library.event_facility, syslog.LOG_LOCAL0)

    def test_16_chain_exists_deeptest(self):
        ''' Check for odd cases in teardown '''
        self.library.client_ip = '12345'
        with mock.patch.object(self.library, 'chain_exists_iptables', return_value=False), \
                mock.patch.object(self.library, 'chain_exists_iptables', return_value=False):
            result = self.library.chain_exists()
        self.assertFalse(result)

        with mock.patch.object(self.library, 'chain_exists_iptables', return_value=True), \
                mock.patch.object(self.library, 'chain_exists_ipset', return_value=False):
            result = self.library.chain_exists()
        self.assertTrue(result)

        with mock.patch.object(self.library, 'chain_exists_iptables', return_value=False), \
                mock.patch.object(self.library, 'chain_exists_ipset', return_value=True):
            result = self.library.chain_exists()
        self.assertTrue(result)

    def test_16_chain_exists_iptables(self):
        ''' Make sure can figure out if an iptables chain exists '''
        self.library.client_ip = '12345'
        with mock.patch.object(self.library, 'iptables', return_value='x') as mock_ipt:
            result = self.library.chain_exists_iptables()
        # Get back whatever the iptables call is:
        self.assertEqual(result, 'x')
        mock_ipt.assert_called_once_with('-L 12345', False)

    def test_16_chain_exists_ipset(self):
        ''' Make sure can figure out if an ipset chain exists '''
        self.library.client_ip = '12345'
        with mock.patch.object(self.library, 'ipset', return_value='x') as mock_ips:
            result = self.library.chain_exists_ipset()
        # Get back whatever the ipset call is:
        self.assertEqual(result, 'x')
        mock_ips.assert_called_once_with('list 12345', False)

    def test_17_update_chain(self):
        ''' Make sure update_chain is THAT simple '''
        with mock.patch.object(self.library, 'del_chain') as mock_d, \
                mock.patch.object(self.library, 'add_chain', return_value='y') as mock_a:
            result = self.library.update_chain()
        # Get back whatever the add_chain call is:
        self.assertEqual(result, 'y')
        mock_d.assert_called_once_with()
        mock_a.assert_called_once_with()

    def test_18_add_chain(self):
        ''' Test add_chain function '''
        self.library.client_ip = '3.4.5.6'

        # First assume horrific failure:
        with mock.patch.object(self.library, 'chain_exists', side_effect=[True, True]), \
                mock.patch.object(self.library, 'del_chain') as mock_delchain, \
                mock.patch.object(self.library, 'send_event') as mock_logger:
            result = self.library.add_chain()
        self.assertFalse(result, 'Unremovable chain must cause add_chain to be False')
        mock_delchain.assert_called_once_with()
        self.assertEqual(mock_logger.call_count, 2, 'Unremovable chain fails twice')

        # Now, assume simple success:
        with mock.patch.object(self.library, 'chain_exists', return_value=False), \
                mock.patch.object(self.library, 'iptables') as mock_ipt, \
                mock.patch.object(self.library, 'get_acls_for_user',
                                  return_value='q') as mock_acls, \
                mock.patch.object(self.library, 'create_user_rules') as mock_crea, \
                mock.patch.object(self.library, 'remove_safety_block') as mock_block:
            result = self.library.add_chain()
        self.assertTrue(result, 'clean add_chain must be True')
        mock_acls.assert_called_once_with()
        mock_crea.assert_called_once_with('q')
        mock_block.assert_called_once_with()
        mock_ipt.assert_any_call('-A OUTPUT -d 3.4.5.6 -j 3.4.5.6', True)
        mock_ipt.assert_any_call('-A INPUT -s 3.4.5.6 -j 3.4.5.6', True)
        mock_ipt.assert_any_call('-A FORWARD -s 3.4.5.6 -j 3.4.5.6', True)

        # Now, copy all that again but assume that we had to do housekeeping:
        with mock.patch.object(self.library, 'chain_exists', side_effect=[True, False]), \
                mock.patch.object(self.library, 'del_chain') as mock_delchain, \
                mock.patch.object(self.library, 'iptables') as mock_ipt, \
                mock.patch.object(self.library, 'get_acls_for_user',
                                  return_value='q') as mock_acls, \
                mock.patch.object(self.library, 'create_user_rules') as mock_crea, \
                mock.patch.object(self.library, 'remove_safety_block') as mock_block, \
                mock.patch.object(self.library, 'send_event') as mock_logger:
            result = self.library.add_chain()
        self.assertTrue(result, 'add_chain must be True even if it had to clean a chain out')
        mock_acls.assert_called_once_with()
        mock_crea.assert_called_once_with('q')
        mock_block.assert_called_once_with()
        mock_delchain.assert_called_once_with()
        # Collision cleanout triggers an event:
        mock_logger.assert_called_once()
        mock_ipt.assert_any_call('-A OUTPUT -d 3.4.5.6 -j 3.4.5.6', True)
        mock_ipt.assert_any_call('-A INPUT -s 3.4.5.6 -j 3.4.5.6', True)
        mock_ipt.assert_any_call('-A FORWARD -s 3.4.5.6 -j 3.4.5.6', True)

    def test_19_del_chain(self):
        ''' Test del_chain function '''
        self.library.client_ip = '2.3.4.5'

        with mock.patch.object(self.library, 'iptables') as mock_ipt, \
                mock.patch.object(self.library, 'ipset') as mock_ips:
            result = self.library.del_chain()
        # A lot just happened.  Time to check that iptables and ipset did the right things.
        self.assertTrue(result, "del_chain must return True")
        mock_ipt.assert_any_call('-D OUTPUT -d 2.3.4.5 -j 2.3.4.5', False)
        mock_ipt.assert_any_call('-D INPUT -s 2.3.4.5 -j 2.3.4.5', False)
        mock_ipt.assert_any_call('-D FORWARD -s 2.3.4.5 -j 2.3.4.5', False)
        mock_ipt.assert_any_call('-F 2.3.4.5', False)
        mock_ipt.assert_any_call('-X 2.3.4.5', False)
        mock_ips.assert_any_call('--destroy 2.3.4.5', False)

    def test_21_iptables(self):
        ''' Test iptables function '''
        # change the executable for shorter testing, and, in case we screw up our mock,
        # it'll have no chance of executing on the host.
        self.library.iptables_executable = 'ipt'

        # 0 emulates iptables working correctly
        with mock.patch('os.system', return_value=0) as mock_syscall:
            result = self.library.iptables('foo1', raiseexception=True)
        self.assertTrue(result, 'iptables should return True when a command works')
        mock_syscall.assert_called_once_with('ipt foo1')

        with mock.patch('os.system', return_value=0) as mock_syscall:
            result = self.library.iptables('foo2', raiseexception=False)
        self.assertTrue(result, 'iptables should return True when a command works')
        mock_syscall.assert_called_once_with('ipt foo2 >/dev/null 2>&1')

        # -1 emulates the iptables executable being wrong completely:
        with mock.patch('os.system', return_value=-1) as mock_syscall:
            with self.assertRaises(IptablesFailure):
                self.library.iptables('foo3', raiseexception=True)
        mock_syscall.assert_called_once_with('ipt foo3')

        with mock.patch('os.system', return_value=-1) as mock_syscall:
            with self.assertRaises(IptablesFailure):
                self.library.iptables('foo4', raiseexception=False)
        mock_syscall.assert_called_once_with('ipt foo4 >/dev/null 2>&1')

        # 256 emulates the iptables executable being confused:
        with mock.patch('os.system', return_value=256) as mock_syscall:
            with self.assertRaises(IptablesFailure):
                self.library.iptables('foo5', raiseexception=True)
        mock_syscall.assert_called_once_with('ipt foo5')

        with mock.patch('os.system', return_value=256) as mock_syscall:
            result = self.library.iptables('foo6', raiseexception=False)
        self.assertFalse(result, 'iptables should return False when a command fails')
        mock_syscall.assert_called_once_with('ipt foo6 >/dev/null 2>&1')

    def test_22_ipset(self):
        ''' Test ipset function '''
        # change the executable for shorter testing, and, in case we screw up our mock,
        # it'll have no chance of executing on the host.
        self.library.ipset_executable = 'ips'

        # 0 emulates ipset working correctly
        with mock.patch('os.system', return_value=0) as mock_syscall:
            result = self.library.ipset('foo1', raiseexception=True)
        self.assertTrue(result, 'ipset should return True when a command works')
        mock_syscall.assert_called_once_with('ips foo1')

        with mock.patch('os.system', return_value=0) as mock_syscall:
            result = self.library.ipset('foo2', raiseexception=False)
        self.assertTrue(result, 'ipset should return True when a command works')
        mock_syscall.assert_called_once_with('ips foo2 >/dev/null 2>&1')

        # -1 emulates the ipset executable being wrong completely:
        with mock.patch('os.system', return_value=-1) as mock_syscall:
            with self.assertRaises(IpsetFailure):
                self.library.ipset('foo3', raiseexception=True)
        mock_syscall.assert_called_once_with('ips foo3')

        with mock.patch('os.system', return_value=-1) as mock_syscall:
            with self.assertRaises(IpsetFailure):
                self.library.ipset('foo4', raiseexception=False)
        mock_syscall.assert_called_once_with('ips foo4 >/dev/null 2>&1')

        # 256 emulates the ipset executable being confused:
        with mock.patch('os.system', return_value=256) as mock_syscall:
            with self.assertRaises(IpsetFailure):
                self.library.ipset('foo5', raiseexception=True)
        mock_syscall.assert_called_once_with('ips foo5')

        with mock.patch('os.system', return_value=256) as mock_syscall:
            result = self.library.ipset('foo6', raiseexception=False)
        self.assertFalse(result, 'ipset should return False when a command fails')
        mock_syscall.assert_called_once_with('ips foo6 >/dev/null 2>&1')

    def test_30_build_fw_rule(self):
        ''' Test _build_firewall_rule_iptables function '''
        self.library.username_is = 'bob'

        iptables_acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='', address='5.6.7.8', portstring='80', description='')
        with mock.patch.object(self.library, 'iptables') as mock_ipt:
            self.library._build_firewall_rule_iptables('chain1', '1.2.3.4', 'tcp', iptables_acl1)
        mock_ipt.assert_called_once_with(('-A chain1 -s 1.2.3.4 -d 5.6.7.8 -p tcp '
                                          '-m multiport --dports 80  -j ACCEPT'))

        iptables_acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule2', address='5.6.7.9', portstring='80', description='I HAZ COMMENT')
        with mock.patch.object(self.library, 'iptables') as mock_ipt:
            self.library._build_firewall_rule_iptables('chain2', '1.2.3.4', 'tcp', iptables_acl2)
        mock_ipt.assert_called_once_with(('-A chain2 -s 1.2.3.4 -d 5.6.7.9 -p tcp -m multiport '
                                          '--dports 80 -m comment '
                                          '--comment "bob:rule2 ACL I HAZ COMMENT" '
                                          '-j ACCEPT'))

        ipset_acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='', address='5.6.7.10', portstring='', description='')
        with mock.patch.object(self.library, 'ipset') as mock_ips:
            self.library._build_firewall_rule_iptables('chain3', '1.2.3.4', '', ipset_acl1)
        mock_ips.assert_called_once_with('--add chain3 5.6.7.10')

        ipset_acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule4', address='5.6.7.11', portstring='', description='IPSET SET SET')
        with mock.patch.object(self.library, 'ipset') as mock_ips:
            self.library._build_firewall_rule_iptables('chain4', '1.2.3.4', '', ipset_acl2)
        mock_ips.assert_called_once_with('--add chain4 5.6.7.11 comment "bob:rule4 ACL IPSET SET SET"')

    def test_31_create_rules(self):
        ''' Test create_user_rules function '''
        self.library.username_is = 'larry'
        self.library.client_ip = '2.3.4.5'

        acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule2', address='5.6.7.9', portstring='80', description='I HAZ COMMENT')
        acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule4', address='5.6.7.11', portstring='', description='IPSET SET SET')
        with mock.patch.object(self.library, 'iptables') as mock_ipt, \
                mock.patch.object(self.library, 'ipset') as mock_ips:
            self.library.create_user_rules([acl1, acl2])
        # A lot just happened.  Time to check that iptables and ipset did the right things.
        # This is written not in the order they were invoked, but in the order you'd read them.
        # Make the chains:
        mock_ipt.assert_any_call('-N 2.3.4.5')
        mock_ips.assert_any_call('--create 2.3.4.5 hash:net comment')
        # allow established and ipsets:
        mock_ipt.assert_any_call(('-I 2.3.4.5 -m conntrack --ctstate ESTABLISHED -m comment '
                                  '--comment "larry at 2.3.4.5" -j ACCEPT'), True)
        mock_ipt.assert_any_call(('-I 2.3.4.5 -s 2.3.4.5 -m set --match-set 2.3.4.5 dst -m '
                                  'comment --comment "larry groups: rule2;rule4" -j ACCEPT'), True)
        # And now the rules.  Two for a portstring:
        mock_ipt.assert_any_call(('-A 2.3.4.5 -s 2.3.4.5 -d 5.6.7.9 -p tcp -m multiport '
                                  '--dports 80 -m comment --comment '
                                  '"larry:rule2 ACL I HAZ COMMENT" -j ACCEPT'))
        mock_ipt.assert_any_call(('-A 2.3.4.5 -s 2.3.4.5 -d 5.6.7.9 -p udp -m multiport '
                                  '--dports 80 -m comment --comment '
                                  '"larry:rule2 ACL I HAZ COMMENT" -j ACCEPT'))
        # One item in the ipset:
        mock_ips.assert_any_call('--add 2.3.4.5 5.6.7.11 comment "larry:rule4 ACL IPSET SET SET"')
        # And the mandatory drops:
        mock_ipt.assert_any_call(('-A 2.3.4.5 -m comment --comment "larry at 2.3.4.5" '
                                  '-j LOG --log-prefix "DROP larry "'), True)
        mock_ipt.assert_any_call(('-A 2.3.4.5 -m comment --comment "larry at 2.3.4.5" '
                                  '-j REJECT --reject-with icmp-admin-prohibited'), True)

    def test_add_safety(self):
        ''' Test add_safety_block function '''
        self.library.client_ip = '12345'

        # Assume an add works:
        with mock.patch.object(self.library, 'iptables') as mock_ipt:
            self.library.add_safety_block()
        mock_ipt.assert_called_once_with('-I FORWARD -s 12345 -j DROP')

        # Assume an add fails:
        with mock.patch.object(self.library, 'iptables', side_effect=IptablesFailure), \
                self.assertRaises(IptablesFailure):
            self.library.add_safety_block()

    def test_del_safety(self):
        ''' Test add_safety_block function '''
        self.library.client_ip = '23456'

        # Assume a delete has nothing to do:
        with mock.patch.object(self.library, 'iptables', return_value=False) as mock_ipt:
            self.library.remove_safety_block()
        mock_ipt.assert_called_once_with('-C FORWARD -s 23456 -j DROP', False)

        # Assume a delete works:
        with mock.patch.object(self.library, 'iptables', side_effect=[True, True]) as mock_ipt, \
                mock.patch.object(self.library, 'send_event') as mock_logger:
            self.library.remove_safety_block()
        mock_ipt.assert_any_call('-C FORWARD -s 23456 -j DROP', False)
        mock_ipt.assert_any_call('-D FORWARD -s 23456 -j DROP >/dev/null 2>&1', True)
        mock_logger.assert_not_called()

        # Assume a delete blows out, SOMEHOW:
        with mock.patch.object(self.library, 'iptables',
                               side_effect=[True, IptablesFailure]) as mock_ipt, \
                mock.patch.object(self.library, 'send_event') as mock_logger:
            self.library.remove_safety_block()
        mock_ipt.assert_any_call('-C FORWARD -s 23456 -j DROP', False)
        mock_ipt.assert_any_call('-D FORWARD -s 23456 -j DROP >/dev/null 2>&1', True)
        mock_logger.assert_called_once()
