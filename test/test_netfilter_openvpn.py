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
import time
import tempfile
import datetime
import json
import syslog
import configparser
import test.context  # pylint: disable=unused-import
import mock
from netaddr import IPNetwork
import iamvpnlibrary
from netfilter_openvpn import IptablesFailure, IpsetFailure, NetfilterOpenVPN


class TestExceptions(unittest.TestCase):
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


class TestNetfilterOpenVPN(unittest.TestCase):
    '''
        Test the NetfilterOpenVPN class.
    '''

    def setUp(self):
        # We create a library that pretends it was done by root.
        # If you notice in the module, this exists as a simple early filter and prevents scripts
        # from going into cases where root is needed.  Since we're mocking here, the worry is
        # "well, now you can get into situations where you wouldn't otherwise.
        # True, but that's the point.
        with mock.patch('os.geteuid', return_value=0):
            self.library = NetfilterOpenVPN()

    def test_01_init_no_powers(self):
        ''' When we're not root, we should explode. '''
        with mock.patch('os.geteuid', return_value=1000):
            with self.assertRaises(Exception):
                NetfilterOpenVPN()

    def test_03_ingest_no_config_files(self):
        """ With no config files, get an empty ConfigParser """
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS', new=[]):
            result = self.library._ingest_config_from_file()
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), [],
                         'Should not have found any configfile sections.')

    def test_04_ingest_no_config_file(self):
        """ With all missing config files, get an empty ConfigParser """
        _not_a_real_file = '/tmp/no-such-file.txt'  # nosec hardcoded_tmp_directory
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[_not_a_real_file]):
            result = self.library._ingest_config_from_file()
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), [],
                         'Should not have found any configfile sections.')

    def test_05_ingest_bad_config_file(self):
        """ With a bad config file, get an empty ConfigParser """
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=['test/context.py']):
            result = self.library._ingest_config_from_file()
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), [],
                         'Should not have found any configfile sections.')

    def test_06_ingest_config_from_file(self):
        """ With an actual config file, get a populated ConfigParser """
        _not_a_real_file = '/tmp/no-such-file.txt'  # nosec hardcoded_tmp_directory
        test_reading_file = '/tmp/test-reader.txt'  # nosec hardcoded_tmp_directory
        with open(test_reading_file, 'w') as filepointer:
            filepointer.write('[aa]\nbb = cc\n')
        filepointer.close()
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[_not_a_real_file, test_reading_file]):
            result = self.library._ingest_config_from_file()
        os.remove(test_reading_file)
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), ['aa'],
                         'Should have found one configfile section.')
        self.assertEqual(result.options('aa'), ['bb'],
                         'Should have found one option.')
        self.assertEqual(result.get('aa', 'bb'), 'cc',
                         'Should have read a correct value.')

    def test_07a_ingest_variables_bad(self):
        """ With a poor config file, check we get the right things. """
        test_reading_file = '/tmp/test-reader.txt'  # nosec hardcoded_tmp_directory
        with open(test_reading_file, 'w') as filepointer:
            filepointer.write('[openvpn-netfilter]\n')
            filepointer.write('syslog-events-facility = blah\n')
        filepointer.close()
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[test_reading_file]), \
                mock.patch('os.geteuid', return_value=0):
            library = NetfilterOpenVPN()
        os.remove(test_reading_file)
        self.assertEqual(library.iptables_executable, '/sbin/iptables')
        self.assertEqual(library.ipset_executable, '/usr/sbin/ipset')
        self.assertEqual(library.lockpath, '/var/run/openvpn_netfilter.lock')
        self.assertEqual(library.lockwaittime, 2)
        self.assertEqual(library.lockretriesmax, 10)
        self.assertEqual(library.event_send, False)
        self.assertEqual(library.event_facility, syslog.LOG_AUTH)

    def test_07b_ingest_variables_good(self):
        """ With an actual config file, check we get the right things. """
        test_reading_file = '/tmp/test-reader.txt'  # nosec hardcoded_tmp_directory
        with open(test_reading_file, 'w') as filepointer:
            filepointer.write('[openvpn-netfilter]\n')
            filepointer.write('iptables_executable = /foo/bar\n')
            filepointer.write('ipset_executable = /foo/baz\n')
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
        self.assertEqual(library.iptables_executable, '/foo/bar')
        self.assertEqual(library.ipset_executable, '/foo/baz')
        self.assertEqual(library.lockpath, '/some/lock')
        self.assertEqual(library.lockwaittime, 6)
        self.assertEqual(library.lockretriesmax, 12)
        self.assertEqual(library.event_send, True)
        self.assertEqual(library.event_facility, syslog.LOG_LOCAL0)

    def test_08_set_targets(self):
        """ test set_targets """
        self.library.set_targets()
        self.assertIsNone(self.library.client_ip, 'without args, client_ip should be none')
        self.assertIsNone(self.library.username_is, 'without args, username_is should be none')
        self.assertIsNone(self.library.username_as, 'without args, username_as should be none')
        self.assertIsNone(self.library.iam_object, 'without args, iam_object should be none')

        self.library.set_targets(username_is='a', username_as=None, client_ip='c')
        self.assertEqual(self.library.client_ip, 'c', 'client_ip should receive an arg')
        self.assertEqual(self.library.username_is, 'a', 'username_is should receive an arg')
        self.assertEqual(self.library.username_as, 'a', 'username_as should receive an arg')
        self.assertIsNone(self.library.iam_object, 'without sudoing, iam_object should be none')

        with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam:
            instance = mock_iam.return_value
            with mock.patch.object(instance, 'verify_sudo_user', return_value='q'):
                self.library.set_targets(username_is='a', username_as='b', client_ip='c')
        self.assertEqual(self.library.client_ip, 'c', 'client_ip should receive an arg')
        self.assertEqual(self.library.username_is, 'a', 'username_is should receive an arg')
        self.assertEqual(self.library.username_as, 'q', 'username_as should calculate an arg')
        self.assertIsNotNone(self.library.iam_object, 'iam_object should be set when sudoing')

    def test_09_usernamestr(self):
        """ test username_string """
        self.library.username_is = None
        self.library.username_as = None
        self.assertEqual(self.library.username_string(), '',
                         "username_string must be '' before any vars are set")
        self.library.username_is = 'foo'
        self.library.username_as = None
        self.assertEqual(self.library.username_string(), 'foo',
                         'username_string must be set when IS but not AS')
        self.library.username_is = 'bar'
        self.library.username_as = 'bar'
        self.assertEqual(self.library.username_string(), 'bar',
                         'username_string must be right when IS and AS agree')
        self.library.username_is = 'baz'
        self.library.username_as = 'quux'
        self.assertEqual(self.library.username_string(), 'baz-sudoing-as-quux',
                         'username_string must list sudo when appropriate')

    def test_10_lock_timeout(self):
        ''' test the lock_timeout function '''
        self.library.lockwaittime = 3
        with self.library._lock_timeout():
            # Do something that will finish in under 3s:
            _dummy = 1 + 1
        # If all went right, we fell out of the bottom of _lock_timeout just fine.

        # Speed it up, we ain't got all day.
        self.library.lockwaittime = 1
        with self.assertRaises(OSError):
            with self.library._lock_timeout():
                # Do something that can't finish in under 1s:
                time.sleep(3)
        # Here we took too long, so, timed out correctly.

    def test_11_acquire_lock_simple(self):
        ''' test the acquire_lock function when there's no hiccups '''
        tmpfile = tempfile.NamedTemporaryFile()
        self.library.lockpath = tmpfile.name
        self.assertIsNone(self.library._lock)
        self.assertTrue(self.library.acquire_lock())
        self.assertIsNotNone(self.library._lock)
        # Better test: is a file object ^
        self.assertTrue(self.library.free_lock())
        self.assertIsNone(self.library._lock)

    def test_12_acquire_lock_failure(self):
        ''' test the acquire_lock function when things go badly '''
        tmpfile = tempfile.NamedTemporaryFile()
        self.library.lockpath = tmpfile.name
        self.assertIsNone(self.library._lock)
        with mock.patch('fcntl.flock', side_effect=IOError), \
                mock.patch.object(self.library, 'send_event') as mock_logger:
            self.assertFalse(self.library.acquire_lock())
        # Lock failure triggers an event:
        mock_logger.assert_called_once()

    def test_13_log_event_nosend(self):
        ''' Test the send_event method failing to send '''
        self.library.event_send = False
        with mock.patch('syslog.openlog') as mock_openlog, \
                mock.patch('syslog.syslog') as mock_syslog:
            self.library.send_event('some message', {'foo': 5}, 'CRITICAL')
        mock_openlog.assert_not_called()
        mock_syslog.assert_not_called()

    def test_14_log_event_send(self):
        ''' Test the send_event method tries to send '''
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(2020, 12, 25, 13, 14, 15, 123456, tzinfo=datetime.timezone.utc)
        self.library.event_send = True
        self.library.event_facility = syslog.LOG_LOCAL1
        with mock.patch('syslog.openlog') as mock_openlog, \
                mock.patch('syslog.syslog') as mock_syslog, \
                mock.patch('datetime.datetime', new=datetime_mock), \
                mock.patch('os.getpid', return_value=12345), \
                mock.patch('socket.getfqdn', return_value='my.host.name'):
            self.library.send_event('some message', {'foo': 5}, 'CRITICAL')
        mock_openlog.assert_called_once_with(facility=syslog.LOG_LOCAL1)
        mock_syslog.assert_called_once()
        arg_passed_in = mock_syslog.call_args_list[0][0][0]
        json_sent = json.loads(arg_passed_in)
        details = json_sent['details']
        self.assertEqual(json_sent['category'], 'authentication')
        self.assertEqual(json_sent['processid'], 12345)
        self.assertEqual(json_sent['severity'], 'CRITICAL')
        self.assertIn('processname', json_sent)
        self.assertEqual(json_sent['timestamp'], '2020-12-25T13:14:15.123456+00:00')
        self.assertEqual(json_sent['hostname'], 'my.host.name')
        self.assertEqual(json_sent['summary'], 'some message')
        self.assertEqual(json_sent['source'], 'openvpn')
        self.assertEqual(json_sent['tags'], ['vpn', 'netfilter'])
        self.assertEqual(details, {'foo': 5})

    def test_15_chain_name(self):
        ''' Make sure we get a chain name based on the client_ip value '''
        self.library.client_ip = '12345'
        self.assertEqual(self.library._chain_name(), '12345')

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
        ''' Test _build_firewall_rule function '''
        self.library.username_is = 'bob'

        iptables_acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='', address='5.6.7.8', portstring='80', description='')
        with mock.patch.object(self.library, 'iptables') as mock_ipt:
            self.library._build_firewall_rule('chain1', '1.2.3.4', 'tcp', iptables_acl1)
        mock_ipt.assert_called_once_with(('-A chain1 -s 1.2.3.4 -d 5.6.7.8 -p tcp '
                                          '-m multiport --dports 80  -j ACCEPT'))

        iptables_acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule2', address='5.6.7.9', portstring='80', description='I HAZ COMMENT')
        with mock.patch.object(self.library, 'iptables') as mock_ipt:
            self.library._build_firewall_rule('chain2', '1.2.3.4', 'tcp', iptables_acl2)
        mock_ipt.assert_called_once_with(('-A chain2 -s 1.2.3.4 -d 5.6.7.9 -p tcp -m multiport '
                                          '--dports 80 -m comment '
                                          '--comment "bob:rule2 ACL I HAZ COMMENT" '
                                          '-j ACCEPT'))

        ipset_acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='', address='5.6.7.10', portstring='', description='')
        with mock.patch.object(self.library, 'ipset') as mock_ips:
            self.library._build_firewall_rule('chain3', '1.2.3.4', '', ipset_acl1)
        mock_ips.assert_called_once_with('--add chain3 5.6.7.10')

        ipset_acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule4', address='5.6.7.11', portstring='', description='IPSET SET SET')
        with mock.patch.object(self.library, 'ipset') as mock_ips:
            self.library._build_firewall_rule('chain4', '1.2.3.4', '', ipset_acl2)
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

    def test_35_get_acls(self):
        ''' Test get_acls_for_user function '''
        self.library.username_is = 'joe'
        self.library.username_as = 'moe'
        self.library.iam_object = mock.Mock()

        with mock.patch.object(self.library.iam_object, 'get_allowed_vpn_acls',
                               return_value=[]):
            result = self.library.get_acls_for_user()
        self.assertEqual(result, [], 'User without IAM ACLs must get []')

        # stanalone ACL, WITH a port,    WITH    a larger group to absorb it (but can't)
        acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.10.10/32'),
                                                  portstring='80', description='')
        # stanalone ACL, WITH a port,    WITH    a larger group to absorb it (and it could be)
        acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.10.12/32'),
                                                  portstring='443', description='')
        # stanalone ACL, WITH a port,    WITHOUT a larger group to absorb it.
        acl3 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.40.10/32'),
                                                  portstring='80', description='')
        # stanalone ACL, WITHOUT a port, WITH    a larger group to absorb it.
        acl4 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.20.11/32'),
                                                  portstring='', description='')
        # stanalone ACL, WITHOUT a port, WITHOUT a larger group to absorb it.
        acl5 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.30.50.70/32'),
                                                  portstring='', description='')
        # CIDR ACL,      WITH a port,    WITH    a larger group to absorb it (but can't)
        acl6 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.10.0/27'),
                                                  portstring='443', description='')
        # CIDR ACL,      WITH a port,    WITH    a larger group to absorb it (and it could be)
        acl7 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.30.0/27'),
                                                  portstring='443', description='')
        # CIDR ACL,      WITH a port,    WITHOUT a larger group to absorb it.
        acl8 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.30.0/24'),
                                                  portstring='443', description='')
        # CIDR ACL,      WITHOUT a port, WITH    a larger group to absorb it.
        acl9 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.20.0/27'),
                                                  portstring='', description='')
        # CIDR ACL,      WITHOUT a port, WITHOUT a larger group to absorb it.
        acl10 = iamvpnlibrary.iamvpnbase.ParsedACL(rule='', address=IPNetwork('10.10.20.0/24'),
                                                   portstring='', description='')

        # portstring-focused absorbing:
        with mock.patch.object(self.library.iam_object, 'get_allowed_vpn_acls',
                               return_value=[acl1, acl5, acl6]):
            self.assertEqual(self.library.get_acls_for_user(), [acl6, acl1, acl5])

        # portstring that COULD be absorbed, but we don't.  This could be improved, so if
        # this test is the status quo, but don't be scared to change it.
        with mock.patch.object(self.library.iam_object, 'get_allowed_vpn_acls',
                               return_value=[acl2, acl6]):
            self.assertEqual(self.library.get_acls_for_user(), [acl6, acl2])

        # portstring that COULD be absorbed, but we don't.  This could be improved, so if
        # this test is the status quo, but don't be scared to change it.
        with mock.patch.object(self.library.iam_object, 'get_allowed_vpn_acls',
                               return_value=[acl7, acl8]):
            self.assertEqual(self.library.get_acls_for_user(), [acl8, acl7])

        # collapsing of ranges:
        with mock.patch.object(self.library.iam_object, 'get_allowed_vpn_acls',
                               return_value=[acl3, acl4, acl9, acl10]):
            self.assertEqual(self.library.get_acls_for_user(), [acl10, acl3])

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
