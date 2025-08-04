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
from netfilter_openvpn import NetfilterOpenVPN


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
        with open(test_reading_file, 'w', encoding='utf-8') as filepointer:
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
