'''
   tests that are specific to nftables
'''
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2025 Mozilla Corporation

import unittest
import os
import syslog
import test.context  # pylint: disable=unused-import
import mock
from netaddr import IPNetwork
import iamvpnlibrary
from netfilter_openvpn import NftablesFailure, NetfilterOpenVPN


class TestExceptionsnftables(unittest.TestCase):
    """
        These are the tests for the class-defined Exceptions.
    """

    def test_exceptions(self):
        """ Verify that the self object was initialized """
        self.assertIsInstance(NftablesFailure(), NftablesFailure,
                              'NftablesFailure does not exist')
        self.assertIsInstance(NftablesFailure(), Exception,
                              'NftablesFailure is not an Exception')


class TestNetfilterOpenVPNnftables(unittest.TestCase):
    '''
        Test the NetfilterOpenVPN class against nftables.
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
            filepointer.write('framework = nftables\n')
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
            filepointer.write('framework = nftables\n')
            filepointer.write('syslog-events-facility = blah\n')
        filepointer.close()
        with mock.patch.object(NetfilterOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[test_reading_file]), \
                mock.patch('os.geteuid', return_value=0):
            library = NetfilterOpenVPN()
        os.remove(test_reading_file)
        self.assertEqual(library.nf_framework, 'nftables')
        self.assertNotEqual(library.nft, None)
        self.assertEqual(library.nftables_table, 'openvpn_netfilter')
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
            filepointer.write('framework = nftables\n')
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
        self.assertEqual(library.nf_framework, 'nftables')
        self.assertNotEqual(library.nft, None)
        self.assertEqual(library.nftables_table, 'some_tablename')
        self.assertEqual(library.lockpath, '/some/lock')
        self.assertEqual(library.lockwaittime, 6)
        self.assertEqual(library.lockretriesmax, 12)
        self.assertEqual(library.event_send, True)
        self.assertEqual(library.event_facility, syslog.LOG_LOCAL0)


    def test_16_chain_exists_deeptest(self):
        ''' Check for odd cases in teardown '''
        self.library.client_ip = '12345'
        with mock.patch.object(self.library, 'chain_exists_nftables', return_value=False):
            result = self.library.chain_exists()
        self.assertFalse(result)

        with mock.patch.object(self.library, 'chain_exists_nftables', return_value=True):
            result = self.library.chain_exists()
        self.assertTrue(result)


    def test_16_chain_exists_nftables(self):
        ''' Make sure can figure out if an nftables chain exists '''
        self.library.client_ip = '12345'
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (0, 'somejson', '')
            result = self.library.chain_exists_nftables()
        # Get back whatever the nftables call is:
        self.assertEqual(result, True)
        mock_nft.assert_called_once_with({'nftables': [
            {'list': {'chain': {'family': 'inet',
                                'table': 'openvpn_netfilter',
                                'name': self.library.client_ip}
                                }}]})


    def test_16_chain_does_not_exist_nftables(self):
        ''' Make sure can figure out if an nftables chain is not here '''
        self.library.client_ip = '12345'
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (-1, 'somejson', '')
            result = self.library.chain_exists_nftables()
        # Get back whatever the nftables call is:
        self.assertEqual(result, False)
        mock_nft.assert_called_once_with({'nftables': [
            {'list': {'chain': {'family': 'inet',
                                'table': 'openvpn_netfilter',
                                'name': self.library.client_ip}
                                }}]})


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
                mock.patch.object(self.library.nft, 'json_cmd') as mock_nft, \
                mock.patch.object(self.library, 'get_acls_for_user',
                                  return_value='q') as mock_acls, \
                mock.patch.object(self.library, 'create_user_rules') as mock_crea, \
                mock.patch.object(self.library, 'remove_safety_block') as mock_block:
            mock_nft.return_value = (0, '', '')
            result = self.library.add_chain()
        self.assertTrue(result, 'clean add_chain must be True')
        mock_acls.assert_called_once_with()
        mock_crea.assert_called_once_with('q')
        mock_block.assert_called_once_with()
        mock_nft.assert_called_once_with({'nftables': [
            {'add': {'rule': {'family': 'inet',
                              'table': 'openvpn_netfilter',
                              'chain': 'FORWARD',
                              'expr': [{'match': {'op': '==',
                                                  'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                                                  'right': '3.4.5.6'}},
                                       {'jump': {'target': '3.4.5.6'}}]}}},
            {'add': {'rule': {'family': 'inet',
                              'table': 'openvpn_netfilter',
                              'chain': 'FORWARD',
                              'expr': [{'match': {'op': '==',
                                                  'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                                                  'right': '3.4.5.6'}},
                                       {'jump': {'target': '3.4.5.6'}}]}}},
        ]})

        # Now, copy all that again but assume that we had to do housekeeping:
        with mock.patch.object(self.library, 'chain_exists', side_effect=[True, False]), \
                mock.patch.object(self.library.nft, 'json_cmd') as mock_nft, \
                mock.patch.object(self.library, 'del_chain') as mock_delchain, \
                mock.patch.object(self.library, 'get_acls_for_user',
                                  return_value='q') as mock_acls, \
                mock.patch.object(self.library, 'create_user_rules') as mock_crea, \
                mock.patch.object(self.library, 'remove_safety_block') as mock_block, \
                mock.patch.object(self.library, 'send_event') as mock_logger:
            mock_nft.return_value = (0, '', '')
            result = self.library.add_chain()
        self.assertTrue(result, 'add_chain must be True even if it had to clean a chain out')
        mock_acls.assert_called_once_with()
        mock_crea.assert_called_once_with('q')
        mock_delchain.assert_called_once_with()
        # Collision cleanout triggers an event:
        mock_logger.assert_called_once()
        # Not deep-checking the nft call; the above test should do that.
        mock_nft.assert_called_once()
        mock_block.assert_called_once_with()

        # One last time, but fail the add:
        with mock.patch.object(self.library, 'chain_exists', return_value=False), \
                mock.patch.object(self.library.nft, 'json_cmd') as mock_nft, \
                mock.patch.object(self.library, 'get_acls_for_user',
                                  return_value='q') as mock_acls, \
                mock.patch.object(self.library, 'create_user_rules') as mock_crea, \
                mock.patch.object(self.library, 'remove_safety_block') as mock_block:
            mock_nft.return_value = (-1, '', '')
            with self.assertRaises(NftablesFailure,
                    msg='add_chain with a failure must raise'):
                self.library.add_chain()
        mock_acls.assert_called_once_with()
        mock_crea.assert_called_once_with('q')
        # Not deep-checking the nft call; the above test should do that.
        mock_nft.assert_called_once()
        # notice this non-call:
        mock_block.assert_not_called()
        # ^ this means a bad flaw can leave 'safety blocks' across IPs.  This is
        # SUPREMELY unlikely based on the design of the blocks, but this is a callout of
        # a weird situation and if you ever stumble over this, look at it closely.


    def test_19_del_chain(self):
        ''' Test del_chain function '''
        self.library.client_ip = '2.3.4.5'

        rule_to_delete_out = {
            'family': 'inet',
            'table': 'openvpn_netfilter',
            'chain': 'FORWARD',
            'handle': 13,
            'expr': [
                { 'match': {
                    'op': '==',
                    'left': { 'payload': { 'protocol': 'ip', 'field': 'saddr' }},
                    'right': self.library.client_ip}
                },
                { 'jump': { 'target': self.library.client_ip } }
            ]
        }
        rule_to_delete_in = {
            'family': 'inet',
            'table': 'openvpn_netfilter',
            'chain': 'FORWARD',
            'handle': 14,
            'expr': [
                { 'match': {
                    'op': '==',
                    'left': { 'payload': { 'protocol': 'ip', 'field': 'daddr' }},
                    'right': self.library.client_ip}
                },
                { 'jump': { 'target': self.library.client_ip } }
            ]
        }

        # Assume a delete works:
        search_obj = {"nftables": [
            # A rule with no expr, to test that we don't blow up there.
            {"rule": {"family": "inet"}},
            # A chain, to make sure that doesn't stop us.
            {"chain": {}},
            # The rules we want:
            {"rule": rule_to_delete_out},
            {"rule": rule_to_delete_in},
        ]}
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            # This return is a little odd, saying 'search_obj' a lot for
            # the list (correct) and the deletes (kinda wrong)
            mock_nft.return_value = (0, search_obj, '')
            res = self.library.del_chain()

        self.assertTrue(res, 'del_chain shoule be True on positive-success')
        # Four calls, the lookup, 2 rule deletes, and the delete of chain+set:
        self.assertEqual(mock_nft.call_count, 4)
        mock_nft.assert_any_call({'nftables': [
            {'list': {'chain': {
                'family': 'inet',
                'table': 'openvpn_netfilter',
                'name': 'FORWARD'}
            }}
        ]})
        mock_nft.assert_any_call({'nftables': [
            {'delete': {'rule': {'family': 'inet',
                                 'table': 'openvpn_netfilter',
                                 'chain': 'FORWARD',
                                 'handle': 13,}}}]})
        mock_nft.assert_any_call({'nftables': [
            {'delete': {'rule': {'family': 'inet',
                                 'table': 'openvpn_netfilter',
                                 'chain': 'FORWARD',
                                 'handle': 14,}}}]})
        mock_nft.assert_any_call({'nftables': [
            {'delete': {'chain': {'family': 'inet',
                                  'table': 'openvpn_netfilter',
                                  'name': self.library.client_ip,}}},
            {'delete': {'set': {'family': 'inet',
                                'table': 'openvpn_netfilter',
                                'type': 'ipv4_addr',
                                'name': self.library.client_ip,}}},
        ]})

        # OK so that was a lot.. that was "what if it all works".
        # What if a list lookup fails?
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (-1, 'somejson', '')
            with self.assertRaises(NftablesFailure,
                    msg='del_chain should raise on a botched lookup'):
                self.library.del_chain()

        # IMPROVEME - there are potential failures we've not thought of
        # or built tests for, because we've not seen them/thought of them.


    def test_30_build_fw_rule(self):
        ''' Test _build_firewall_rule_nftables function '''
        self.library.username_is = 'bob'

        in_acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='', address=IPNetwork('5.6.7.8'), portstring='80', description='')
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (0, '', '')
            self.library._build_firewall_rule_nftables('chain1', '1.2.3.4', 'tcp', in_acl1)
        mock_nft.assert_called_once_with({'nftables': [
            {'add': {'rule': {'family': 'inet',
                              'table': 'openvpn_netfilter',
                              'chain': 'chain1',
                              'comment': None,
                              'expr': [{'match': {
                                  'op': '==',
                                  'left': {'payload': { 'protocol': 'ip', 'field': 'saddr'}},
                                  'right': '1.2.3.4'}},
                                       {'match': {
                                  'op': '==',
                                  'left': {'payload': { 'protocol': 'ip', 'field': 'daddr'}},
                                  'right': '5.6.7.8/32'}},
                                       {'match': {
                                  'op': '==',
                                  'left': {'payload': { 'protocol': 'tcp', 'field': 'dport'}},
                                  'right': {'set': [80]}}},
                                       {'drop': None}]}}}]})
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (-1, '', 'someerror')
            with self.assertRaises(NftablesFailure,
                    msg='_build_firewall_rule_nftables raises when a rule add fails'):
                self.library._build_firewall_rule_nftables('chain1', '1.2.3.4', 'tcp', in_acl1)

        in_acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule2', address=IPNetwork('5.6.7.9'), portstring='80', description='I HAZ COMMENT')
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (0, '', '')
            self.library._build_firewall_rule_nftables('chain2', '1.2.3.4', 'tcp', in_acl2)
        mock_nft.assert_called_once_with({'nftables': [
            {'add': {'rule': {'family': 'inet',
                              'table': 'openvpn_netfilter',
                              'chain': 'chain2',
                              'comment': 'bob:rule2 ACL I HAZ COMMENT',
                              'expr': [{'match': {
                                  'op': '==',
                                  'left': {'payload': { 'protocol': 'ip', 'field': 'saddr'}},
                                  'right': '1.2.3.4'}},
                                       {'match': {
                                  'op': '==',
                                  'left': {'payload': { 'protocol': 'ip', 'field': 'daddr'}},
                                  'right': '5.6.7.9/32'}},
                                       {'match': {
                                  'op': '==',
                                  'left': {'payload': { 'protocol': 'tcp', 'field': 'dport'}},
                                  'right': {'set': [80]}}},
                                       {'drop': None}]}}}]})

        ip_set_acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='', address=IPNetwork('5.6.7.0/24'), portstring='', description='')
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (0, '', '')
            self.library._build_firewall_rule_nftables('chain3', '1.2.3.4', '', ip_set_acl1)
        mock_nft.assert_called_once_with({'nftables': [
            {'add': {'element': {'family': 'inet',
                                 'table': 'openvpn_netfilter',
                                 'name': 'chain3',
                                 'elem': [ { 'prefix': {
                                     'addr': '5.6.7.0',
                                     'len': 24 } }
                                 ]
                                 }}}]})
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (-1, '', 'someerror')
            with self.assertRaises(NftablesFailure,
                    msg='_build_firewall_rule_nftables raises when a set-element add fails'):
                self.library._build_firewall_rule_nftables('chain3', '1.2.3.4', '', ip_set_acl1)

        # comments don't work in nftables sets, so "the output here is the same"
        ip_set_acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule4', address=IPNetwork('5.6.7.11'), portstring='', description='IPSET SET SET')
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (0, '', '')
            self.library._build_firewall_rule_nftables('chain4', '1.2.3.4', '', ip_set_acl2)
        mock_nft.assert_called_once_with({'nftables': [
            {'add': {'element': {'family': 'inet',
                              'table': 'openvpn_netfilter',
                              'name': 'chain4',
                              'elem': ['5.6.7.11'] }}}]})


    def test_31_create_rules(self):
        ''' Test create_user_rules function '''
        self.library.username_is = 'larry'
        self.library.client_ip = '2.3.4.5'

        acl1 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule2', address=IPNetwork('5.6.7.9'), portstring='80', description='I HAZ COMMENT')
        acl2 = iamvpnlibrary.iamvpnbase.ParsedACL(
            rule='rule4', address=IPNetwork('5.6.7.11'), portstring='', description='IPSET SET SET')

        # Before we get too far into this, let's do the bad cases.
        # What if we can't make a chain/set for this person?
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft, \
                mock.patch.object(self.library, '_ensure_nftables_framework') as mock_framework:
            mock_nft.return_value = (-1, '', '')
            with self.assertRaises(NftablesFailure,
                    msg='create_user_rules raises when creation fails early'):
                self.library.create_user_rules([acl1, acl2])

        # What if we can make a chain/set for this person but then populating it fails?
        # skip going to _build_firewall_rule_nftables.. this failure check is to make sure
        # our final rule add is looked at.
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft, \
                mock.patch.object(self.library, '_build_firewall_rule_nftables'), \
                mock.patch.object(self.library, '_ensure_nftables_framework') as mock_framework:
            mock_nft.side_effect = [(0, '', ''),
                                    (-1, '', '')]
            with self.assertRaises(NftablesFailure,
                    msg='create_user_rules raises when creation fails in the second phase'):
                self.library.create_user_rules([acl1, acl2])

        # and now, the very complicated success route:
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft, \
                mock.patch.object(self.library, '_ensure_nftables_framework') as mock_framework:
            mock_nft.return_value = (0, '', '')
            self.library.create_user_rules([acl1, acl2])
        mock_framework.assert_called_once()
        # A lot just happened.  Time to check that nftables did the right things.
        # This is not necessarily written not in the order they were invoked.
        # Make the user chain and user set:
        self.assertEqual(mock_nft.call_count, 5)
        mock_nft.assert_any_call({'nftables': [
            {'add': {
                'chain': {
                    'family': 'inet',
                    'table': 'openvpn_netfilter',
                    'name': '2.3.4.5'
                    }
                }
            },
            {'add': {
                'set': {
                    'family': 'inet',
                    'table': 'openvpn_netfilter',
                    'type': 'ipv4_addr',
                    'name': '2.3.4.5',
                    'flags': ['interval']
                    }
                }
            }
            ]}
        )
        # This is a long one.  allow established and sets, log-drop anything else:
        mock_nft.assert_any_call({'nftables': [
            {'add': { 'rule': {
                'family': 'inet',
                'table': 'openvpn_netfilter',
                'chain': '2.3.4.5',
                'comment': 'larry at 2.3.4.5',
                'expr': [
                    {'match': {
                        'op': 'in',
                        'left': {'ct': {'key': 'state'}},
                        'right': [
                            'established',
                            'related',
                        ]},
                    },
                    {'accept': None}
                    ]
                }
            }},
            {'add': {'rule': {
                'family': 'inet',
                'table': 'openvpn_netfilter',
                'chain': '2.3.4.5',
                'expr': [
                    {'match': {
                        'op': '==',
                        'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                        'right': '2.3.4.5'}
                    },
                    {'match': {
                        'op': '==',
                        'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                        'right': '@2.3.4.5'}
                    },
                    {'accept': None}
                    ]
                }
            }},
            {'add': {'rule': {
                'family': 'inet',
                'table': 'openvpn_netfilter',
                'chain': '2.3.4.5',
                'expr': [
                    {'log': {
                        'prefix': 'DROP larry '}
                    }
                    ]
                }
            }},
            {'add': {'rule': {
                'family': 'inet',
                'table': 'openvpn_netfilter',
                'chain': '2.3.4.5',
                'expr': [
                    {'reject': {
                        'type': 'icmp',
                        'expr': 'admin-prohibited'}
                    }
                    ]
                }
            }}
            ]}
        )

        # And now the rules.  Two for a portstring:
        for test_proto in ('tcp', 'udp'):
            mock_nft.assert_any_call({'nftables': [
                {'add': {'rule': {
                    'family': 'inet',
                    'table': 'openvpn_netfilter',
                    'chain': '2.3.4.5',
                    'comment': 'larry:rule2 ACL I HAZ COMMENT',
                    'expr': [
                        {'match': {
                            'op': '==',
                            'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                            'right': '2.3.4.5'}
                        },
                        {'match': {
                            'op': '==',
                            'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                            'right': '5.6.7.9/32'}
                        },
                        {'match': {
                            'op': '==',
                            'left': {'payload': {'protocol': test_proto, 'field': 'dport'}},
                            'right': {'set': [80]}}
                        },
                        {'drop': None}]}
                }}
                ]}
            )

        # One item added into the set:
        mock_nft.assert_any_call({'nftables': [
            {'add': {'element': {
                'family': 'inet',
                'table': 'openvpn_netfilter',
                'name': '2.3.4.5',
                'elem': [
                    '5.6.7.11'
                ]}
            }}
            ]}
        )


    def test_32_ensure_nftables_framework(self):
        ''' Test _ensure_nftables_framework function '''

        # Assume everything is already there.  This is the most common case.
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.side_effect = [
                (0, '{"nftables": []}', ''),
                (0, '{"nftables": []}', '')
            ]
            res = self.library._ensure_nftables_framework()
        self.assertTrue(res)
        # 2 lists, all successful:
        self.assertEqual(mock_nft.call_count, 2)
        mock_nft.assert_any_call({'nftables': [
            {'list': {'table': {
                'family': 'inet',
                'name': 'openvpn_netfilter'}
            }}
        ]})
        mock_nft.assert_any_call({'nftables': [
            {'list': {'chain': {
                'family': 'inet',
                'table': 'openvpn_netfilter',
                'name': 'FORWARD',
                'type': 'filter',
                'hook': 'forward',
                'prio': -10,
                'policy': 'drop', }
            }}
        ]})

        # Assume nothing is already there.  This is the startup case.
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.side_effect = [
                (-1, '', 'no table'),
                (0, '', ''),
                (-1, '', 'no chain'),
                (0, '', ''),
            ]
            res = self.library._ensure_nftables_framework()
        self.assertTrue(res)
        # list add list add, all expected
        self.assertEqual(mock_nft.call_count, 4)
        for action in ('list', 'add'):
            mock_nft.assert_any_call({'nftables': [
                {action: {'table': {
                    'family': 'inet',
                    'name': 'openvpn_netfilter'}
                }}
            ]})
            mock_nft.assert_any_call({'nftables': [
                {action: {'chain': {
                    'family': 'inet',
                    'table': 'openvpn_netfilter',
                    'name': 'FORWARD',
                    'type': 'filter',
                    'hook': 'forward',
                    'prio': -10,
                    'policy': 'drop', }
                }}
            ]})

        # IMPROVEME: needs bad tests


    def test_add_safety(self):
        ''' Test add_safety_block function '''
        self.library.client_ip = '12345'

        # Assume an add works:
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft, \
                mock.patch.object(self.library, '_ensure_nftables_framework'):
            mock_nft.return_value = (0, 'somejson', '')
            res = self.library.add_safety_block()
        mock_nft.assert_called_once_with({'nftables': [
            {'add': {'rule': {'family': 'inet',
                              'table': 'openvpn_netfilter',
                              'chain': 'FORWARD',
                              'expr': [{'match': {'op': '==',
                                                  'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                                                  'right': '12345'}},
                                        {'drop': None}]}}}]})
        self.assertTrue(res, 'add_safety_block shoule be true on success')

        ### Assume an add fails:
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft, \
                mock.patch.object(self.library, '_ensure_nftables_framework'):
            mock_nft.return_value = (-1, 'somejson', '')
            with self.assertRaises(NftablesFailure,
                    msg='add_safety_block should raise on a botched delete'):
                self.library.add_safety_block()


    def test_del_safety(self):
        ''' Test add_safety_block function '''
        self.library.client_ip = '23456'

        good_rule_to_delete = {
            'family': 'inet',
            'table': 'openvpn_netfilter',
            'chain': 'FORWARD',
            'handle': 13,
            'expr': [
                { 'match': {
                    'op': '==',
                    'left': { 'payload': { 'protocol': 'ip', 'field': 'saddr' }},
                    'right': self.library.client_ip}
                },
                { 'drop': None }
            ]
        }

        # Assume a delete works:
        search_obj = {"nftables": [
            # A rule with no expr, to test that we don't blow up there.
            {"rule": {"family": "inet"}},
            # A chain, to make sure that doesn't stop us.
            {"chain": {}},
            # The rule we want:
            {"rule": good_rule_to_delete},
        ]}
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (0, search_obj, '')
            res = self.library.remove_safety_block()

        self.assertTrue(res, 'remove_safety_block shoule be True on positive-success')
        # Two calls, the lookup and the delete:
        mock_nft.assert_any_call({'nftables': [
            {'delete': {'rule': {'family': 'inet',
                                 'table': 'openvpn_netfilter',
                                 'chain': 'FORWARD',
                                 'handle': 13,}}}]})
        # The test that would happen if we could delete normally:
        #mock_nft.assert_any_call({'nftables': [
        #    {'delete': {'rule': {'family': 'inet',
        #                         'table': 'openvpn_netfilter',
        #                         'chain': 'FORWARD',
        #                         'expr': [{'match': {'op': '==',
        #                                             'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
        #                                             'right': '23456'}},
        #                                   {'drop': None}]}}}]})

        # Assume a delete finds no rule to delete:
        search_obj = {"nftables": [
            {"rule": {"family": "inet"}},
            {"chain": {}},
        ]}
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (0, search_obj, '')
            res = self.library.remove_safety_block()
        self.assertTrue(res, 'remove_safety_block shoule be True on no-rule-found')
        # One call, the lookup:
        mock_nft.assert_called_once()

        # Assume a delete fails:
        search_obj = {"nftables": [
            # A rule with no expr, to test that we don't blow up there.
            {"rule": {"family": "inet"}},
            # A chain, to make sure that doesn't stop us.
            {"chain": {}},
            # The rule we want:
            {"rule": good_rule_to_delete},
        ]}
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.side_effect = [(0, search_obj, ''),
                                    (-1, '', '')]
            with self.assertRaises(NftablesFailure,
                    msg='delete_safety_block should raise on a botched delete'):
                self.library.remove_safety_block()
            # Not checking the call; the above test should do that.

        # Assume a list blows out, SOMEHOW:
        with mock.patch.object(self.library.nft, 'json_cmd') as mock_nft:
            mock_nft.return_value = (-1, '{}', '')
            with self.assertRaises(NftablesFailure,
                    msg='delete_safety_block should raise on a botched lookup'):
                self.library.remove_safety_block()
            # Not checking the call; the above test should do that.
