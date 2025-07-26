"""
    Setup script for the library.
    This packages the library file that integration scripts will use.
"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2019 Mozilla Corporation
# Author: gcox@mozilla.com
# derived from original Author: gdestuynder@mozilla.com

import os
import subprocess
from setuptools import setup

VERSION = '1.2.1'


def git_version():
    """ Return the git revision as a string """
    def _minimal_ext_cmd(cmd):
        # construct minimal environment
        env = {}
        for envvar in ['SYSTEMROOT', 'PATH']:
            val = os.environ.get(envvar)
            if val is not None:
                env[envvar] = val
        # LANGUAGE is used on win32
        env['LANGUAGE'] = 'C'
        env['LANG'] = 'C'
        env['LC_ALL'] = 'C'
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               env=env).communicate()[0]
        return out

    try:
        out = _minimal_ext_cmd(['git', 'rev-parse', 'HEAD'])
        git_revision = out.strip().decode('ascii')
    except OSError:
        git_revision = 'Unknown'

    return git_revision


setup(
    name='openvpn-netfilter',
    py_modules=['netfilter_openvpn'],
    version=VERSION,
    author='Greg Cox',
    author_email='gcox@mozilla.com',
    description=('A library to implement netfilter ' +
                 'rules per connected user\n' +
                 'This package is built upon commit ' + git_version()),
    license='MPL',
    keywords="vpn netfilter",
    url="https://github.com/mozilla-it/openvpn-netfilter",
    long_description=open('README.rst', 'r', encoding='utf-8').read(),
    install_requires=['iamvpnlibrary>=0.9.0'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: System :: Logging",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    ],
)
