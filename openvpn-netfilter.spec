%define	debug_package %{nil}
%define prefix  /usr

Name:           openvpn-netfilter
Version:        1.0
Release:        2%{?dist}
Packager:       Ed Lim <limed@mozilla.com>
Summary:        OpenVPN netfilter plugin

BuildArch:	noarch
Group:          Utilities/Misc
License:        MPL
URL:            https://github.com/mozilla-it/%{name}
Source0:        https://github.com/mozilla-it/%{name}/archive/master.zip
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Requires:       openvpn, python, python-ldap, python-mozdef_client, iptables, ipset

%description
%{name} is a plugin that dynamically creates iptables rules for
a VPN user to deny and grant access to a server.  This is done via
LDAP groups as well as having the ipHostNumber attribute in LDAP.

Using the ipHostNumber attribute in ldap netfilter_openvpn builds iptables
rules based on the user that logs in to the VPN server.

%package utils
Summary:	Utility scripts for %{name}
Group:		Utilities/Misc
License:	MPL
Requires:	iptables, ipset

%description utils
Scripts which are not essential for the core functioning of %{name}, but
are helpful for humans who will interact with it.


%prep
%setup -n %{name}-master

%build

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}


%files
%defattr(0755,root,root)
%{prefix}/lib/openvpn/plugins/netfilter_openvpn.sh
%{prefix}/lib/openvpn/plugins/netfilter_openvpn.py
%{prefix}/lib/openvpn/plugins/netfilter_openvpn.pyc
%exclude %{prefix}/lib/openvpn/plugins/netfilter_openvpn.pyo
%attr(0440,root,root)/etc/sudoers.d/openvpn-netfilter
%attr(0640,root,openvpn) %config(noreplace) %verify(not md5 size mtime)/etc/netfilter_openvpn.conf

%files utils
%defattr(0755,root,root)
%{prefix}/bin/vpn-fw-find-user.sh
%{prefix}/bin/vpn-netfilter-cleanup-ip.sh


%changelog
* Sat Feb 10 2018 gcox <gcox@mozilla.com>
    - Stop packaging .pyo because PEP 488
    - Split utilities into separate package
    - Build based on a github checkout

* Thu Jul 10 2014 Ed Lim <limed@mozilla.com>
    - Initial spec file creation
