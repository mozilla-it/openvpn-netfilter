%define     prefix  /usr

Name:	    openvpn-netfilter
Version:	1.0
Release:	1%{?dist}
Packager:   Ed Lim <limed@mozilla.com>
Summary:	Openvpn netfilter plugin

Group:		Utilities/Misc
License:	MPL
URL:		https://openvpn.net/
Source0:	openvpn-netfilter-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

Requires:   openvpn, python, python-ldap, python-mozdef, iptables, ipset

%description
Openvpn netfilter is a plugin that dynamically creates iptable rules for a VPN user
to deny and grant access to a server. This is done via LDAP groups as well as having the ipHostNumber
attribute in LDAP.

Using the ipHostNumber attribute in ldap netfilter_openvpn builts iptable rules based on the user that
logs in to the VPN server.


%prep
%setup -q

%build


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}


%files
%defattr(0755,root,root)
%{prefix}/lib/openvpn/plugins/netfilter_openvpn.sh
%{prefix}/lib/openvpn/plugins/netfilter_openvpn.py
%{prefix}/lib/openvpn/plugins/netfilter_openvpn.pyc
%{prefix}/lib/openvpn/plugins/netfilter_openvpn.pyo
%{prefix}/bin/vpn-fw-find-user.sh
%{prefix}/bin/vpn-netfilter-cleanup-ip.sh
%attr(0440,root,root)/etc/sudoers.d/openvpn-netfilter
%attr(0640,root,openvpn) %config(noreplace) %verify(not md5 size mtime)/etc/netfilter_openvpn.conf

%changelog
* Thu Jul 10 2014 Ed Lim <limed@mozilla.com>
    - Initial spec file creation
