INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr
PACKAGE := openvpn-netfilter
VERSION := 1.0.2

.DEFAULT: test
.PHONY: clean all test pep8 pylint pypi install rpm pythonrpm servicerpm

all: rpm

pythonrpm:
	fpm -s python -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d iptables -d ipset \
    --iteration 1 setup.py
	@rm -rf openvpn_netfilter.egg-info

# FIXME: summary  description   git?
servicerpm:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d python-$(PACKAGE) -d openvpn \
    -n $(PACKAGE) -v $(VERSION) \
    --url https://github.com/mozilla-it/openvpn-netfilter \
    -a noarch -C tmp etc usr
	rm -rf ./tmp

rpm: pythonrpm servicerpm

test:
	python -B -m unittest discover -f -s test

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 {} \;

pylint:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pylint -r no --disable=locally-disabled {} \;

pypi:
	python setup.py sdist check upload --sign

install:
	mkdir -p $(DESTDIR)$(PREFIX)/lib/openvpn/plugins
	mkdir -p $(DESTDIR)/etc/systemd/system/openvpn@.service.d
	mkdir -p $(DESTDIR)/etc/sudoers.d
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m755 wrappers/netfilter_openvpn.sh $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m755 wrappers/netfilter_openvpn_sync.py $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m755 wrappers/netfilter_openvpn_async.py $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m755 scripts/vpn-fw-find-user.sh $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m755 scripts/vpn-netfilter-cleanup-ip.py $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m440 sudoers.inc $(DESTDIR)/etc/sudoers.d/openvpn-netfilter
	$(INSTALL) -m644 systemd-only-kill-process.conf $(DESTDIR)/etc/systemd/system/openvpn@.service.d/only-kill-process.conf

clean:
	rm -f *.o
	rm -f *.so
	rm -f *.pyc
	rm -rf __pycache__
	rm -rf dist sdist build
	rm -rf openvpn_netfilter.egg-info
	rm -rf tmp
