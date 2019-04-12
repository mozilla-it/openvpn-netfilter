INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr
PACKAGE := openvpn-netfilter
VERSION := 1.0.4
TEST_FLAGS_FOR_SUITE := -m unittest discover -f -s test

.DEFAULT: test
.PHONY: all test coverage coveragereport pythonrpm servicerpm rpm pep8 pylint pypi install clean

all: rpm

test:
	python -B $(TEST_FLAGS_FOR_SUITE)

coverage:
	coverage run $(TEST_FLAGS_FOR_SUITE)

coveragereport:
	coverage report -m netfilter_openvpn.py test/*.py

pythonrpm:
	fpm -s python -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d iptables -d ipset \
    --iteration 1 setup.py
	@rm -rf openvpn_netfilter.egg-info

# FIXME: summary  description   git?
servicerpm:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d "python-$(PACKAGE) >= 1.1.4" -d openvpn \
    -n $(PACKAGE) -v $(VERSION) \
    --url https://github.com/mozilla-it/openvpn-netfilter \
    -a noarch -C tmp etc usr
	rm -rf ./tmp

rpm: pythonrpm servicerpm

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 --show-source --max-line-length=100 {} \;

pylint:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pylint -r no --disable=locally-disabled --rcfile=/dev/null {} \;

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
	rm -f netfilter_openvpn.pyc test/*.pyc
	rm -rf __pycache__
	rm -rf dist sdist build
	rm -rf openvpn_netfilter.egg-info
	rm -rf tmp
