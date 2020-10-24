INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr
PACKAGE := openvpn-netfilter
VERSION := 1.1.5
.DEFAULT: coverage
.PHONY: coverage coveragereport pep8 pylint pythonrpm rpm pythonrpm2 pythonrpm3 servicerpm pypi install clean
TEST_FLAGS_FOR_SUITE := -m unittest discover -f

PLAIN_PYTHON = $(shell which python 2>/dev/null)
PYTHON3 = $(shell which python3 2>/dev/null)
ifneq (, $(PYTHON3))
  PYTHON_BIN = $(PYTHON3)
  PY_PACKAGE_PREFIX = python3
  RPM_MAKE_TARGET = pythonrpm3
endif
ifneq (, $(PLAIN_PYTHON))
  PYTHON_BIN = $(PLAIN_PYTHON)
  PY_PACKAGE_PREFIX = python
  RPM_MAKE_TARGET = pythonrpm2
endif

COVERAGE2 = $(shell which coverage 2>/dev/null)
COVERAGE3 = $(shell which coverage-3 2>/dev/null)
ifneq (, $(COVERAGE2))
  COVERAGE = $(COVERAGE2)
endif
ifneq (, $(COVERAGE3))
  COVERAGE = $(COVERAGE3)
endif


coverage:
	$(COVERAGE) run $(TEST_FLAGS_FOR_SUITE) -s test
	@rm -rf test/__pycache__
	@rm -f netfilter_openvpn.pyc test/*.pyc

coveragereport:
	$(COVERAGE) report -m netfilter_openvpn.py test/*.py

pythonrpm:  $(RPM_MAKE_TARGET)

pythonrpm2:
	fpm -s python -t rpm --python-bin $(PYTHON_BIN) --python-package-name-prefix $(PY_PACKAGE_PREFIX) --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d iptables -d ipset \
    --iteration 1 setup.py
	@rm -rf openvpn_netfilter.egg-info

pythonrpm3:
	fpm -s python -t rpm --python-bin $(PYTHON_BIN) --python-package-name-prefix $(PY_PACKAGE_PREFIX) --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d iptables -d ipset \
    --iteration 1 setup.py
	@rm -rf openvpn_netfilter.egg-info

# FIXME: summary  description   git?
servicerpm:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d "$(PY_PACKAGE_PREFIX)-$(PACKAGE) >= 1.1.4" -d openvpn \
    -n $(PACKAGE) -v $(VERSION) \
    --url https://github.com/mozilla-it/openvpn-netfilter \
    --iteration 1 \
    -a noarch -C tmp etc usr
	rm -rf ./tmp

rpm:  pythonrpm servicerpm

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 --show-source --max-line-length=100 {} \;

pylint:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -path ./test -prune -o -type f -name '*.py' -exec pylint -r no --disable=useless-object-inheritance,superfluous-parens --rcfile=/dev/null {} \;
	@find ./test -type f -name '*.py' -exec pylint -r no --disable=useless-object-inheritance,protected-access,locally-disabled,too-many-public-methods --rcfile=/dev/null {} \;

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
	sed -i "1c#!$(PYTHON_BIN)" $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/*.py $(DESTDIR)$(PREFIX)/bin/*.py

clean:
	rm -f netfilter_openvpn.pyc test/*.pyc
	rm -rf __pycache__
	rm -rf dist sdist build
	rm -rf openvpn_netfilter.egg-info
	rm -rf tmp
