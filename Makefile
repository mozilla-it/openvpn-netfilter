INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr
PACKAGE := openvpn-netfilter
VERSION := 1.0.1

all:
	./setup.py build

pyinstall:
	./setup.py install

rpm:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t rpm -d python-mozdef_client -n $(PACKAGE) -v $(VERSION) -C tmp etc usr

deb:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t deb -d python-mozdef_client -n $(PACKAGE) -v $(VERSION) -C tmp etc usr

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 {} \;

pylint:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pylint -r no --disable=locally-disabled {} \;

pypi:
	python setup.py sdist check upload --sign

install:
	mkdir -p $(DESTDIR)$(PREFIX)/lib/openvpn/plugins
	mkdir -p $(DESTDIR)/etc/openvpn
	mkdir -p $(DESTDIR)/etc/systemd/system/openvpn@.service.d
	mkdir -p $(DESTDIR)/etc/sudoers.d
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m755 netfilter_openvpn.py $(DESTDIR)$(PREFIX)/lib/openvpn/plugins
	$(INSTALL) -m755 netfilter_openvpn.sh $(DESTDIR)$(PREFIX)/lib/openvpn/plugins
	$(INSTALL) -m600 netfilter_openvpn.conf.inc $(DESTDIR)/etc/netfilter_openvpn.conf
	$(INSTALL) -m755 scripts/vpn-fw-find-user.sh $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m755 scripts/vpn-netfilter-cleanup-ip.sh $(DESTDIR)$(PREFIX)/bin
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
	rm -rf *.rpm
	rm -rf *.deb
