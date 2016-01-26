INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr

all:
	./setup.py build

#This replaces the install target, which is kept for legacy compat purposes, or if you want to use a real RPM file instead of fpm.
pyinstall:
	./setup.py install

rpm:
	fpm -s python -t rpm -d mozdef_client ./setup.py

deb:
	fpm -s python -t deb ./setup.py

pypi:
	python setup.py sdist check upload --sign

install:
	mkdir -p $(DESTDIR)$(PREFIX)/lib/openvpn/plugins
	mkdir -p $(DESTDIR)/etc/openvpn
	mkdir -p $(DESTDIR)/etc/sudoers.d
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m755 netfilter_openvpn.py $(DESTDIR)$(PREFIX)/lib/openvpn/plugins
	$(INSTALL) -m755 netfilter_openvpn.sh $(DESTDIR)$(PREFIX)/lib/openvpn/plugins
	$(INSTALL) -m600 netfilter_openvpn.conf.inc $(DESTDIR)/etc/netfilter_openvpn.conf
	$(INSTALL) -m755 scripts/vpn-fw-find-user.sh $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m755 scripts/vpn-netfilter-cleanup-ip.sh $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m440 sudoers.inc $(DESTDIR)/etc/sudoers.d/openvpn-netfilter

clean:
	rm -f *.o
	rm -f *.so
	rm -f *.pyc
	rm -rf __pycache__
