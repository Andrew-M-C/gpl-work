#wput makefile
PACKAGE     = wput
prefix      = /usr/local
datadir     = $(prefix)/share
mandir	    = $(datadir)/man/man1
exec_prefix = ${prefix}
bindir=${exec_prefix}/bin

all clean:
	cd po && $(MAKE) $(MAKEDEFS) $@
	cd src && $(MAKE) $(MAKEDEFS) $@
	cd doc && $(MAKE) $(MAKEDEFS) $@

win-clean:
	cd src && $(MAKE) $(MAKEDEFS) $@

install: all
	cd po && $(MAKE) $(MAKEDEFS) $@
	install -m0755 wput $(bindir)
	install -m0644 doc/wput.1.gz $(mandir)
	@echo "----------------"
	@echo "Wput installed. See 'wput -h' or 'man wput' for usage information."
	@echo "Further documentation is located in the doc/USAGE.* files."
	@echo 
	@echo "Wput is not perfect, so please report any bugs you notice (see BUGS-section"
	@echo "in the manpage)."
	@echo "----------------"
uninstall:
	rm -f $(bindir)/wput
	rm -f $(mandir)/wput.1.gz
	
