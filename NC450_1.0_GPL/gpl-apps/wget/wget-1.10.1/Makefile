# Makefile for `Wget' utility
# Copyright (C) 1995, 1996, 1997 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

# In addition, as a special exception, the Free Software Foundation
# gives permission to link the code of its release of Wget with the
# OpenSSL project's "OpenSSL" library (or with modified versions of it
# that use the same license as the "OpenSSL" library), and distribute
# the linked executables.  You must obey the GNU General Public License
# in all respects for all of the code used other than "OpenSSL".  If you
# modify this file, you may extend this exception to your version of the
# file, but you are not obligated to do so.  If you do not wish to do
# so, delete this exception statement from your version.

#
# Version: 1.10.1
#

SHELL = /bin/sh


top_builddir = .

srcdir = .


#
# User configuration section
#

#
# Install variables
#
prefix      = /usr/local
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/bin
infodir     = ${prefix}/info
sysconfdir  = ${prefix}/etc
mandir      = ${prefix}/man
manext      = 1
localedir   = $(prefix)/share/locale

CC = mipsel-linux-gcc
CFLAGS =  -O2 -Wall -Wno-implicit
CPPFLAGS = 
DEFS = -DHAVE_CONFIG_H -DSYSTEM_WGETRC=\"$(sysconfdir)/wgetrc\" -DLOCALEDIR=\"$(localedir)\"
LIBS = -ldl  
LDFLAGS = 

#
# End of user configuration section.  There should be no need to change
# anything below this line.
#

DISTNAME = wget-1.10.1
RM = rm -f

# These are used for maintenance only, so they are safe without
# special autoconf cruft.
FIND = find
GZIP = gzip
TAR = tar

# flags passed to recursive makes in subdirectories
MAKEDEFS = CC='$(CC)' CPPFLAGS='$(CPPFLAGS)' DEFS='$(DEFS)' \
CFLAGS='$(CFLAGS)' LDFLAGS='$(LDFLAGS)' LIBS='$(LIBS)' \
prefix='$(prefix)' exec_prefix='$(exec_prefix)' bindir='$(bindir)' \
infodir='$(infodir)' mandir='$(mandir)' manext='$(manext)'

# subdirectories in the distribution
SUBDIRS = src doc po util windows

# default target
all: src/config.h Makefile $(SUBDIRS)

check: all

$(SUBDIRS): FORCE
	cd $@ && $(MAKE) $(MAKEDEFS)

# install everything
install: install.bin install.info install.wgetrc \
	 install.mo install.man

# install/uninstall the binary
install.bin uninstall.bin:
	cd src && $(MAKE) $(MAKEDEFS) $@

# install/uninstall the info/man pages
install.info uninstall.info install.man uninstall.man install.wgetrc:
	cd doc && $(MAKE) $(MAKEDEFS) $@

# Install `.mo' files
install.mo:
	cd po && $(MAKE) $(MAKEDEFS) $@

# Create configure.bat from configure.bat.in by DOS-ifying the lines.
# This is invoked by `make dist' and deleted by `make realclean' (not
# `make distclean' because we want to preserve it for distribution).
configure.bat: $(srcdir)/configure.bat.in
	awk '{ print $$0 ($$0 ~ /\r$$/ ? "" : "\r") }' $< > $@

# create tag files for Emacs
TAGS:
	cd src && $(MAKE) $@

dist: $(srcdir)/configure $(srcdir)/configure.bat DISTFILES
	mkdir $(DISTNAME)
	for d in `$(FIND) . -type d ! -name CVS -a ! -name RCS -print`; do \
		if [ "$$d" != "." -a "$$d" != "./$(DISTNAME)" ]; then \
			mkdir $(DISTNAME)/$$d; \
		fi; \
	done
	for f in `cat DISTFILES`; do \
		ln $(srcdir)/$$f $(DISTNAME)/$$f || \
		{ echo copying $$f; cp -p $(srcdir)/$$f $(DISTNAME)/$$f ; } \
	done
	(cd $(DISTNAME); $(MAKE) distclean)
	$(TAR) chvf - $(DISTNAME) | $(GZIP) -c --best >$(DISTNAME).tar.gz
	$(RM) -r $(DISTNAME)
	$(RM) DISTFILES

DISTFILES: FORCE
	rm -rf $(DISTNAME)	
	(cd $(srcdir); find . ! -type d -print) \
	| sed '/\/\(CVS\|RCS\)\//d; /$@/d; /\.tar.*/d; s/^.\///; /^\.$$/d;' \
	| sort | uniq > $@

#
# Cleanup dependencies
#

clean:		clean-recursive		clean-top
distclean:	distclean-recursive	distclean-top
realclean:	realclean-recursive	realclean-top

clean-top:
	$(RM) *~ *.bak $(DISTNAME).tar.gz

distclean-top: clean-top
	$(RM) Makefile config.status config.log config.cache libtool stamp-h
	$(RM) -r autom4te.cache

realclean-top: distclean-top
	$(RM) configure configure.bat

clean-recursive distclean-recursive realclean-recursive:
	for subdir in $(SUBDIRS); do \
	   target=`echo $@ | sed s/-recursive//`; \
	   (cd $$subdir && $(MAKE) $(MAKEDEFS) $$target) || exit 1; \
	done

#
# Dependencies for maintenance
#

$(srcdir)/configure: configure.in
	cd $(srcdir) && autoconf

# autoheader might not change config.h.in, so touch a stamp file.
$(srcdir)/src/config.h.in: stamp-h.in
$(srcdir)/stamp-h.in: configure.in
	@true; # running autoheader here breaks: cd $(srcdir) && autoheader
	echo timestamp > $(srcdir)/stamp-h.in

src/config.h: stamp-h
stamp-h: src/config.h.in config.status
	./config.status

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck

FORCE:
