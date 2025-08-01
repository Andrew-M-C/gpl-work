# Makefile for `wget' utility
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

#
# Version: 1.10.1
#

SHELL = /bin/sh

# Program to format Texinfo source into Info files.
MAKEINFO = true
# Program to format Texinfo source into DVI files.
TEXI2DVI = texi2dvi
# Program to convert DVI files to PostScript
DVIPS = dvips -D 300
# Program to convert texinfo files to html
TEXI2HTML = texi2html -expandinfo -split_chapter

top_builddir = ..

top_srcdir = ..
srcdir     = .


prefix     = /usr/local
infodir    = ${prefix}/info
mandir     = ${prefix}/man
manext     = 1
sysconfdir = ${prefix}/etc

DESTDIR    =

INSTALL      = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
RM = rm -f

TEXI2POD     = texi2pod.pl
POD2MAN      = /usr/bin/pod2man
MAN          = wget.$(manext)
WGETRC       = $(sysconfdir)/wgetrc
SAMPLERCTEXI = sample.wgetrc.munged_for_texi_inclusion

#
# Dependencies for building
#

all: wget.info $(MAN)

everything: all wget_us.ps wget_a4.ps wget_toc.html

$(SAMPLERCTEXI): $(srcdir)/sample.wgetrc
	sed s/@/@@/g $? > $@

wget.info: $(srcdir)/wget.texi $(SAMPLERCTEXI) $(srcdir)/version.texi
	$(MAKEINFO) -I$(srcdir) $(srcdir)/wget.texi

$(TEXI2POD): $(srcdir)/$(TEXI2POD).in
	sed 's,^#! /usr/bin/perl,#! /usr/bin/perl,' $? > $@
	chmod u+x $@

wget.pod: $(srcdir)/wget.texi $(TEXI2POD) $(srcdir)/version.texi
	./$(TEXI2POD) $(srcdir)/wget.texi $@

$(MAN): wget.pod
	$(POD2MAN) --center="GNU Wget" --release="GNU Wget 1.10.1" $? > $@

#wget.cat: $(MAN)
#	nroff -man $? > $@

dvi: wget.dvi

wget.dvi: $(srcdir)/wget.texi
	$(TEXI2DVI) $(srcdir)/wget.texi

wget_us.ps: wget.dvi
	$(DVIPS) -t letter -o $@ wget.dvi

wget_a4.ps: wget.dvi
	$(DVIPS) -t a4 -o $@ wget.dvi

wget_toc.html: $(srcdir)/wget.texi
	$(TEXI2HTML) $(srcdir)/wget.texi

#
# Dependencies for installing
#

# install all the documentation
install: install.info install.wgetrc install.man

# uninstall all the documentation
uninstall: uninstall.info uninstall.man

# install info pages, creating install directory if necessary
# if the info pages are built in the build directory, they are used.
# otherwise, the ones from the distribution are installed.
install.info: wget.info
	$(top_srcdir)/mkinstalldirs $(DESTDIR)$(infodir)
	-if test -f wget.info; then \
	  for file in wget.info wget.info-*[0-9]; do \
            if test -f "$$file"; then \
	      $(INSTALL_DATA) "$$file" "$(DESTDIR)$(infodir)/$$file" ; \
	    fi; \
	  done; \
	else \
	  for file in $(srcdir)/wget.info $(srcdir)/wget.info-*[0-9]; do \
            if test -f "$$file"; then \
	      $(INSTALL_DATA) "$$file" "$(DESTDIR)$(infodir)/`basename $$file`" ; \
	    fi; \
	  done; \
	fi

# install man page, creating install directory if necessary
install.man: $(MAN)
	$(top_srcdir)/mkinstalldirs $(DESTDIR)$(mandir)/man$(manext)
	$(INSTALL_DATA) $(MAN) $(DESTDIR)$(mandir)/man$(manext)/$(MAN)

# install sample.wgetrc
install.wgetrc: $(srcdir)/sample.wgetrc
	$(top_srcdir)/mkinstalldirs $(DESTDIR)$(sysconfdir)
	@if test -f $(DESTDIR)$(WGETRC); then \
	  if cmp -s $(srcdir)/sample.wgetrc $(DESTDIR)$(WGETRC); then echo ""; \
	     else \
	     echo ' $(INSTALL_DATA) $(srcdir)/sample.wgetrc $(DESTDIR)$(WGETRC).new'; \
	     $(INSTALL_DATA) $(srcdir)/sample.wgetrc $(DESTDIR)$(WGETRC).new; \
	     echo; \
	     echo "WARNING: Differing \`$(DESTDIR)$(WGETRC)'"; \
	     echo "         exists and has been spared.  You might want to"; \
	     echo "         consider merging in the new lines from"; \
	     echo "         \`$(DESTDIR)$(WGETRC).new'."; \
	     echo; \
	  fi; \
	else \
	  $(INSTALL_DATA) $(srcdir)/sample.wgetrc $(DESTDIR)$(WGETRC); \
	fi

# uninstall info pages
uninstall.info:
	$(RM) $(DESTDIR)$(infodir)/wget.info*

# uninstall man page
uninstall.man:
	$(RM) $(DESTDIR)$(mandir)/man$(manext)/$(MAN)

#
# Dependencies for cleanup
#

clean:
	$(RM) *~ *.bak *.cat *.pod *.html
	$(RM) *.dvi *.aux *.cp *.cps *.fn *.toc *.tp *.vr *.ps *.ky *.pg *.log

distclean: clean
	$(RM) Makefile
	$(RM) $(MAN) $(TEXI2POD)

realclean: distclean
	$(RM) wget.info*
	$(RM) $(SAMPLERCTEXI)

#
# Dependencies for maintenance
#

subdir = doc

Makefile: Makefile.in ../config.status
	cd .. && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= ./config.status
