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

top_builddir = ..

top_srcdir = ..
srcdir     = .

ANSI2KNR = 
o = .o

prefix       = /usr/local
exec_prefix  = ${prefix}
bindir       = ${exec_prefix}/bin
sysconfdir   = ${prefix}/etc
localedir    = $(prefix)/share/locale

DESTDIR      =

CC       = mipsel-linux-gcc
CPPFLAGS = 
# The following line is losing on some versions of make!
DEFS     = -DHAVE_CONFIG_H -DSYSTEM_WGETRC=\"$(sysconfdir)/wgetrc\" -DLOCALEDIR=\"$(localedir)\"
CFLAGS   =  -O2 -Wall -Wno-implicit
LDFLAGS  = 
LIBS     = -ldl  
exeext   = 

INCLUDES = -I. -I$(srcdir)

COMPILE = $(CC) $(INCLUDES) $(CPPFLAGS)  $(DEFS) $(CFLAGS)
LINK    = $(CC) $(CFLAGS) $(LDFLAGS) -o $@
INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
RM = rm -f
ETAGS = etags

# Conditional compiles
ALLOCA     = 
MD5_OBJ    = gen-md5$o gnu-md5$o
OPIE_OBJ   = ftp-opie$o
NTLM_OBJ   = 
SSL_OBJ    = 
GETOPT_OBJ = 

OBJ = $(ALLOCA) cmpt$o connect$o convert$o cookies$o              \
      ftp$o ftp-basic$o ftp-ls$o $(OPIE_OBJ) $(GETOPT_OBJ) hash$o \
      host$o html-parse$o html-url$o http$o $(NTLM_OBJ) init$o    \
      log$o main$o $(MD5_OBJ) netrc$o progress$o ptimer$o recur$o \
      res$o retr$o safe-ctype$o snprintf$o $(SSL_OBJ) url$o       \
      utils$o version$o xmalloc$o 

.SUFFIXES:
.SUFFIXES: .c .o ._c ._o

.c.o:
	$(COMPILE) -c $<

.c._c: $(ANSI2KNR)
	$(ANSI2KNR) $< > $*.tmp && mv $*.tmp $@

._c._o:
	@echo $(COMPILE) -c $<
	@rm -f _$*.c
	@ln $< _$*.c && $(COMPILE) -c _$*.c && mv _$*.o $@ && rm _$*.c

.c._o: $(ANSI2KNR)
	$(ANSI2KNR) $< > $*.tmp && mv $*.tmp $*._c
	@echo $(COMPILE) -c $*._c
	@rm -f _$*.c
	@ln $*._c _$*.c && $(COMPILE) -c _$*.c && mv _$*.o $@ && rm _$*.c

# Dependencies for building

wget$(exeext): $(OBJ)
	$(LINK) $(OBJ) $(LIBS)

ansi2knr: ansi2knr.o
	$(CC) -o ansi2knr ansi2knr.o $(LIBS)

# We make object files depend on every header.  Rather than attempt to
# track dependencies, everything gets recompiled when a header
# changes.  With a program of Wget's size this doesn't waste much
# time, and it's a lot safer than attempting to get all the
# dependencies right.

$(OBJ): $(ANSI2KNR) \
        config-post.h connect.h convert.h cookies.h ftp.h gen-md5.h \
        getopt.h gnu-md5.h hash.h host.h html-parse.h http-ntlm.h   \
        init.h log.h mswindows.h netrc.h options.h progress.h       \
        ptimer.h recur.h res.h retr.h safe-ctype.h ssl.h sysdep.h   \
        url.h utils.h wget.h xmalloc.h

#
# Dependencies for installing
#

install: install.bin

uninstall: uninstall.bin

install.bin: wget$(exeext)
	$(top_srcdir)/mkinstalldirs $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) wget$(exeext) $(DESTDIR)$(bindir)/wget$(exeext)

uninstall.bin:
	$(RM) $(DESTDIR)$(bindir)/wget$(exeext)

#
# Dependencies for cleanup
#

clean:
	$(RM) *.o wget$(exeext) *~ *.bak core core.[0-9]* $(ANSI2KNR) *._o *._c

distclean: clean
	$(RM) Makefile config.h

realclean: distclean
	$(RM) TAGS config.h.in

#
# Dependencies for maintenance
#

subdir = src

Makefile: Makefile.in ../config.status
	cd .. && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= ./config.status

TAGS: *.c *.h
	-$(ETAGS) *.c *.h
