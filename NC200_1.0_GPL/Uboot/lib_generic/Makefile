#
# (C) Copyright 2000-2002
# Wolfgang Denk, DENX Software Engineering, wd@denx.de.
#
# See file CREDITS for list of people who contributed to this
# project.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307 USA
#

include $(TOPDIR)/config.mk

LIB	= libgeneric.a

OBJS	= crc32.o ctype.o display_options.o string.o vsprintf.o
OBJS	+= rsa/rsa.o rsa/nn.o
OBJS	+= md5.o sha1.o
OBJS	+= tpRecovery.o

ifeq ($(CONFIG_GZIP),ON)
OBJS   += zlib.o
endif

ifeq ($(CONFIG_BZIP2),ON)
OBJS   += bzlib.o bzlib_crctable.o bzlib_randtable.o bzlib_decompress.o bzlib_huffman.o
endif

ifeq ($(CONFIG_LZMA),ON)
OBJS   += LzmaDecode.o
endif

ifeq ($(CONFIG_XZ),ON)
OBJS   += decompress_unxz.o xz_dec_bcj.o xz_dec_lzma2.o xz_dec_stream.o
endif

$(LIB):	.depend $(OBJS)
	$(AR) crv $@ $(OBJS)

#########################################################################

.depend:	Makefile $(OBJS:.o=.c)
		$(CC) -M $(CFLAGS) $(OBJS:.o=.c) > $@

sinclude .depend

#########################################################################
