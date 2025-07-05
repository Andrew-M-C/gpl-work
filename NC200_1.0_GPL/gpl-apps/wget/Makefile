APP_DIR = wget-1.10.1
CONFIGURE_ARGS=
CROSS_COMPILE=mipsel-linux-
AR=$(CROSS_COMPILE)ar
CC=$(CROSS_COMPILE)gcc
STRIP=$(CROSS_COMPILE)strip

ifeq ($(CROSS_COMPILE),mipsel-linux-)
CONFIGURE_ARGS := --enable-my_feature --host=mipsel-linux $(CONFIGURE_ARGS)
endif

ifdef SYSTEM_INCDIR
MAKE_ARGS = CFLAGS=-I$(SYSTEM_INCDIR) LDFLAGS=-L$(SYSTEM_LIBDIR)
endif

all:
	-cd $(APP_DIR) && \
	if [ ! -f Makefile ]; then \
		$(MAKE_ARGS) ./configure $(CONFIGURE_ARGS); \
	fi && \
	make

install:
	-cd $(APP_DIR) && \
	if [ "$(CROSS_COMPILE)" == "mipsel-linux-" ]; then \
		$(STRIP) wget && \
		cp src/wget $(INSTALL_ROOT)/bin; \
	fi

.PHONY: clean
clean:
	cd $(APP_DIR) && \
	make clean

distclean:
	cd $(APP_DIR) && \
	make distclean

