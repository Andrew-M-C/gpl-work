
APP_DIR = ppp-2.4.5
CONFIGURE_ARGS = 

ifeq ($(CROSS_COMPILE),mipsel-linux-)
CONFIGURE_ARGS := 
endif

ifdef SYSTEM_INCDIR
MAKE_ARGS = CFLAGS=-I$(SYSTEM_INCDIR) LDFLAGS=-L$(SYSTEM_LIBDIR)
endif

all:
	 -cd $(APP_DIR) && \
        if [ ! -f Makefile ]; then \
                $(MAKE_ARGS) ./configure $(CONFIGURE_ARGS); \
        fi && \
        make CC=$(CROSS_COMPILE)gcc

install:
	-cd $(APP_DIR) && \
	if [ "$(CROSS_COMPILE)" == "mipsel-linux-" ]; then \
		mipsel-linux-strip pppd/pppd; \
		cp -f pppd/pppd $(INSTALL_ROOT)/bin/; \
	fi

.PHONY: clean
clean:
	cd $(APP_DIR) && \
	make clean

distclean:
	cd $(APP_DIR) && \
	make dist-clean 
