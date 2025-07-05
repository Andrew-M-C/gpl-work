#CROSS_COMPILE=mipsel-linux-
#SYSTEM_INCDIR=/opt/RT288x_SDK/source/lib/include
#SYSTEM_LIBDIR=/opt/RT288x_SDK/source/lib/lib
SSL_INCDIR=/opt/RT288x_SDK/source/user/openssl-0.9.8e/include
SSL_LIBDIR=/opt/RT288x_SDK/source/user/openssl-0.9.8e/

APP_DIR = ssmtp-2.61
CONFIGURE_ARGS = --enable-ssl --enable-md5auth --enable-my_feature --disable-rewrite-domain

ifeq ($(CROSS_COMPILE),mipsel-linux-)
CONFIGURE_ARGS := --host=mipsel-linux $(CONFIGURE_ARGS)
endif

ifdef SYSTEM_INCDIR
MAKE_ARGS = CFLAGS='-I$(SYSTEM_INCDIR) -I$(SSL_INCDIR)' LDFLAGS='-L$(SYSTEM_LIBDIR) -lpthread -L$(SSL_LIBDIR)' CC=mipsel-linux-gcc
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
		mipsel-linux-strip ssmtp && \
		cp ssmtp $(INSTALL_ROOT)/bin; \
	fi

.PHONY: clean
clean:
	cd $(APP_DIR) && \
	make clean

distclean:
	cd $(APP_DIR) && \
	make distclean

