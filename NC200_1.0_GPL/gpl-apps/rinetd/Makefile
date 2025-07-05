
APP_DIR = rinetd-0.62
all:
	-cd $(APP_DIR) && \
	make 

install:
	-cd $(APP_DIR) && \
	if [ "$(CROSS_COMPILE)" == "mipsel-linux-" ]; then \
		mipsel-linux-strip ./rinetd; \
		cp ./rinetd $(INSTALL_ROOT)/bin; \
	fi

.PHONY: clean
clean:
	cd $(APP_DIR) && \
	make clean

distclean:
	cd $(APP_DIR) && \
	make clean

