#
# Makefile for the kernel character device drivers.
#

#
# This file contains the font map for the default (hardware) font
#
FONTMAPFILE = cp437.uni

obj-y	 += mem.o random.o tty_io.o n_tty.o tty_ioctl.o tty_ldisc.o tty_buffer.o tty_port.o

obj-y				+= tty_mutex.o
obj-$(CONFIG_LEGACY_PTYS)	+= pty.o
obj-$(CONFIG_UNIX98_PTYS)	+= pty.o
obj-y				+= misc.o
obj-$(CONFIG_VT)		+= vt_ioctl.o vc_screen.o selection.o keyboard.o
obj-$(CONFIG_BFIN_JTAG_COMM)	+= bfin_jtag_comm.o
obj-$(CONFIG_CONSOLE_TRANSLATIONS) += consolemap.o consolemap_deftbl.o
obj-$(CONFIG_HW_CONSOLE)	+= vt.o defkeymap.o
obj-$(CONFIG_AUDIT)		+= tty_audit.o
obj-$(CONFIG_MAGIC_SYSRQ)	+= sysrq.o
obj-$(CONFIG_MVME147_SCC)	+= generic_serial.o vme_scc.o
obj-$(CONFIG_MVME162_SCC)	+= generic_serial.o vme_scc.o
obj-$(CONFIG_BVME6000_SCC)	+= generic_serial.o vme_scc.o
obj-$(CONFIG_ROCKETPORT)	+= rocket.o
obj-$(CONFIG_SERIAL167)		+= serial167.o
obj-$(CONFIG_CYCLADES)		+= cyclades.o
obj-$(CONFIG_STALLION)		+= stallion.o
obj-$(CONFIG_ISTALLION)		+= istallion.o
obj-$(CONFIG_NOZOMI)		+= nozomi.o
obj-$(CONFIG_DIGIEPCA)		+= epca.o
obj-$(CONFIG_SPECIALIX)		+= specialix.o
obj-$(CONFIG_MOXA_INTELLIO)	+= moxa.o
obj-$(CONFIG_A2232)		+= ser_a2232.o generic_serial.o
obj-$(CONFIG_ATARI_DSP56K)	+= dsp56k.o
obj-$(CONFIG_MOXA_SMARTIO)	+= mxser.o
obj-$(CONFIG_COMPUTONE)		+= ip2/
obj-$(CONFIG_RISCOM8)		+= riscom8.o
obj-$(CONFIG_ISI)		+= isicom.o
obj-$(CONFIG_SYNCLINK)		+= synclink.o
obj-$(CONFIG_SYNCLINKMP)	+= synclinkmp.o
obj-$(CONFIG_SYNCLINK_GT)	+= synclink_gt.o
obj-$(CONFIG_N_HDLC)		+= n_hdlc.o
obj-$(CONFIG_N_GSM)		+= n_gsm.o
obj-$(CONFIG_AMIGA_BUILTIN_SERIAL) += amiserial.o
obj-$(CONFIG_SX)		+= sx.o generic_serial.o
obj-$(CONFIG_RIO)		+= rio/ generic_serial.o
obj-$(CONFIG_HVC_CONSOLE)	+= hvc_vio.o hvsi.o
obj-$(CONFIG_HVC_ISERIES)	+= hvc_iseries.o
obj-$(CONFIG_HVC_RTAS)		+= hvc_rtas.o
obj-$(CONFIG_HVC_TILE)		+= hvc_tile.o
obj-$(CONFIG_HVC_BEAT)		+= hvc_beat.o
obj-$(CONFIG_HVC_DRIVER)	+= hvc_console.o
obj-$(CONFIG_HVC_IRQ)		+= hvc_irq.o
obj-$(CONFIG_HVC_XEN)		+= hvc_xen.o
obj-$(CONFIG_HVC_IUCV)		+= hvc_iucv.o
obj-$(CONFIG_HVC_UDBG)		+= hvc_udbg.o
obj-$(CONFIG_VIRTIO_CONSOLE)	+= virtio_console.o
obj-$(CONFIG_RAW_DRIVER)	+= raw.o
obj-$(CONFIG_SGI_SNSC)		+= snsc.o snsc_event.o
obj-$(CONFIG_MSPEC)		+= mspec.o
obj-$(CONFIG_MMTIMER)		+= mmtimer.o
obj-$(CONFIG_UV_MMTIMER)	+= uv_mmtimer.o
obj-$(CONFIG_VIOTAPE)		+= viotape.o
obj-$(CONFIG_HVCS)		+= hvcs.o
obj-$(CONFIG_IBM_BSR)		+= bsr.o
obj-$(CONFIG_SGI_MBCS)		+= mbcs.o
obj-$(CONFIG_BRIQ_PANEL)	+= briq_panel.o
obj-$(CONFIG_BFIN_OTP)		+= bfin-otp.o

obj-$(CONFIG_PRINTER)		+= lp.o

obj-$(CONFIG_APM_EMULATION)	+= apm-emulation.o

obj-$(CONFIG_DTLK)		+= dtlk.o
obj-$(CONFIG_R3964)		+= n_r3964.o
obj-$(CONFIG_APPLICOM)		+= applicom.o
obj-$(CONFIG_SONYPI)		+= sonypi.o
obj-$(CONFIG_RTC)		+= rtc.o
obj-$(CONFIG_HPET)		+= hpet.o
obj-$(CONFIG_GEN_RTC)		+= genrtc.o
obj-$(CONFIG_EFI_RTC)		+= efirtc.o
obj-$(CONFIG_DS1302)		+= ds1302.o
obj-$(CONFIG_XILINX_HWICAP)	+= xilinx_hwicap/
ifeq ($(CONFIG_GENERIC_NVRAM),y)
  obj-$(CONFIG_NVRAM)	+= generic_nvram.o
else
  obj-$(CONFIG_NVRAM)	+= nvram.o
endif
obj-$(CONFIG_TOSHIBA)		+= toshiba.o
obj-$(CONFIG_I8K)		+= i8k.o
obj-$(CONFIG_DS1620)		+= ds1620.o
obj-$(CONFIG_HW_RANDOM)		+= hw_random/
obj-$(CONFIG_PPDEV)		+= ppdev.o
obj-$(CONFIG_NWBUTTON)		+= nwbutton.o
obj-$(CONFIG_NWFLASH)		+= nwflash.o
obj-$(CONFIG_SCx200_GPIO)	+= scx200_gpio.o
obj-$(CONFIG_PC8736x_GPIO)	+= pc8736x_gpio.o
obj-$(CONFIG_NSC_GPIO)		+= nsc_gpio.o
obj-$(CONFIG_CS5535_GPIO)	+= cs5535_gpio.o
obj-$(CONFIG_GPIO_TB0219)	+= tb0219.o
obj-$(CONFIG_TELCLOCK)		+= tlclk.o

obj-$(CONFIG_MWAVE)		+= mwave/
obj-$(CONFIG_AGP)		+= agp/
obj-$(CONFIG_PCMCIA)		+= pcmcia/
obj-$(CONFIG_IPMI_HANDLER)	+= ipmi/

obj-$(CONFIG_HANGCHECK_TIMER)	+= hangcheck-timer.o
obj-$(CONFIG_TCG_TPM)		+= tpm/

obj-$(CONFIG_PS3_FLASH)		+= ps3flash.o
obj-$(CONFIG_RAMOOPS)		+= ramoops.o

obj-$(CONFIG_RALINK_GPIO)	+= ralink_gpio.o
obj-$(CONFIG_TPLINK_4_PHASE_MOTOR)	+= tplink_4phase_motor.o
obj-$(CONFIG_RALINK_HSDMA)	+= hs_dma.o
#obj-$(CONFIG_RALINK_HSDMA)	+= hs_dma_test.o
#obj-$(CONFIG_RALINK_HSDMA)	+= mem_test.o
obj-$(CONFIG_RALINK_GDMA)	+= ralink_gdma.o 
#obj-$(CONFIG_RALINK_GDMA)	+= gdma_test.o
obj-$(CONFIG_RALINK_SPI) 	+= spi_drv.o 
obj-$(CONFIG_RALINK_I2C) 	+= i2c_drv.o
obj-$(CONFIG_RALINK_PCM)	+= pcm/
obj-$(CONFIG_RALINK_I2S)	+= i2s/
obj-$(CONFIG_RALINK_SPDIF)      += spdif/

obj-$(CONFIG_JS_RTC)		+= js-rtc.o
js-rtc-y = rtc.o

# Files generated that shall be removed upon make clean
clean-files := consolemap_deftbl.c defkeymap.c

quiet_cmd_conmk = CONMK   $@
      cmd_conmk = scripts/conmakehash $< > $@

$(obj)/consolemap_deftbl.c: $(src)/$(FONTMAPFILE)
	$(call cmd,conmk)

$(obj)/defkeymap.o:  $(obj)/defkeymap.c

# Uncomment if you're changing the keymap and have an appropriate
# loadkeys version for the map. By default, we'll use the shipped
# versions.
# GENERATE_KEYMAP := 1

ifdef GENERATE_KEYMAP

$(obj)/defkeymap.c: $(obj)/%.c: $(src)/%.map
	loadkeys --mktable $< > $@.tmp
	sed -e 's/^static *//' $@.tmp > $@
	rm $@.tmp

endif
