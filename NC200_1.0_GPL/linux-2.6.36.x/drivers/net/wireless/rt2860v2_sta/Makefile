EXTRA_CFLAGS = -Idrivers/net/wireless/rt2860v2/include -Idrivers/net/wireless/rt2860v2/ate/include

obj-$(CONFIG_RT2860V2_STA) += rt2860v2_sta.o

rt2860v2_sta-objs += ../rt2860v2/common/crypt_md5.o
rt2860v2_sta-objs += ../rt2860v2/common/crypt_sha2.o
rt2860v2_sta-objs += ../rt2860v2/common/crypt_hmac.o
rt2860v2_sta-objs += ../rt2860v2/common/mlme.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_wep.o
rt2860v2_sta-objs += ../rt2860v2/common/action.o
rt2860v2_sta-objs += ../rt2860v2/common/ba_action.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_data.o
rt2860v2_sta-objs += ../rt2860v2/common/rtmp_init.o
rt2860v2_sta-objs += ../rt2860v2/common/rtmp_init_inf.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_tkip.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_aes.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_sync.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_sanity.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_info.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_wpa.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_radar.o
rt2860v2_sta-objs += ../rt2860v2/common/spectrum.o
rt2860v2_sta-objs += ../rt2860v2/common/rt_os_util.o

rt2860v2_sta-objs += ../rt2860v2/common/rtmp_timer.o
rt2860v2_sta-objs += ../rt2860v2/common/rt_channel.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_profile.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_asic.o
rt2860v2_sta-objs += ../rt2860v2/common/rtmp_swmcu.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_cfg.o
rt2860v2_sta-objs += ../rt2860v2/common/eeprom.o
rt2860v2_sta-objs += ../rt2860v2/common/ee_flash.o
rt2860v2_sta-objs += ../rt2860v2/common/ps.o

rt2860v2_sta-objs += ../rt2860v2/common/cmm_mac_pci.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_data_pci.o
rt2860v2_sta-objs += ../rt2860v2/common/crypt_aes.o
rt2860v2_sta-objs += ../rt2860v2/common/crypt_arc4.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_cmd.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_wpa_adhoc.o

rt2860v2_sta-objs += ../rt2860v2/rate_ctrl/ra_ctrl.o
rt2860v2_sta-objs += ../rt2860v2/rate_ctrl/alg_legacy.o

rt2860v2_sta-objs += ../rt2860v2/common/cmm_rf_cal.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_loft_cal.o

rt2860v2_sta-objs += ../rt2860v2/sta/assoc.o
rt2860v2_sta-objs += ../rt2860v2/sta/auth.o
rt2860v2_sta-objs += ../rt2860v2/sta/auth_rsp.o
rt2860v2_sta-objs += ../rt2860v2/sta/sync.o
rt2860v2_sta-objs += ../rt2860v2/sta/sanity.o
rt2860v2_sta-objs += ../rt2860v2/sta/rtmp_data.o
rt2860v2_sta-objs += ../rt2860v2/sta/connect.o
rt2860v2_sta-objs += ../rt2860v2/sta/wpa.o
rt2860v2_sta-objs += ../rt2860v2/sta/sta_cfg.o

rt2860v2_sta-objs += ../rt2860v2/os/linux/rt_proc.o
rt2860v2_sta-objs += ../rt2860v2/os/linux/rt_linux.o
rt2860v2_sta-objs += ../rt2860v2/os/linux/rt_profile.o
rt2860v2_sta-objs += ../rt2860v2/os/linux/rt_main_dev.o
rt2860v2_sta-objs += ../rt2860v2/os/linux/sta_ioctl.o
rt2860v2_sta-objs += ../rt2860v2/chips/rtmp_chip.o

rt2860v2_sta-objs += ../rt2860v2/ate/common/rt_ate.o
rt2860v2_sta-objs += ../rt2860v2/ate/common/rt_qa.o
rt2860v2_sta-objs += ../rt2860v2/ate/common/ate_pci.o

rt2860v2_sta-objs += ../rt2860v2/chips/rtmp_chip.o

rt2860v2_sta-objs +=  ../rt2860v2/os/linux/rbus_main_dev.o
rt2860v2_sta-objs +=  ../rt2860v2/os/linux/rt_pci_rbus.o
rt2860v2_sta-objs +=  ../rt2860v2/os/linux/rt_rbus_pci_util.o
rt2860v2_sta-objs +=  ../rt2860v2/os/linux/rt_rbus_pci_drv.o

ifeq ($(CONFIG_RALINK_RT2880),y)
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt2880.o
endif

ifeq ($(CONFIG_RALINK_RT2883),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/rt_rf.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt2883.o
endif

ifeq ($(CONFIG_RALINK_RT3883),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/rt_rf.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt3883.o
rt2860v2_sta-objs += ../rt2860v2/ate/chips/rt3883_ate.o
rt2860v2_sta-objs +=  ../rt2860v2/rate_ctrl/alg_grp.o
endif

ifeq ($(CONFIG_RALINK_RT3052),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/rt_rf.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt305x.o
endif

ifeq ($(CONFIG_RALINK_RT3352),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/rt_rf.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt305x.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt3352.o
endif

ifeq ($(CONFIG_RT3x52),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/rt_rf.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt305x.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt3352.o
endif

ifeq ($(CONFIG_RALINK_RT5350),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/rt_rf.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt305x.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt5350.o
endif

ifeq ($(CONFIG_RALINK_RT6352),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/rt_rf.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt6352.o
rt2860v2_sta-objs +=  ../rt2860v2/ate/chips/rt6352_ate.o
endif

ifeq ($(CONFIG_RALINK_MT7620),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/rt_rf.o
rt2860v2_sta-objs +=  ../rt2860v2/chips/rt6352.o
rt2860v2_sta-objs +=  ../rt2860v2/ate/chips/rt6352_ate.o
endif

ifeq ($(CONFIG_RT2860V2_STA_LED),y)
rt2860v2_sta-objs += ../rt2860v2/common/rt_led.o
endif

#ifeq ($(CONFIG_RT2860V2_STA_WMM_ACM),y)
#rt2860v2_sta-objs += ../rt2860v2/common/acm_edca.o
#rt2860v2_sta-objs += ../rt2860v2/common/acm_comm.o
#rt2860v2_sta-objs += ../rt2860v2/common/acm_iocl.o
#endif

#ifeq ($(CONFIG_RT2860V2_STA_WAPI),y)
#rt2860v2_sta-objs += ../rt2860v2/common/wapi.o
#rt2860v2_sta-objs += wapi_sms4.obj
#rt2860v2_sta-objs += wapi_crypt.obj
#endif

#ifeq ($(CONFIG_RT2860V2_RT3XXX_STA_ANTENNA_DIVERSITY),y)
#rt2860v2_sta-objs += ../rt2860v2/os/linux/ap_diversity.o
#endif

ifeq ($(CONFIG_RT2860V2_STA_DLS),y)
rt2860v2_sta-objs += ../rt2860v2/sta/dls.o
endif

ifeq ($(CONFIG_RT2860V2_STA_WSC),y)
rt2860v2_sta-objs += ../rt2860v2/common/wsc.o
rt2860v2_sta-objs += ../rt2860v2/common/wsc_tlv.o
rt2860v2_sta-objs += ../rt2860v2/common/crypt_biginteger.o
rt2860v2_sta-objs += ../rt2860v2/common/crypt_dh.o
endif

ifeq ($(CONFIG_RT2860V2_STA_WSC_V2),y)
rt2860v2_sta-objs += ../rt2860v2/common/wsc_v2.o
endif

ifeq ($(CONFIG_RT2860V2_STA_VIDEO_TURBINE),y)
rt2860v2_sta-objs += ../rt2860v2/common/cmm_video.o
endif

ifeq ($(CONFIG_RT2860V2_STA_P2P),y)
rt2860v2_sta-objs += ../rt2860v2/common/p2p_inf.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_mbss.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_assoc.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_auth.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_connect.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_mlme.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_sanity.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_sync.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_wpa.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_data.o
rt2860v2_sta-objs += ../rt2860v2/common/uapsd.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_autoChSel.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_qload.o
rt2860v2_sta-objs += ../rt2860v2/sta/p2pcli.o
rt2860v2_sta-objs += ../rt2860v2/sta/p2pcli_ctrl.o
rt2860v2_sta-objs += ../rt2860v2/sta/p2pcli_sync.o
rt2860v2_sta-objs += ../rt2860v2/sta/p2pcli_auth.o
rt2860v2_sta-objs += ../rt2860v2/sta/p2pcli_assoc.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_mat.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_mat_iparp.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_mat_pppoe.o
rt2860v2_sta-objs += ../rt2860v2/common/cmm_mat_ipv6.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_dbg.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_cfg.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_packet.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_action.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_table.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_ctrl.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_disc_mng.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_nego_mng.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_dbg.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_packet.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_action.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_table.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_ctrl.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_disc_mng.o
rt2860v2_sta-objs += ../rt2860v2/common/p2p_nego_mng.o
rt2860v2_sta-objs += ../rt2860v2/common/wsc.o
rt2860v2_sta-objs += ../rt2860v2/common/wsc_tlv.o
rt2860v2_sta-objs += ../rt2860v2/common/wsc_ufd.o
rt2860v2_sta-objs += ../rt2860v2/common/crypt_biginteger.o
rt2860v2_sta-objs += ../rt2860v2/common/crypt_dh.o
rt2860v2_sta-objs += ../rt2860v2/ap/ap_mbss_inf.o
rt2860v2_sta-objs += ../rt2860v2/common/rt_os_util.o
rt2860v2_sta-objs += ../rt2860v2/os/linux/ap_ioctl.o
rt2860v2_sta-objs += ../rt2860v2/os/linux/sta_ioctl.o
rt2860v2_sta-objs += ../rt2860v2/os/linux/rt_linux.o
rt2860v2_sta-objs += ../rt2860v2/os/linux/rt_main_dev.o
endif

ifeq ($(CONFIG_RT2860V2_STA_TXBF),y)
rt2860v2_sta-objs +=  ../rt2860v2/common/cmm_txbf.o
rt2860v2_sta-objs +=  ../rt2860v2/common/cmm_txbf_cal.o
endif

###################
#  CFLAGS
##################
EXTRA_CFLAGS += -DAGGREGATION_SUPPORT -DPIGGYBACK_SUPPORT -DWMM_SUPPORT  -DLINUX \
	       -Wall -Wstrict-prototypes -Wno-trigraphs 

EXTRA_CFLAGS += -DCONFIG_STA_SUPPORT -DDBG -DRALINK_ATE -DRALINK_QA -DRTMP_RBUS_SUPPORT -DRTMP_MAC_PCI
EXTRA_CFLAGS += -DDOT11_N_SUPPORT -DRELEASE_EXCLUDE -DSTATS_COUNT_SUPPORT
EXTRA_CFLAGS += -DCONFIG_RT2880_ATE_CMD_NEW -DCONFIG_SWMCU_SUPPORT
#EXTRA_CFLAGS += -DCONFIG_RA_NAT_NONE

ifeq ($(CONFIG_RALINK_RT2880),y)
EXTRA_CFLAGS += -DRT2880
endif

ifeq ($(CONFIG_RALINK_RT2883),y)
EXTRA_CFLAGS += -DRT2883 -DRTMP_RF_RW_SUPPORT -DDOT11N_SS3_SUPPORT -DCONFIG_RALINK_RT2883
ifeq ($(CONFIG_RT2860V2_STA_TXBF),y)
EXTRA_CFLAGS += -DTXBF_SUPPORT
endif
EXTRA_CFLAGS += -DSTREAM_MODE_SUPPORT
endif

ifeq ($(CONFIG_RALINK_RT3883),y)
EXTRA_CFLAGS += -DRT3883 -DRTMP_RF_RW_SUPPORT -DDOT11N_SS3_SUPPORT -DCONFIG_RALINK_RT3883 -DRTMP_FLASH_SUPPORT
ifeq ($(CONFIG_RT2860V2_STA_TXBF),y)
EXTRA_CFLAGS += -DTXBF_SUPPORT -DSTA_ITXBF_SUPPORT
endif
EXTRA_CFLAGS += -DSTREAM_MODE_SUPPORT
EXTRA_CFLAGS += -DRANGE_EXT_SUPPORT -DNEW_RATE_ADAPT_SUPPORT
endif

ifeq ($(CONFIG_RALINK_RT3052),y)
EXTRA_CFLAGS += -DSPECIFIC_VCORECAL_SUPPORT
ifeq ($(CONFIG_RALINK_RT3350),y)
EXTRA_CFLAGS += -DRT3350 -DRT305x -DRTMP_RF_RW_SUPPORT
else
EXTRA_CFLAGS += -DRT3052 -DRT305x -DRTMP_RF_RW_SUPPORT
endif
endif

ifeq ($(CONFIG_RALINK_RT3352),y)
EXTRA_CFLAGS += -DRT3352 -DRT305x -DRTMP_RF_RW_SUPPORT -DSPECIFIC_BCN_BUF_SUPPORT -DVCORECAL_SUPPORT
endif

ifeq ($(CONFIG_RT3x52),y)
EXTRA_CFLAGS += -DRT3052 -DRT3352 -DRT305x -DRTMP_RF_RW_SUPPORT -DSPECIFIC_BCN_BUF_SUPPORT -DVCORECAL_SUPPORT
endif

ifeq ($(CONFIG_RALINK_RT5350),y)
EXTRA_CFLAGS += -DRT5350 -DRT305x -DRTMP_RF_RW_SUPPORT -DVCORECAL_SUPPORT -DCONFIG_SWMCU_SUPPORT
endif

ifeq ($(CONFIG_RALINK_RT6352),y)
EXTRA_CFLAGS += -DRT6352 -DRTMP_RF_RW_SUPPORT -DRF_BANK -DRTMP_FLASH_SUPPORT -DCONFIG_SWMCU_SUPPORT
EXTRA_CFLAGS += -DRESOURCE_PRE_ALLOC
EXTRA_CFLAGS += -DVCORECAL_SUPPORT
EXTRA_CFLAGS += -DENHANCED_STAT_DISPLAY
EXTRA_CFLAGS += -DRTMP_TEMPERATURE_CALIBRATION
endif

ifeq ($(CONFIG_RALINK_MT7620),y)
EXTRA_CFLAGS += -DRT6352 -DRTMP_RF_RW_SUPPORT -DRF_BANK -DRTMP_FLASH_SUPPORT -DCONFIG_SWMCU_SUPPORT
EXTRA_CFLAGS += -DRESOURCE_PRE_ALLOC
EXTRA_CFLAGS += -DVCORECAL_SUPPORT
EXTRA_CFLAGS += -DENHANCED_STAT_DISPLAY
EXTRA_CFLAGS += -DRTMP_TEMPERATURE_CALIBRATION
endif

ifeq ($(CONFIG_RT2860V2_STA_WPA_SUPPLICANT),y)
EXTRA_CFLAGS += -DWPA_SUPPLICANT_SUPPORT
endif

#ifeq ($(CONFIG_RT2860V2_STA_WMM_ACM),y)
#EXTRA_CFLAGS += -DWMM_ACM_SUPPORT
#endif

ifeq ($(CONFIG_RT2860V2_STA_LED),y)
EXTRA_CFLAGS += -DLED_CONTROL_SUPPORT -DCONFIG_SWMCU_SUPPORT
ifeq ($(CONFIG_RT2860V2_STA_WSC),y)
EXTRA_CFLAGS += -DWSC_LED_SUPPORT
endif
endif

ifeq ($(CONFIG_RT2860V2_SNMP),y)
EXTRA_CFLAGS += -DSNMP_SUPPORT
endif

#ifeq ($(CONFIG_RT2860V2_STA_CARRIER),y)
#EXTRA_CFLAGS += -DCARRIER_DETECTION_SUPPORT
#endif

ifeq ($(CONFIG_RT2860V2_EXT_CHANNEL_LIST),y)
EXTRA_CFLAGS   += -DEXT_BUILD_CHANNEL_LIST
endif

#ifeq ($(CONFIG_RT2860V2_STA_IDS),y)
#EXTRA_CFLAGS += -DIDS_SUPPORT
#endif

ifeq ($(CONFIG_RT2860V2_STA_DLS),y)
EXTRA_CFLAGS += -DQOS_DLS_SUPPORT
endif

#ifeq ($(CONFIG_RT2860V2_STA_WAPI),y)
#EXTRA_CFLAGS += -DWAPI_SUPPORT
#ifeq ($(CONFIG_RALINK_RT3052),y)
#EXTRA_CFLAGS += -DSOFT_ENCRYPT
#endif
#endif

ifeq ($(CONFIG_RT2860V2_HW_STA_ANTENNA_DIVERSITY),y)
EXTRA_CFLAGS += -DHW_ANTENNA_DIVERSITY_SUPPORT
endif

ifeq ($(CONFIG_RT2860V2_STA_WSC),y)
EXTRA_CFLAGS += -DWSC_STA_SUPPORT
endif

ifeq ($(CONFIG_RT2860V2_STA_WSC_V2),y)
EXTRA_CFLAGS += -DWSC_V2_SUPPORT
endif

ifeq ($(CONFIG_RT2860V2_STA_VIDEO_TURBINE),y)
EXTRA_CFLAGS += -DVIDEO_TURBINE_SUPPORT
endif

ifeq ($(CONFIG_RA_NETWORK_WORKQUEUE_BH),y)
EXTRA_CFLAGS   += -DWORKQUEUE_BH
endif

ifeq ($(CONFIG_RT2860V2_STA_RTMP_INTERNAL_TX_ALC),y)
EXTRA_CFLAGS   += -DRTMP_INTERNAL_TX_ALC
endif

ifeq ($(CONFIG_RT2860V2_STA_INTELLIGENT_RATE_ADAPTION),y)
EXTRA_CFLAGS   += -DNEW_RATE_ADAPT_SUPPORT
endif

ifeq ($(CONFIG_RT2860V2_STA_80211N_DRAFT3),y)
EXTRA_CFLAGS += -DDOT11N_DRAFT3
endif

ifeq ($(CONFIG_RT2860V2_STA_P2P),y)
EXTRA_CFLAGS += -DP2P_SUPPORT -DAPCLI_SUPPORT -DMAT_SUPPORT -DAP_SCAN_SUPPORT -DP2P_APCLI_SUPPORT -DCONFIG_AP_SUPPORT -DCONFIG_APSTA_MIXED_SUPPORT -DUAPSD_SUPPORT -DMBSS_SUPPORT -DIAPP_SUPPORT -DDOT1X_SUPPORT -DAP_SCAN_SUPPORT -DWSC_AP_SUPPORT -DWSC_STA_SUPPORT
endif

ifeq ($(CONFIG_RT2860V2_STA_EDCCA_MONITOR),y)
EXTRA_CFLAGS += -DED_MONITOR
endif

