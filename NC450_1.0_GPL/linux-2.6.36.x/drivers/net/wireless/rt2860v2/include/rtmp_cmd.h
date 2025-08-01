#ifndef __RTMP_CMD_H__
#define __RTMP_CMD_H__

#include "rtmp_type.h"

typedef struct _CmdQElmt {
	UINT command;
	PVOID buffer;
	ULONG bufferlength;
	BOOLEAN CmdFromNdis;
	BOOLEAN SetOperation;
	struct _CmdQElmt *next;
} CmdQElmt, *PCmdQElmt;

typedef struct _CmdQ {
	UINT size;
	CmdQElmt *head;
	CmdQElmt *tail;
	UINT32 CmdQState;
} CmdQ, *PCmdQ;

#define EnqueueCmd(cmdq, cmdqelmt)		\
{										\
	if (cmdq->size == 0)				\
		cmdq->head = cmdqelmt;			\
	else								\
		cmdq->tail->next = cmdqelmt;	\
	cmdq->tail = cmdqelmt;				\
	cmdqelmt->next = NULL;				\
	cmdq->size++;						\
}

#define NDIS_OID	UINT

/* OS_RTCMDUp is only used in UTIL/NETIF module */
#define OS_RTCMDUp						RtmpOsCmdUp


#if defined(RTMP_MAC_PCI) || defined(RTMP_RBUS_SUPPORT)
#define CMDTHREAD_CHAN_RESCAN					0x0D730101
#define CMDTHREAD_REG_HINT						0x0D730102
#define CMDTHREAD_REG_HINT_11D					0x0D730103
#define CMDTHREAD_SCAN_END						0x0D730104
#define CMDTHREAD_CONNECT_RESULT_INFORM			0x0D730105
#endif /* RTMP_MAC_PCI || RTMP_RBUS_SUPPORT */

/* RALINK command status code */
#define RTMP_IO_EINVAL							30000
#define RTMP_IO_EOPNOTSUPP						30001
#define RTMP_IO_EFAULT							30002
#define RTMP_IO_ENETDOWN						30003
#define RTMP_IO_E2BIG							30004
#define RTMP_IO_ENOMEM							30005
#define RTMP_IO_EAGAIN							30006
#define RTMP_IO_ENOTCONN						30007

enum {
#ifdef MAT_SUPPORT
	SHOW_IPV4_MAT_INFO = 1,
	SHOW_IPV6_MAT_INFO = 2,
	SHOW_ETH_CLONE_MAC = 3,
#endif /* MAT_SUPPORT */
	SHOW_CONN_STATUS = 4,
	SHOW_DRVIER_VERION = 5,
	SHOW_BA_INFO = 6,
	SHOW_DESC_INFO = 7,
	RAIO_OFF = 10,
	RAIO_ON = 11,
#ifdef QOS_DLS_SUPPORT
	SHOW_DLS_ENTRY_INFO = 20,
#endif /* QOS_DLS_SUPPORT */
	SHOW_CFG_VALUE = 21,
	SHOW_ADHOC_ENTRY_INFO = 22,
#ifdef DOT11Z_TDLS_SUPPORT
	SHOW_TDLS_ENTRY_INFO = 25,
#endif /* DOT11Z_TDLS_SUPPORT */
};

#ifdef CONFIG_STA_SUPPORT
#ifdef WSC_STA_SUPPORT
enum {
	WSC_CREDENTIAL_COUNT = 1,
	WSC_CREDENTIAL_SSID = 2,
	WSC_CREDENTIAL_AUTH_MODE = 3,
	WSC_CREDENTIAL_ENCR_TYPE = 4,
	WSC_CREDENTIAL_KEY_INDEX = 5,
	WSC_CREDENTIAL_KEY = 6,
	WSC_CREDENTIAL_MAC = 7,
	WSC_SET_DRIVER_CONNECT_BY_CREDENTIAL_IDX = 8,
	WSC_SET_DRIVER_AUTO_CONNECT = 9,
	WSC_SET_CONF_MODE = 10,	/* Enrollee or Registrar */
	WSC_SET_MODE = 11,	/* PIN or PBC */
	WSC_SET_PIN = 12,
	WSC_SET_SSID = 13,
	WSC_START = 14,
	WSC_STOP = 15,
	WSC_GEN_PIN_CODE = 16,
	WSC_AP_BAND = 17,
	WSC_SET_BSSID = 18,
};
#endif /* WSC_STA_SUPPORT */

#ifdef WPA_SUPPLICANT_SUPPORT
#ifndef NATIVE_WPA_SUPPLICANT_SUPPORT
#define	RT_ASSOC_EVENT_FLAG                         0x0101
#define	RT_DISASSOC_EVENT_FLAG                      0x0102
#define	RT_REQIE_EVENT_FLAG                         0x0103
#define	RT_RESPIE_EVENT_FLAG                        0x0104
#define	RT_ASSOCINFO_EVENT_FLAG                     0x0105
#define RT_PMKIDCAND_FLAG                           0x0106
#define RT_INTERFACE_DOWN                           0x0107
#define RT_INTERFACE_UP                             0x0108
#endif /* NATIVE_WPA_SUPPLICANT_SUPPORT */
#endif /* WPA_SUPPLICANT_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */

/* RALINK command handle ID */
/* ap commands */
typedef enum _CMD_RTPRIV_IOCTL_AP {

	/* general */
	CMD_RTPRIV_IOCTL_SET_WSCOOB = 0x0001,
	CMD_RTPRIV_IOCTL_GET_MAC_TABLE,
	CMD_RTPRIV_IOCTL_GSITESURVEY,
	CMD_RTPRIV_IOCTL_STATISTICS,
	CMD_RTPRIV_IOCTL_QUERY_BATABLE,
	CMD_RTPRIV_IOCTL_E2P,
	CMD_RTPRIV_IOCTL_BBP,
	CMD_RTPRIV_IOCTL_MAC,
	CMD_RTPRIV_IOCTL_RF,
	CMD_RT_PRIV_IOCTL,
	CMD_RTPRIV_IOCTL_SET,
	CMD_RTPRIV_IOCTL_SHOW,
	CMD_RTPRIV_IOCTL_GET_AR9_SHOW,
	CMD_RTPRIV_IOCTL_ATE,
	CMD_RTPRIV_IOCTL_CHID_2_FREQ,
	CMD_RTPRIV_IOCTL_FREQ_2_CHID,
	CMD_RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT,

	/* mbss */
	CMD_RTPRIV_IOCTL_MBSS_BEACON_UPDATE,
	CMD_RTPRIV_IOCTL_MBSS_OPEN,
	CMD_RTPRIV_IOCTL_MBSS_CLOSE,
	CMD_RTPRIV_IOCTL_MBSS_INIT,
	CMD_RTPRIV_IOCTL_MBSS_REMOVE,

	/* wsc */
	CMD_RTPRIV_IOCTL_WSC_PROFILE,
	CMD_RTPRIV_IOCTL_WSC_INIT,

	/* apc */
	CMD_RTPRIV_IOCTL_APC_UP,
	CMD_RTPRIV_IOCTL_APC_DISCONNECT,
	CMD_RTPRIV_IOCTL_APC_INIT,
	CMD_RTPRIV_IOCTL_APC_OPEN,
	CMD_RTPRIV_IOCTL_APC_CLOSE,
	CMD_RTPRIV_IOCTL_APC_REMOVE,

	/* interface */
	CMD_RTPRIV_IOCTL_MAIN_OPEN,

	/* ioctl */
	CMD_RTPRIV_IOCTL_PREPARE,
	CMD_RTPRIV_IOCTL_AP_SIOCGIWAP,
	CMD_RTPRIV_IOCTL_AP_SIOCGIFHWADDR,
	CMD_RTPRIV_IOCTL_AP_SIOCGIWESSID,
	CMD_RTPRIV_IOCTL_AP_SIOCGIWRATEQ,
	CMD_RTPRIV_IOCTL_AP_SIOCSIWGENIE,

	CMD_RTPRIV_IOCTL_CONN_STATUS,
	/* can not exceed 0x5000 */
} CMD_RTPRIV_IOCTL_AP;

/* common commands */
typedef enum _CMD_RTPRIV_IOCTL_COMMON {

	/* general */
	CMD_RTPRIV_IOCTL_NETDEV_GET = 0x5000,
	CMD_RTPRIV_IOCTL_NETDEV_SET,
	CMD_RTPRIV_IOCTL_OPMODE_GET,
	CMD_RTPRIV_IOCTL_TASK_LIST_GET,
	CMD_RTPRIV_IOCTL_IRQ_INIT,
	CMD_RTPRIV_IOCTL_IRQ_RELEASE,
	CMD_RTPRIV_IOCTL_MSI_ENABLE,
	CMD_RTPRIV_IOCTL_NIC_NOT_EXIST,
#ifdef CONFIG_APSTA_MIXED_SUPPORT
	CMD_RTPRIV_IOCTL_MAX_IN_BIT,
#endif /* CONFIG_APSTA_MIXED_SUPPORT */
#ifdef CONFIG_STA_SUPPORT
#ifdef CONFIG_PM
#ifdef USB_SUPPORT_SELECTIVE_SUSPEND
	CMD_RTPRIV_IOCTL_USB_DEV_GET,
	CMD_RTPRIV_IOCTL_USB_INTF_GET,
	CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_SET,
	CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_CLEAR,
	CMD_RTPRIV_IOCTL_ADAPTER_SEND_DISSASSOCIATE,
	CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_TEST,
	CMD_RTPRIV_IOCTL_ADAPTER_IDLE_RADIO_OFF_TEST,
	CMD_RTPRIV_IOCTL_ADAPTER_RT28XX_USB_ASICRADIO_OFF,
	CMD_RTPRIV_IOCTL_ADAPTER_RT28XX_USB_ASICRADIO_ON,
#ifdef WOW_SUPPORT
#endif /* WOW_SUPPORT */
#endif /* USB_SUPPORT_SELECTIVE_SUSPEND */
#endif /* CONFIG_PM */
	CMD_RTPRIV_IOCTL_AP_BSSID_GET,
#endif /* CONFIG_STA_SUPPORT */
	CMD_RTPRIV_IOCTL_SANITY_CHECK,
	CMD_RTPRIV_IOCTL_SANITY_CHECK_ON_SET_CMD,	
#ifdef EXT_BUILD_CHANNEL_LIST
	CMD_RTPRIV_SET_PRECONFIG_VALUE,
#endif /* EXT_BUILD_CHANNEL_LIST */


	/* mesh */
	CMD_RTPRIV_IOCTL_MESH_INIT,
	CMD_RTPRIV_IOCTL_MESH_REMOVE,
	CMD_RTPRIV_IOCTL_MESH_OPEN_PRE,
	CMD_RTPRIV_IOCTL_MESH_OPEN_POST,
	CMD_RTPRIV_IOCTL_MESH_IS_VALID,
	CMD_RTPRIV_IOCTL_MESH_CLOSE,

	/* p2p */
	CMD_RTPRIV_IOCTL_P2P_INIT,
	CMD_RTPRIV_IOCTL_P2P_REMOVE,
	CMD_RTPRIV_IOCTL_P2P_OPEN_PRE,
	CMD_RTPRIV_IOCTL_P2P_OPEN_POST,
	CMD_RTPRIV_IOCTL_P2P_IS_VALID,
	CMD_RTPRIV_IOCTL_P2P_CLOSE,

	/* usb */
	CMD_RTPRIV_IOCTL_USB_MORE_FLAG_SET,
	CMD_RTPRIV_IOCTL_USB_CONFIG_INIT,
	CMD_RTPRIV_IOCTL_USB_SUSPEND,
	CMD_RTPRIV_IOCTL_USB_RESUME,

	/* pci */
	CMD_RTPRIV_IOCTL_PCI_SUSPEND,
	CMD_RTPRIV_IOCTL_PCI_RESUME,
	CMD_RTPRIV_IOCTL_PCI_CSR_SET,
	CMD_RTPRIV_IOCTL_PCIE_INIT,

	/* cfg80211 */
	CMD_RTPRIV_IOCTL_CFG80211_CFG_START,

	/* inf ppa */
	CMD_RTPRIV_IOCTL_INF_PPA_INIT,
	CMD_RTPRIV_IOCTL_INF_PPA_EXIT,

	/* wireless */
	CMD_RTPRIV_IOCTL_BEACON_UPDATE,
	CMD_RTPRIV_IOCTL_RXPATH_GET,
	CMD_RTPRIV_IOCTL_CHAN_LIST_NUM_GET,
	CMD_RTPRIV_IOCTL_CHAN_LIST_GET,
	CMD_RTPRIV_IOCTL_FREQ_LIST_GET,

	/* interface */
	CMD_RTPRIV_IOCTL_VIRTUAL_INF_UP,
	CMD_RTPRIV_IOCTL_VIRTUAL_INF_DOWN,
	CMD_RTPRIV_IOCTL_VIRTUAL_INF_GET,
	CMD_RTPRIV_IOCTL_INF_TYPE_GET,
	CMD_RTPRIV_IOCTL_INF_STATS_GET,
	CMD_RTPRIV_IOCTL_INF_IW_STATUS_GET,
	CMD_RTPRIV_IOCTL_INF_MAIN_CREATE,
	CMD_RTPRIV_IOCTL_INF_MAIN_ID_GET,
	CMD_RTPRIV_IOCTL_INF_MAIN_CHECK,
	CMD_RTPRIV_IOCTL_INF_P2P_CHECK,

	/* ioctl */
	CMD_RTPRIV_IOCTL_SIOCGIWFREQ,
	CMD_RTPRIV_IOCTL_SIOCGIWNAME,

	/* wds */
	CMD_RTPRIV_IOCTL_WDS_INIT,
	CMD_RTPRIV_IOCTL_WDS_REMOVE,
	CMD_RTPRIV_IOCTL_WDS_STATS_GET,

	CMD_RTPRIV_IOCTL_MAC_ADDR_GET,

#ifdef RT_CFG80211_SUPPORT
	/* cfg802.11 */
	/* Note: All cfg commands must be continue. */
	CMD_RTPRIV_IOCTL_80211_START,
	CMD_RTPRIV_IOCTL_80211_CB_GET,
	CMD_RTPRIV_IOCTL_80211_CB_SET,
	CMD_RTPRIV_IOCTL_80211_CHAN_SET,
	CMD_RTPRIV_IOCTL_80211_VIF_CHG,
	CMD_RTPRIV_IOCTL_80211_SCAN,
	CMD_RTPRIV_IOCTL_80211_IBSS_JOIN,
	CMD_RTPRIV_IOCTL_80211_STA_LEAVE,
	CMD_RTPRIV_IOCTL_80211_STA_GET,
	CMD_RTPRIV_IOCTL_80211_KEY_ADD,
	CMD_RTPRIV_IOCTL_80211_KEY_DEFAULT_SET,
	CMD_RTPRIV_IOCTL_80211_CONNECT_TO,
	CMD_RTPRIV_IOCTL_80211_RFKILL,
	CMD_RTPRIV_IOCTL_80211_REG_NOTIFY_TO,
	CMD_RTPRIV_IOCTL_80211_UNREGISTER,
	CMD_RTPRIV_IOCTL_80211_BANDINFO_GET,
	CMD_RTPRIV_IOCTL_80211_SURVEY_GET,
	CMD_RTPRIV_IOCTL_80211_END,
#endif /* RT_CFG80211_SUPPORT */

	CMD_RTPRIV_IOCTL_ADAPTER_TSO_SUPPORT_TEST,

	/* can not exceed 0xa000 */
	CMD_RTPRIV_IOCTL_80211_COM_LATEST_ONE,
} CMD_RTPRIV_IOCTL_COMMON;

#ifdef RT_CFG80211_SUPPORT
typedef struct __CMD_RTPRIV_IOCTL_80211_CHAN {

	UINT8 ChanId;

#define RT_CMD_80211_IFTYPE_STATION		0x00
#define RT_CMD_80211_IFTYPE_ADHOC		0x01
#define RT_CMD_80211_IFTYPE_MONITOR		0x02
	UINT8 IfType;

#define RT_CMD_80211_CHANTYPE_NOHT		0x00
#define RT_CMD_80211_CHANTYPE_HT20		0x01
#define RT_CMD_80211_CHANTYPE_HT40MINUS	0X02
#define RT_CMD_80211_CHANTYPE_HT40PLUS	0X03
	UINT8 ChanType;

	UINT32 MonFilterFlag;
} CMD_RTPRIV_IOCTL_80211_CHAN;

#define RT_CMD_80211_FILTER_FCSFAIL		0x01
#define RT_CMD_80211_FILTER_PLCPFAIL	0x02
#define RT_CMD_80211_FILTER_CONTROL		0x04
#define RT_CMD_80211_FILTER_OTHER_BSS	0x08

typedef struct __CMD_RTPRIV_IOCTL_80211_IBSS {

	UINT32 BeaconInterval;
	UCHAR *pSsid;
} CMD_RTPRIV_IOCTL_80211_IBSS;

typedef struct __CMD_RTPRIV_IOCTL_80211_STA {

	UINT8 MAC[6];
	ULONG DataRate;

#define RT_CMD_80211_TXRATE_LEGACY		0x01
#define RT_CMD_80211_TXRATE_BW_40		0x02
#define RT_CMD_80211_TXRATE_SHORT_GI	0x04
	UINT32 TxRateFlags;
	
	UINT32 TxRateMCS;
	INT32 Signal;
	UINT32 TxPacketCnt;
	UINT32 InactiveTime;
} CMD_RTPRIV_IOCTL_80211_STA;

typedef struct __CMD_RTPRIV_IOCTL_80211_KEY {

#define RT_CMD_80211_KEY_WEP			0x00
#define RT_CMD_80211_KEY_WPA			0x01
	UINT8 KeyType;
	UINT8 KeyBuf[50];
	UINT8 KeyId;
} CMD_RTPRIV_IOCTL_80211_KEY;

typedef struct __CMD_RTPRIV_IOCTL_80211_CONNECT {

	UINT8 WpaVer;
	BOOLEAN FlgIs8021x;
	BOOLEAN FlgIsAuthOpen;

#define RT_CMD_80211_CONN_ENCRYPT_NONE	0x01
#define RT_CMD_80211_CONN_ENCRYPT_WEP	0x02
#define RT_CMD_80211_CONN_ENCRYPT_TKIP	0x04
#define RT_CMD_80211_CONN_ENCRYPT_CCMP	0x08
	UINT8 PairwiseEncrypType;
	UINT8 GroupwiseEncrypType;

	UINT8 *pKey;
	UINT32 KeyLen;
	UINT8 KeyIdx;

	UINT8 *pSsid;
	UINT32 SsidLen;
} CMD_RTPRIV_IOCTL_80211_CONNECT;

typedef struct __CMD_RTPRIV_IOCTL_80211_REG_NOTIFY {

	UCHAR Alpha2[2];
	VOID *pWiphy;
} CMD_RTPRIV_IOCTL_80211_REG_NOTIFY;

typedef struct __CMD_RTPRIV_IOCTL_80211_SURVEY {

	VOID *pCfg80211;
/*	UINT64 ChannelTime; */ /* idle + busy, not support */
	UINT64 ChannelTimeBusy;
	UINT64 ChannelTimeExtBusy;
} CMD_RTPRIV_IOCTL_80211_SURVEY;

#endif /* RT_CFG80211_SUPPORT */

/* station commands */
#ifdef CONFIG_STA_SUPPORT
typedef enum _CMD_RTPRIV_IOCTL_STATION {

	/* general */
	CMD_RTPRIV_IOCTL_PARAM_SET = 0xa000,
	CMD_RTPRIV_IOCTL_SITESURVEY_GET,
	CMD_RTPRIV_IOCTL_SITESURVEY,
	CMD_RTPRIV_IOCTL_ORI_DEV_TYPE_SET,
	CMD_RTPRIV_IOCTL_STA_SCAN_SANITY_CHECK,
	CMD_RTPRIV_IOCTL_STA_SCAN_END,

	/* wireless */
	CMD_RTPRIV_IOCTL_BSS_LIST_GET,

	/* standard ioctl */
	CMD_RTPRIV_IOCTL_STA_SIOCSIWFREQ,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWFREQ,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWMODE,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWMODE,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWAP,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWAP,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWSCAN,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWSCAN,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWESSID,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWESSID,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWNICKN,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWNICKN,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWRTS,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWRTS,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWFRAG,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWFRAG,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWENCODE,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWENCODE,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWMLME,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWAUTH,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWAUTH,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWENCODEEXT,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWENCODEEXT,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWGENIE,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWGENIE,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWPMKSA,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWRATE,
	CMD_RTPRIV_IOCTL_STA_SIOCGIWRATE,
	CMD_RTPRIV_IOCTL_STA_SIOCGIFHWADDR,
	CMD_RTPRIV_IOCTL_STA_SIOCSIWPRIVRSSI,

	CMD_RTPRIV_IOCTL_STA_IW_SET_WSC_U32_ITEM,
	CMD_RTPRIV_IOCTL_STA_IW_SET_WSC_STR_ITEM,
	CMD_RTPRIV_IOCTL_STA_IW_GET_STATISTICS,
} CMD_RTPRIV_IOCTL_STATION;

#define RT_CMD_MODE_ADHOC								0x01
#define RT_CMD_MODE_INFRA								0x02
#define RT_CMD_MODE_MONITOR								0x03
#endif /* CONFIG_STA_SUPPORT */

/* when adding any new type, please also add codes in LINUX_WEVENT_TRANSLATE */
#define RT_WLAN_EVENT_CUSTOM							0x01
#define RT_WLAN_EVENT_CGIWAP							0x02
#define RT_WLAN_EVENT_ASSOC_REQ_IE						0x03
#define RT_WLAN_EVENT_SCAN								0x04
#define RT_WLAN_EVENT_EXPIRED							0x05
#define RT_WLAN_EVENT_SHOWPIN							0x06
#define RT_WLAN_EVENT_PIN							0x07

typedef struct __RT_CMD_RATE_SET {
	IN UINT32 Rate;
	IN UINT32 Fixed;
} RT_CMD_RATE_SET;

typedef struct __RT_CMD_PARAM_SET {
	IN PSTRING pThisChar;
	IN PSTRING pValue;
} RT_CMD_PARAM_SET;

typedef struct __RT_CMD_SHARED_KEY_ADD {
	IN UCHAR KeyIdx;
	IN BOOLEAN FlgHaveGTK;
} RT_CMD_SHARED_KEY_ADD;

typedef struct __RT_CMD_MBSS_KICKOUT {
	IN INT BssId;
	IN USHORT Reason;
} RT_CMD_MBSS_KICKOUT;

typedef struct __RT_CMD_USB_MORE_FLAG_CONFIG {
	IN UINT32 VendorID;
	IN UINT32 ProductID;
} RT_CMD_USB_MORE_FLAG_CONFIG;

typedef struct __RT_CMD_USB_DEV_CONFIG {
	IN UINT NumberOfPipes;
	IN UINT BulkInEpAddr;
	IN USHORT BulkInMaxPacketSize;
	IN UINT BulkOutEpAddr[6];
	IN USHORT BulkOutMaxPacketSize;
	IN VOID *pConfig;
} RT_CMD_USB_DEV_CONFIG;

typedef struct __RT_CMD_CFG80211_CONFIG {
	IN VOID *pCfgDev;
	IN VOID(
	*CFG80211_Register) (
	IN VOID * pAd,
	IN VOID * pDev,
	IN VOID * pNetDev);
} RT_CMD_CFG80211_CONFIG;

typedef struct __RT_CMD_WAIT_QUEUE_LIST {
	OUT RTMP_OS_TASK *pMlmeTask;
	OUT RTMP_OS_TASK *pTimerTask;
	OUT RTMP_OS_TASK *pCmdQTask;
	OUT RTMP_OS_TASK *pWscTask;
} RT_CMD_WAIT_QUEUE_LIST;

typedef struct __RT_CMD_INF_UP_DOWN {

	IN	int (*rt28xx_open)(VOID *net_dev);
	IN	int (*rt28xx_close)(VOID *net_dev);
} RT_CMD_INF_UP_DOWN;

typedef struct __RT_CMD_STATS {
	IN VOID *pNetDev;
	OUT VOID *pStats;	/* point to pAd->stats */

	OUT unsigned long rx_packets;	/* total packets received       */
	OUT unsigned long tx_packets;	/* total packets transmitted */
	OUT unsigned long rx_bytes;	/* total bytes received         */
	OUT unsigned long tx_bytes;	/* total bytes transmitted      */
	OUT unsigned long rx_errors;	/* bad packets received         */
	OUT unsigned long tx_errors;	/* packet transmit problems     */
	OUT unsigned long multicast;	/* multicast packets received */
	OUT unsigned long collisions;

	OUT unsigned long rx_over_errors;	/* receiver ring buff overflow  */
	OUT unsigned long rx_crc_errors;	/* recved pkt with crc error    */
	OUT unsigned long rx_frame_errors;	/* recv'd frame alignment error */
	OUT unsigned long rx_fifo_errors;	/* recv'r fifo overrun                  */
} RT_CMD_STATS;

typedef struct __RT_CMD_IW_STATS {

	ULONG priv_flags;
	UCHAR *dev_addr;

	VOID *pStats;		/* point to pAd->iw_stats */

	UINT8 qual;
	UINT8 level;
	UINT8 noise;
	UINT8 updated;
} RT_CMD_IW_STATS;

typedef struct __RT_CMD_PCIE_INIT {

	IN VOID *pPciDev;
	IN UINT32 ConfigDeviceID;
	IN UINT32 ConfigSubsystemVendorID;
	IN UINT32 ConfigSubsystemID;
} RT_CMD_PCIE_INIT;

typedef struct __RT_CMD_AP_IOCTL_CONFIG {
	IN VOID *net_dev;
	IN ULONG priv_flags;
	IN char *pCmdData;
	IN INT32 CmdId_RTPRIV_IOCTL_SET;
	IN char *name;
	IN INT apidx;

	OUT INT32 Status;
} RT_CMD_AP_IOCTL_CONFIG;

typedef struct __RT_CMD_AP_IOCTL_SSID {
	IN ULONG priv_flags;
	IN INT apidx;

	OUT char *pSsidStr;
	OUT INT32 length;
} RT_CMD_AP_IOCTL_SSID;

typedef struct __RT_CMD_IOCTL_RATE {
	IN ULONG priv_flags;
	OUT UINT32 BitRate;
} RT_CMD_IOCTL_RATE;

#define RTMP_CMD_STA_MODE_AUTO			0x00
#define RTMP_CMD_STA_MODE_ADHOC			0x01
#define RTMP_CMD_STA_MODE_INFRA			0x02
#define RTMP_CMD_STA_MODE_MONITOR		0x03

typedef struct __RT_CMD_STA_IOCTL_FREQ {
	IN INT32 m;		/* Mantissa */
	IN INT16 e;		/* Exponent */
} RT_CMD_STA_IOCTL_FREQ;

typedef struct __RT_CMD_STA_IOCTL_BSS {
	OUT UCHAR Bssid[6];
	OUT UCHAR ChannelQuality;
	OUT CHAR Rssi;
	OUT CHAR Noise;
} RT_CMD_STA_IOCTL_BSS;

typedef struct __RT_CMD_STA_IOCTL_BSS_LIST {
	IN UINT32 MaxNum;
	OUT UINT32 BssNum;
	OUT RT_CMD_STA_IOCTL_BSS *pList;
} RT_CMD_STA_IOCTL_BSS_LIST;

typedef struct __RT_CMD_STA_IOCTL_SCAN {
	IN UCHAR FlgScanThisSsid;
	IN UINT32 SsidLen;
	IN CHAR *pSsid;
	OUT INT32 Status;
} RT_CMD_STA_IOCTL_SCAN;

typedef struct __RT_CMD_STA_IOCTL_BSS_TABLE {
	OUT UCHAR Bssid[6];
	OUT UCHAR Channel;
	OUT UCHAR BssType;
	OUT UCHAR HtCapabilityLen;

	OUT UCHAR SupRate[12];
	OUT UCHAR SupRateLen;
	OUT UCHAR ExtRate[12];
	OUT UCHAR ExtRateLen;

	OUT UCHAR SsidLen;
	OUT CHAR Ssid[32];

	OUT USHORT CapabilityInfo;
	OUT UCHAR ChannelWidth, ShortGIfor40, ShortGIfor20, MCSSet;

	OUT USHORT WpaIeLen;
	OUT UCHAR *pWpaIe;

	OUT USHORT RsnIeLen;
	OUT UCHAR *pRsnIe;

	OUT USHORT WpsIeLen;
	OUT UCHAR *pWpsIe;

	OUT UCHAR FlgIsPrivacyOn;

	OUT RT_CMD_STA_IOCTL_BSS Signal;
} RT_CMD_STA_IOCTL_BSS_TABLE;

typedef struct __RT_CMD_STA_IOCTL_SCAN_TABLE {
	IN ULONG priv_flags;
	OUT UINT32 BssNr;
	OUT RT_CMD_STA_IOCTL_BSS_TABLE *pBssTable;	/* must be freed by caller */
	OUT UCHAR MainSharedKey[4][16];
} RT_CMD_STA_IOCTL_SCAN_TABLE;

typedef struct __RT_CMD_STA_IOCTL_SSID {
	IN UCHAR FlgAnySsid;
	INOUT UINT32 SsidLen;
	INOUT CHAR *pSsid;
	OUT INT32 Status;
} RT_CMD_STA_IOCTL_SSID;

typedef struct __RT_CMD_STA_IOCTL_NICK_NAME {
	OUT UINT NameLen;
	OUT CHAR *pName;
} RT_CMD_STA_IOCTL_NICK_NAME;

typedef struct __RT_CMD_STA_IOCTL_SECURITY {
	INOUT CHAR *pData;
	INOUT UINT16 length;
	IN INT32 KeyIdx;
	IN INT32 MaxKeyLen;

#define RT_CMD_STA_IOCTL_SECURITY_ALG_NONE		0x01
#define RT_CMD_STA_IOCTL_SECURITY_ALG_WEP		0x02
#define RT_CMD_STA_IOCTL_SECURITY_ALG_TKIP		0x03
#define RT_CMD_STA_IOCTL_SECURITY_ALG_CCMP		0x04
	IN UINT32 Alg;

#define RT_CMD_STA_IOCTL_SECURTIY_EXT_SET_TX_KEY	0x01
#define RT_CMD_STA_IOCTL_SECURTIY_EXT_GROUP_KEY		0x02
	IN UINT16 ext_flags;

#define RT_CMD_STA_IOCTL_SECURITY_DISABLED		0x01
#define RT_CMD_STA_IOCTL_SECURITY_ENABLED		0x02
#define RT_CMD_STA_IOCTL_SECURITY_RESTRICTED	0x04
#define RT_CMD_STA_IOCTL_SECURITY_OPEN			0x08
#define RT_CMD_STA_IOCTL_SECURITY_NOKEY			0x10
#define RT_CMD_STA_IOCTL_SECURITY_MODE			0x20
	INOUT UINT16 flags;

	OUT INT32 Status;
} RT_CMD_STA_IOCTL_SECURITY;

typedef struct __RT_CMD_STA_IOCTL_WSC_U32_ITEM {
	IN UINT32 *pUWrq;
	OUT INT32 Status;
} RT_CMD_STA_IOCTL_WSC_U32_ITEM;

typedef struct __RT_CMD_STA_IOCTL_WSC_STR_ITEM {
	IN UINT32 Subcmd;
	IN CHAR *pData;
	IN UINT32 length;

	OUT INT32 Status;
} RT_CMD_STA_IOCTL_WSC_STR_ITEM;

typedef struct __RT_CMD_STA_IOCTL_SHOW {
	IN CHAR *pData;
	IN UINT32 MaxSize;
	IN UINT32 InfType;
} RT_CMD_STA_IOCTL_SHOW;

#define RT_CMD_STA_IOCTL_IW_MLME_DEAUTH		0x01
#define RT_CMD_STA_IOCTL_IW_MLME_DISASSOC	0x02

typedef struct __RT_CMD_STA_IOCTL_SECURITY_ADV {

#define RT_CMD_STA_IOCTL_WPA_VERSION					0x10
#define RT_CMD_STA_IOCTL_WPA_VERSION1				0x11
#define RT_CMD_STA_IOCTL_WPA_VERSION2				0x12

#define RT_CMD_STA_IOCTL_WPA_PAIRWISE					0x20
#define RT_CMD_STA_IOCTL_WPA_PAIRWISE_NONE			0x21
#define RT_CMD_STA_IOCTL_WPA_PAIRWISE_WEP40			0x22
#define RT_CMD_STA_IOCTL_WPA_PAIRWISE_WEP104		0x23
#define RT_CMD_STA_IOCTL_WPA_PAIRWISE_TKIP			0x24
#define RT_CMD_STA_IOCTL_WPA_PAIRWISE_CCMP			0x25

#define RT_CMD_STA_IOCTL_WPA_GROUP						0x30
#define RT_CMD_STA_IOCTL_WPA_GROUP_NONE				0x31
#define RT_CMD_STA_IOCTL_WPA_GROUP_WEP40			0x32
#define RT_CMD_STA_IOCTL_WPA_GROUP_WEP104			0x33
#define RT_CMD_STA_IOCTL_WPA_GROUP_TKIP				0x34
#define RT_CMD_STA_IOCTL_WPA_GROUP_CCMP				0x35

#define RT_CMD_STA_IOCTL_WPA_KEY_MGMT					0x40
#define RT_CMD_STA_IOCTL_WPA_KEY_MGMT_1X			0x41
#define RT_CMD_STA_IOCTL_WPA_KEY_MGMT_WPS			0x42

#define RT_CMD_STA_IOCTL_WPA_AUTH_RX_UNENCRYPTED_EAPOL	0x50
#define RT_CMD_STA_IOCTL_WPA_AUTH_PRIVACY_INVOKED		0x60
#define RT_CMD_STA_IOCTL_WPA_AUTH_DROP_UNENCRYPTED		0x70

#define RT_CMD_STA_IOCTL_WPA_AUTH_80211_AUTH_ALG		0x80
#define RT_CMD_STA_IOCTL_WPA_AUTH_80211_AUTH_ALG_SHARED		0x81
#define RT_CMD_STA_IOCTL_WPA_AUTH_80211_AUTH_ALG_OPEN		0x82
#define RT_CMD_STA_IOCTL_WPA_AUTH_80211_AUTH_ALG_LEAP		0x83

#define RT_CMD_STA_IOCTL_WPA_AUTH_WPA_ENABLED			0x90
	IN UINT32 flags;
	IN UINT32 value;
} RT_CMD_STA_IOCTL_SECURITY_ADV;

typedef struct __RT_CMD_STA_IOCTL_RSN_IE {
	INOUT UINT32 length;
	INOUT UCHAR *pRsnIe;
} RT_CMD_STA_IOCTL_RSN_IE;

typedef struct __RT_CMD_STA_IOCTL_PMA_SA {
#define RT_CMD_STA_IOCTL_PMA_SA_FLUSH					0x01
#define RT_CMD_STA_IOCTL_PMA_SA_REMOVE					0x02
#define RT_CMD_STA_IOCTL_PMA_SA_ADD						0x03
	IN UINT32 Cmd;
	IN UCHAR *pBssid;
	IN UCHAR *pPmkid;
} RT_CMD_STA_IOCTL_PMA_SA;

#endif /* __RTMP_CMD_H__ */
