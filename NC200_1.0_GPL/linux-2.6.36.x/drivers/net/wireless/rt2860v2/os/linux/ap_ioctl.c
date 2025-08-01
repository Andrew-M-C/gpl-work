/****************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 * (c) Copyright 2002, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ****************************************************************************

    Module Name:
	ap_ioctl.c

    Abstract:
    IOCTL related subroutines

    Revision History:
    Who          When          What
    ---------    ----------    ----------------------------------------------
*/
#define RTMP_MODULE_OS

/*#include "rt_config.h" */
#include "rtmp_comm.h"
#include "rt_os_util.h"
#include "rt_os_net.h"
#include <linux/wireless.h>

struct iw_priv_args ap_privtab[] = {
{ RTPRIV_IOCTL_SET, 
/* 1024 --> 1024 + 512 */
/* larger size specific to allow 64 ACL MAC addresses to be set up all at once. */
  IW_PRIV_TYPE_CHAR | 1536, 0,
  "set"},  
{ RTPRIV_IOCTL_SHOW,
  IW_PRIV_TYPE_CHAR | 1024, 0,
  "show"},
{ RTPRIV_IOCTL_GSITESURVEY,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024 ,
  "get_site_survey"}, 
#ifdef INF_AR9
  { RTPRIV_IOCTL_GET_AR9_SHOW,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024 ,
  "ar9_show"}, 
#endif
  { RTPRIV_IOCTL_SET_WSCOOB,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024 ,
  "set_wsc_oob"}, 
{ RTPRIV_IOCTL_GET_MAC_TABLE,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024 ,
  "get_mac_table"}, 
{ RTPRIV_IOCTL_E2P,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024,
  "e2p"},
#ifdef DBG
{ RTPRIV_IOCTL_BBP,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024,
  "bbp"},
{ RTPRIV_IOCTL_MAC,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024,
  "mac"},
#ifdef RTMP_RF_RW_SUPPORT
{ RTPRIV_IOCTL_RF,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024,
  "rf"},
#endif /* RTMP_RF_RW_SUPPORT */
#endif /* DBG */

#ifdef WSC_AP_SUPPORT
{ RTPRIV_IOCTL_WSC_PROFILE,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024 ,
  "get_wsc_profile"},
#endif /* WSC_AP_SUPPORT */
{ RTPRIV_IOCTL_QUERY_BATABLE,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024 ,
  "get_ba_table"},
{ RTPRIV_IOCTL_STATISTICS,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024,
  "stat"},
{ RTPRIV_IOCTL_CONN_STATUS,
  IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024,
  "connStatus"}
};


#ifdef CONFIG_APSTA_MIXED_SUPPORT
const struct iw_handler_def rt28xx_ap_iw_handler_def =
{
#define	N(a)	(sizeof (a) / sizeof (a[0]))
	.private_args	= (struct iw_priv_args *) ap_privtab,
	.num_private_args	= N(ap_privtab),
#if IW_HANDLER_VERSION >= 7
	.get_wireless_stats = rt28xx_get_wireless_stats,
#endif 
};
#endif /* CONFIG_APSTA_MIXED_SUPPORT */


INT rt28xx_ap_ioctl(
	IN	struct net_device	*net_dev, 
	IN	OUT	struct ifreq	*rq, 
	IN	INT					cmd)
{
	VOID			*pAd = NULL;
    struct iwreq	*wrqin = (struct iwreq *) rq;
	RTMP_IOCTL_INPUT_STRUCT rt_wrq, *wrq = &rt_wrq;
    INT				Status = NDIS_STATUS_SUCCESS;
    USHORT			subcmd; /*, index; */
/*	POS_COOKIE		pObj; */
	INT			apidx=0;
	UINT32		org_len;
	RT_CMD_AP_IOCTL_CONFIG IoctlConfig, *pIoctlConfig = &IoctlConfig;

	GET_PAD_FROM_NET_DEV(pAd, net_dev);	
/*	pObj = (POS_COOKIE) pAd->OS_Cookie; */

	if (pAd == NULL)
	{
		/* if 1st open fail, pAd will be free;
		   So the net_dev->priv will be NULL in 2rd open */
		return -ENETDOWN;
	}

	wrq->u.data.pointer = wrqin->u.data.pointer;
	wrq->u.data.length = wrqin->u.data.length;
	org_len = wrq->u.data.length;

	pIoctlConfig->Status = 0;
	pIoctlConfig->net_dev = net_dev;
	pIoctlConfig->priv_flags = RT_DEV_PRIV_FLAGS_GET(net_dev);
	pIoctlConfig->pCmdData = wrqin->u.data.pointer;
	pIoctlConfig->CmdId_RTPRIV_IOCTL_SET = RTPRIV_IOCTL_SET;
	pIoctlConfig->name = net_dev->name;
	pIoctlConfig->apidx = 0;

	if ((cmd != SIOCGIWPRIV) &&
		RTMP_AP_IoctlHandle(pAd, NULL, CMD_RTPRIV_IOCTL_PREPARE, 0,
							pIoctlConfig, 0) != NDIS_STATUS_SUCCESS)
	{
		/* prepare error */
		Status = pIoctlConfig->Status;
		goto LabelExit;
	}

	apidx = pIoctlConfig->apidx;
	
    /*+ patch for SnapGear Request even the interface is down */
    if(cmd== SIOCGIWNAME){
	    DBGPRINT(RT_DEBUG_TRACE, ("IOCTL::SIOCGIWNAME\n"));

	RTMP_COM_IoctlHandle(pAd, NULL, CMD_RTPRIV_IOCTL_SIOCGIWNAME, 0, wrqin->u.name, 0);

	    return Status;
    }/*- patch for SnapGear */


	switch(cmd)
	{
		case RTPRIV_IOCTL_ATE:
			{
				RTMP_COM_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_ATE, 0, wrqin->ifr_name, 0);
			}
			break;

		case SIOCGIFHWADDR:
			DBGPRINT(RT_DEBUG_TRACE, ("IOCTLIOCTLIOCTL::SIOCGIFHWADDR\n"));
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_AP_SIOCGIFHWADDR, 0, NULL, 0);
/*            if (pObj->ioctl_if < MAX_MBSSID_NUM(pAd)) */
/*    			strcpy((PSTRING) wrq->u.name, (PSTRING) pAd->ApCfg.MBSSID[pObj->ioctl_if].Bssid); */
			break;
		case SIOCSIWESSID:  /*Set ESSID */
			break;
		case SIOCGIWESSID:  /*Get ESSID */
			{
				RT_CMD_AP_IOCTL_SSID IoctlSSID, *pIoctlSSID = &IoctlSSID;
				struct iw_point *erq = &wrqin->u.essid;
				PCHAR pSsidStr = NULL;

				erq->flags=1;
              /*erq->length = pAd->ApCfg.MBSSID[pObj->ioctl_if].SsidLen; */

				pIoctlSSID->priv_flags = RT_DEV_PRIV_FLAGS_GET(net_dev);
				pIoctlSSID->apidx = apidx;
				RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_AP_SIOCGIWESSID, 0, pIoctlSSID, 0);

				pSsidStr = (PCHAR)pIoctlSSID->pSsidStr;
				erq->length = pIoctlSSID->length;


				if((erq->pointer) && (pSsidStr != NULL))
				{
					/*if(copy_to_user(erq->pointer, pAd->ApCfg.MBSSID[pObj->ioctl_if].Ssid, erq->length)) */
					if(copy_to_user(erq->pointer, pSsidStr, erq->length))
					{
						Status = RTMP_IO_EFAULT;
						break;
					}
				}
				DBGPRINT(RT_DEBUG_TRACE, ("IOCTL::SIOCGIWESSID (Len=%d, ssid=%s...)\n", erq->length, (char *)erq->pointer));
			}
			break;
		case SIOCGIWNWID: /* get network id */
		case SIOCSIWNWID: /* set network id (the cell) */
			Status = RTMP_IO_EOPNOTSUPP;
			break;
		case SIOCGIWFREQ: /* get channel/frequency (Hz) */
		{
			ULONG Channel;
			RTMP_DRIVER_CHANNEL_GET(pAd, &Channel);
			wrqin->u.freq.m = Channel; /*pAd->CommonCfg.Channel; */
			wrqin->u.freq.e = 0;
			wrqin->u.freq.i = 0;
		}
			break; 
		case SIOCSIWFREQ: /*set channel/frequency (Hz) */
			Status = RTMP_IO_EOPNOTSUPP;
			break;
		case SIOCGIWNICKN:
		case SIOCSIWNICKN: /*set node name/nickname */
			Status = RTMP_IO_EOPNOTSUPP;
			break;
		case SIOCGIWRATE:  /*get default bit rate (bps) */
            {
				RT_CMD_IOCTL_RATE IoctlRate, *pIoctlRate = &IoctlRate;

				pIoctlRate->priv_flags = RT_DEV_PRIV_FLAGS_GET(net_dev);
				RTMP_DRIVER_BITRATE_GET(pAd, pIoctlRate);


			wrqin->u.bitrate.value = pIoctlRate->BitRate;
			wrqin->u.bitrate.disabled = 0;
            }
			break;
		case SIOCSIWRATE:  /*set default bit rate (bps) */
		case SIOCGIWRTS:  /* get RTS/CTS threshold (bytes) */
		case SIOCSIWRTS:  /*set RTS/CTS threshold (bytes) */
		case SIOCGIWFRAG:  /*get fragmentation thr (bytes) */
		case SIOCSIWFRAG:  /*set fragmentation thr (bytes) */
		case SIOCGIWENCODE:  /*get encoding token & mode */
		case SIOCSIWENCODE:  /*set encoding token & mode */
			Status = RTMP_IO_EOPNOTSUPP;
			break;
		case SIOCGIWAP:  /*get access point MAC addresses */
			{
/*				PCHAR pBssidStr; */

				wrqin->u.ap_addr.sa_family = ARPHRD_ETHER;
				/*memcpy(wrqin->u.ap_addr.sa_data, &pAd->ApCfg.MBSSID[pObj->ioctl_if].Bssid, ETH_ALEN); */

				RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_AP_SIOCGIWAP, 0,
								wrqin->u.ap_addr.sa_data, RT_DEV_PRIV_FLAGS_GET(net_dev));
			}
			break;
		case SIOCGIWMODE:  /*get operation mode */
			wrqin->u.mode = IW_MODE_INFRA;   /*SoftAP always on INFRA mode. */
			break;
		case SIOCSIWAP:  /*set access point MAC addresses */
		case SIOCSIWMODE:  /*set operation mode */
		case SIOCGIWSENS:   /*get sensitivity (dBm) */
		case SIOCSIWSENS:	/*set sensitivity (dBm) */
		case SIOCGIWPOWER:  /*get Power Management settings */
		case SIOCSIWPOWER:  /*set Power Management settings */
		case SIOCGIWTXPOW:  /*get transmit power (dBm) */
		case SIOCSIWTXPOW:  /*set transmit power (dBm) */
		/*case SIOCGIWRANGE:	//Get range of parameters */
		case SIOCGIWRETRY:	/*get retry limits and lifetime */
		case SIOCSIWRETRY:	/*set retry limits and lifetime */
			Status = RTMP_IO_EOPNOTSUPP;
			break;
		case SIOCGIWRANGE:	/*Get range of parameters */
		    {
/*				struct iw_range range; */
				struct iw_range *prange = NULL;
				UINT32 len;

				/* allocate memory */
				os_alloc_mem(NULL, (UCHAR **)&prange, sizeof(struct iw_range));
				if (prange == NULL)
				{
					DBGPRINT(RT_DEBUG_ERROR, ("%s: Allocate memory fail!!!\n", __FUNCTION__));
					break;
				}

				memset(prange, 0, sizeof(struct iw_range));
				prange->we_version_compiled = WIRELESS_EXT;
				prange->we_version_source = 14;

				/*
					what is correct max? This was not
					documented exactly. At least
					69 has been observed.
				*/
				prange->max_qual.qual = 100;
				prange->max_qual.level = 0; /* dB */
				prange->max_qual.noise = 0; /* dB */
				len = copy_to_user(wrq->u.data.pointer, prange, sizeof(struct iw_range));
				os_free_mem(NULL, prange);
		    }
		    break;
		    
		case RT_PRIV_IOCTL:
		case RT_PRIV_IOCTL_EXT:
		{
			subcmd = wrqin->u.data.flags;

			Status = RTMP_AP_IoctlHandle(pAd, wrq, CMD_RT_PRIV_IOCTL, subcmd, wrqin->u.data.pointer, 0);
		}
			break;
		
#ifdef HOSTAPD_SUPPORT
		case SIOCSIWGENIE:
			DBGPRINT(RT_DEBUG_TRACE,("ioctl SIOCSIWGENIE apidx=%d\n",apidx));
			DBGPRINT(RT_DEBUG_TRACE,("ioctl SIOCSIWGENIE length=%d, pointer=%x\n", wrqin->u.data.length, wrqin->u.data.pointer));


			RTMP_AP_IoctlHandle(pAd, wrqin, CMD_RTPRIV_IOCTL_AP_SIOCSIWGENIE, 0, NULL, 0);
			break;
#endif /* HOSTAPD_SUPPORT */

		case SIOCGIWPRIV:
			if (wrqin->u.data.pointer) 
			{
				if ( access_ok(VERIFY_WRITE, wrqin->u.data.pointer, sizeof(ap_privtab)) != TRUE)
					break;
				if ((sizeof(ap_privtab) / sizeof(ap_privtab[0])) <= wrq->u.data.length)
				{
					wrqin->u.data.length = sizeof(ap_privtab) / sizeof(ap_privtab[0]);
					if (copy_to_user(wrqin->u.data.pointer, ap_privtab, sizeof(ap_privtab)))
						Status = RTMP_IO_EFAULT;
				}
				else
					Status = RTMP_IO_E2BIG;
			}
			break;
		case RTPRIV_IOCTL_SET:
			{
				if( access_ok(VERIFY_READ, wrqin->u.data.pointer, wrqin->u.data.length) == TRUE)
					Status = RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_SET, 0, NULL, 0);
			}
			break;
		    
		case RTPRIV_IOCTL_SHOW:
			{
				if( access_ok(VERIFY_READ, wrqin->u.data.pointer, wrqin->u.data.length) == TRUE)
					Status = RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_SHOW, 0, NULL, 0);
			}
			break;	
			
#ifdef INF_AR9
#ifdef AR9_MAPI_SUPPORT
		case RTPRIV_IOCTL_GET_AR9_SHOW:
			{
				if( access_ok(VERIFY_READ, wrqin->u.data.pointer, wrqin->u.data.length) == TRUE)
					Status = RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_GET_AR9_SHOW, 0, NULL, 0);
			}	
		    break;
#endif /*AR9_MAPI_SUPPORT*/
#endif /* INF_AR9 */

#ifdef WSC_AP_SUPPORT
		case RTPRIV_IOCTL_SET_WSCOOB:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_SET_WSCOOB, 0, NULL, 0);
		    break;
#endif/*WSC_AP_SUPPORT*/

/* modified by Red@Ralink, 2009/09/30 */
		case RTPRIV_IOCTL_GET_MAC_TABLE:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_GET_MAC_TABLE, 0, NULL, 0);
		    break;

		case RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT, 0, NULL, 0);
			break;
/* end of modification */

#ifdef AP_SCAN_SUPPORT
		case RTPRIV_IOCTL_GSITESURVEY:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_GSITESURVEY, 0, NULL, 0);
			break;
#endif /* AP_SCAN_SUPPORT */

		case RTPRIV_IOCTL_STATISTICS:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_STATISTICS, 0, NULL, 0);
			break;
		case RTPRIV_IOCTL_CONN_STATUS:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_CONN_STATUS, 0, NULL, 0);
			break;
#ifdef WSC_AP_SUPPORT
		case RTPRIV_IOCTL_WSC_PROFILE:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_WSC_PROFILE, 0, NULL, 0);
		    break;
#endif /* WSC_AP_SUPPORT */
#ifdef DOT11_N_SUPPORT
		case RTPRIV_IOCTL_QUERY_BATABLE:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_QUERY_BATABLE, 0, NULL, 0);
		    break;
#endif /* DOT11_N_SUPPORT */
		case RTPRIV_IOCTL_E2P:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_E2P, 0, NULL, 0);
			break;

#ifdef DBG
		case RTPRIV_IOCTL_BBP:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_BBP, 0, NULL, 0);
			break;
			
		case RTPRIV_IOCTL_MAC:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_MAC, 0, NULL, 0);
			break;
            
#ifdef RTMP_RF_RW_SUPPORT
		case RTPRIV_IOCTL_RF:
			RTMP_AP_IoctlHandle(pAd, wrq, CMD_RTPRIV_IOCTL_RF, 0, NULL, 0);
			break;
#endif /* RTMP_RF_RW_SUPPORT */
#endif /* DBG */

		default:
/*			DBGPRINT(RT_DEBUG_ERROR, ("IOCTL::unknown IOCTL's cmd = 0x%08x\n", cmd)); */
			Status = RTMP_IO_EOPNOTSUPP;
			break;
	}

LabelExit:
	if (Status != 0)
	{
		RT_CMD_STATUS_TRANSLATE(Status);
	}
	else
	{
		/*
			If wrq length is modified, we reset the lenght of origin wrq;

			Or we can not modify it because the address of wrq->u.data.length
			maybe same as other union field, ex: iw_range, etc.

			if the length is not changed but we change it, the value for other
			union will also be changed, this is not correct.
		*/
		if (wrq->u.data.length != org_len)
			wrqin->u.data.length = wrq->u.data.length;
	}

	return Status;
}
