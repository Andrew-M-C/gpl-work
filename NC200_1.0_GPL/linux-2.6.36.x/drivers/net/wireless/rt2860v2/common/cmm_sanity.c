/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2004, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

	Module Name:
	sanity.c

	Abstract:

	Revision History:
	Who			When			What
	--------	----------		----------------------------------------------
	John Chang  2004-09-01      add WMM support
*/
#include "rt_config.h"

extern UCHAR	CISCO_OUI[];

extern UCHAR	WPA_OUI[];
extern UCHAR	RSN_OUI[];
extern UCHAR	WME_INFO_ELEM[];
extern UCHAR	WME_PARM_ELEM[];
extern UCHAR	RALINK_OUI[];
extern UCHAR	BROADCOM_OUI[];
extern UCHAR    WPS_OUI[];


#ifdef IWSC_SUPPORT
extern UCHAR    IWSC_OUI[];
#endif // IWSC_SUPPORT //

typedef struct wsc_ie_probreq_data
{
	UCHAR	ssid[32];
	UCHAR	macAddr[6];
	UCHAR	data[2];
} WSC_IE_PROBREQ_DATA;

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
        
	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
BOOLEAN MlmeAddBAReqSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen, 
    OUT PUCHAR pAddr2) 
{
    PMLME_ADDBA_REQ_STRUCT   pInfo;
	UINT32 MaxWcidNum = MAX_LEN_OF_MAC_TABLE;
	
#ifdef MAC_REPEATER_SUPPORT
	if (pAd->ApCfg.bMACRepeaterEn)
	MaxWcidNum = MAX_MAC_TABLE_SIZE_WITH_REPEATER;
#endif /* MAC_REPEATER_SUPPORT */


    pInfo = (MLME_ADDBA_REQ_STRUCT *)Msg;

    if ((MsgLen != sizeof(MLME_ADDBA_REQ_STRUCT)))
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAddBAReqSanity fail - message lenght not correct.\n"));
        return FALSE;
    }	
	
    if ((pInfo->Wcid >= MaxWcidNum))
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAddBAReqSanity fail - The peer Mac is not associated yet.\n"));
        return FALSE;
    }	

	/*
    if ((pInfo->BaBufSize > MAX_RX_REORDERBUF) || (pInfo->BaBufSize < 2))
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAddBAReqSanity fail - Rx Reordering buffer too big or too small\n"));
        return FALSE;
    } 
	*/  

    if ((pInfo->pAddr[0]&0x01) == 0x01)
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAddBAReqSanity fail - broadcast address not support BA\n"));
        return FALSE;
    }	
    
    return TRUE;
}

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
        
	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
BOOLEAN MlmeDelBAReqSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen) 
{
	MLME_DELBA_REQ_STRUCT *pInfo;
	UINT32 MaxWcidNum = MAX_LEN_OF_MAC_TABLE;
	pInfo = (MLME_DELBA_REQ_STRUCT *)Msg;

#ifdef MAC_REPEATER_SUPPORT
	if (pAd->ApCfg.bMACRepeaterEn)
	MaxWcidNum = MAX_MAC_TABLE_SIZE_WITH_REPEATER;
#endif /* MAC_REPEATER_SUPPORT */

    if ((MsgLen != sizeof(MLME_DELBA_REQ_STRUCT)))
    {
        DBGPRINT(RT_DEBUG_ERROR, ("MlmeDelBAReqSanity fail - message lenght not correct.\n"));
        return FALSE;
    }	
	
    if ((pInfo->Wcid >= MaxWcidNum))
    {
        DBGPRINT(RT_DEBUG_ERROR, ("MlmeDelBAReqSanity fail - The peer Mac is not associated yet.\n"));
        return FALSE;
    }	

    if ((pInfo->TID & 0xf0))
    {
        DBGPRINT(RT_DEBUG_ERROR, ("MlmeDelBAReqSanity fail - The peer TID is incorrect.\n"));
        return FALSE;
    }	

	if (NdisEqualMemory(pAd->MacTab.Content[pInfo->Wcid].Addr, pInfo->Addr, MAC_ADDR_LEN) == 0)
    {    	
        DBGPRINT(RT_DEBUG_ERROR, ("MlmeDelBAReqSanity fail - the peer addr dosen't exist.\n"));		
        return FALSE;
    }	
    
    return TRUE;
}

BOOLEAN PeerAddBAReqActionSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *pMsg, 
    IN ULONG MsgLen,
	OUT PUCHAR pAddr2)
{
	PFRAME_802_11 pFrame = (PFRAME_802_11)pMsg;
	PFRAME_ADDBA_REQ pAddFrame;
	pAddFrame = (PFRAME_ADDBA_REQ)(pMsg);
	if (MsgLen < (sizeof(FRAME_ADDBA_REQ)))
	{
		DBGPRINT(RT_DEBUG_ERROR,("PeerAddBAReqActionSanity: ADDBA Request frame length size = %ld incorrect\n", MsgLen));
		return FALSE;
	}
	/* we support immediate BA.*/
#ifdef UNALIGNMENT_SUPPORT
	{
		BA_PARM		tmpBaParm;

		NdisMoveMemory((PUCHAR)(&tmpBaParm), (PUCHAR)(&pAddFrame->BaParm), sizeof(BA_PARM));
		*(USHORT *)(&tmpBaParm) = cpu2le16(*(USHORT *)(&tmpBaParm));
		NdisMoveMemory((PUCHAR)(&pAddFrame->BaParm), (PUCHAR)(&tmpBaParm), sizeof(BA_PARM));
	}
#else
	*(USHORT *)(&pAddFrame->BaParm) = cpu2le16(*(USHORT *)(&pAddFrame->BaParm));
#endif
	pAddFrame->TimeOutValue = cpu2le16(pAddFrame->TimeOutValue);
	pAddFrame->BaStartSeq.word = cpu2le16(pAddFrame->BaStartSeq.word); 

	COPY_MAC_ADDR(pAddr2, pFrame->Hdr.Addr2);

	if (pAddFrame->BaParm.BAPolicy != IMMED_BA)
	{
		DBGPRINT(RT_DEBUG_ERROR,("PeerAddBAReqActionSanity: ADDBA Request Ba Policy[%d] not support\n", pAddFrame->BaParm.BAPolicy));
		DBGPRINT(RT_DEBUG_ERROR,("ADDBA Request. tid=%x, Bufsize=%x, AMSDUSupported=%x \n", pAddFrame->BaParm.TID, pAddFrame->BaParm.BufSize, pAddFrame->BaParm.AMSDUSupported));
		return FALSE;
	}

	return TRUE;
}

BOOLEAN PeerAddBARspActionSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *pMsg, 
    IN ULONG MsgLen)
{
	/*PFRAME_802_11 pFrame = (PFRAME_802_11)pMsg;*/
	PFRAME_ADDBA_RSP pAddFrame;
	
	pAddFrame = (PFRAME_ADDBA_RSP)(pMsg);
	if (MsgLen < (sizeof(FRAME_ADDBA_RSP)))
	{
		DBGPRINT(RT_DEBUG_ERROR,("PeerAddBARspActionSanity: ADDBA Response frame length size = %ld incorrect\n", MsgLen));
		return FALSE;
	}
	/* we support immediate BA.*/
#ifdef UNALIGNMENT_SUPPORT
	{
		BA_PARM		tmpBaParm;

		NdisMoveMemory((PUCHAR)(&tmpBaParm), (PUCHAR)(&pAddFrame->BaParm), sizeof(BA_PARM));
		*(USHORT *)(&tmpBaParm) = cpu2le16(*(USHORT *)(&tmpBaParm));
		NdisMoveMemory((PUCHAR)(&pAddFrame->BaParm), (PUCHAR)(&tmpBaParm), sizeof(BA_PARM));
	}
#else
	*(USHORT *)(&pAddFrame->BaParm) = cpu2le16(*(USHORT *)(&pAddFrame->BaParm));
#endif
	pAddFrame->StatusCode = cpu2le16(pAddFrame->StatusCode);
	pAddFrame->TimeOutValue = cpu2le16(pAddFrame->TimeOutValue);

	if (pAddFrame->BaParm.BAPolicy != IMMED_BA)
	{
		DBGPRINT(RT_DEBUG_ERROR,("PeerAddBAReqActionSanity: ADDBA Response Ba Policy[%d] not support\n", pAddFrame->BaParm.BAPolicy));
		return FALSE;
	}

	return TRUE;

}

BOOLEAN PeerDelBAActionSanity(
    IN PRTMP_ADAPTER pAd, 
    IN UCHAR Wcid, 
    IN VOID *pMsg, 
    IN ULONG MsgLen )
{
	/*PFRAME_802_11 pFrame = (PFRAME_802_11)pMsg;*/
	PFRAME_DELBA_REQ  pDelFrame;
	UINT32 MaxWcidNum = MAX_LEN_OF_MAC_TABLE;

	if (MsgLen != (sizeof(FRAME_DELBA_REQ)))
		return FALSE;
	
#ifdef MAC_REPEATER_SUPPORT
	if (pAd->ApCfg.bMACRepeaterEn)
	MaxWcidNum = MAX_MAC_TABLE_SIZE_WITH_REPEATER;
#endif /* MAC_REPEATER_SUPPORT */
	
	if (Wcid >= MaxWcidNum)
		return FALSE;
	
	pDelFrame = (PFRAME_DELBA_REQ)(pMsg);

	*(USHORT *)(&pDelFrame->DelbaParm) = cpu2le16(*(USHORT *)(&pDelFrame->DelbaParm));
	pDelFrame->ReasonCode = cpu2le16(pDelFrame->ReasonCode);

	return TRUE;
}

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
        
	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
BOOLEAN PeerBeaconAndProbeRspSanity(
    IN PRTMP_ADAPTER pAd,
    IN VOID *Msg, 
    IN ULONG MsgLen, 
    IN UCHAR  MsgChannel,
    OUT PUCHAR pAddr2, 
    OUT PUCHAR pBssid, 
    OUT CHAR Ssid[], 
    OUT UCHAR *pSsidLen, 
    OUT UCHAR *pBssType, 
    OUT USHORT *pBeaconPeriod, 
    OUT UCHAR *pChannel, 
    OUT UCHAR *pNewChannel, 
    OUT LARGE_INTEGER *pTimestamp, 
    OUT CF_PARM *pCfParm, 
    OUT USHORT *pAtimWin, 
    OUT USHORT *pCapabilityInfo, 
    OUT UCHAR *pErp,
    OUT UCHAR *pDtimCount, 
    OUT UCHAR *pDtimPeriod, 
    OUT UCHAR *pBcastFlag, 
    OUT UCHAR *pMessageToMe, 
    OUT UCHAR SupRate[],
    OUT UCHAR *pSupRateLen,
    OUT UCHAR ExtRate[],
    OUT UCHAR *pExtRateLen,
    OUT	UCHAR *pCkipFlag,
    OUT	UCHAR *pAironetCellPowerLimit,
    OUT PEDCA_PARM       pEdcaParm,
    OUT PQBSS_LOAD_PARM  pQbssLoad,
    OUT PQOS_CAPABILITY_PARM pQosCapability,
    OUT ULONG *pRalinkIe,
    OUT UCHAR		 *pHtCapabilityLen,
#ifdef CONFIG_STA_SUPPORT
    OUT UCHAR		 *pPreNHtCapabilityLen,
#endif /* CONFIG_STA_SUPPORT */
    OUT HT_CAPABILITY_IE *pHtCapability,
    OUT EXT_CAP_INFO_ELEMENT	*pExtCapInfo,
	OUT UCHAR		 *AddHtInfoLen,
	OUT ADD_HT_INFO_IE *AddHtInfo,
	OUT UCHAR *NewExtChannelOffset,		/* Ht extension channel offset(above or below)*/
    OUT USHORT *LengthVIE,	
    OUT	PNDIS_802_11_VARIABLE_IEs pVIE) 
{
    UCHAR				*Ptr;
#ifdef CONFIG_STA_SUPPORT
	UCHAR 				TimLen;
#ifdef IWSC_SUPPORT
	BOOLEAN				bFoundIWscIe = FALSE;
	USHORT 				PeerConfigMethod = 0;
#endif /* IWSC_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */
    PFRAME_802_11		pFrame;
    PEID_STRUCT         pEid;
    UCHAR				SubType;
    UCHAR				Sanity;
    /*UCHAR				ECWMin, ECWMax;*/
    /*MAC_CSR9_STRUC		Csr9;*/
    ULONG				Length = 0;
	UCHAR				*pPeerWscIe = NULL;
	INT					PeerWscIeLen = 0;
    UCHAR				LatchRfChannel = 0;
	BOOLEAN bWscCheck = TRUE;


	/*
		For some 11a AP which didn't have DS_IE, we use two conditions to decide the channel
		1. If the AP is 11n enabled, then check the control channel.
		2. If the AP didn't have any info about channel, use the channel we received this 
			frame as the channel. (May inaccuracy!!)
	*/
	UCHAR			CtrlChannel = 0;
	
	
	os_alloc_mem(NULL, &pPeerWscIe, 512);
    /* Add for 3 necessary EID field check*/
    Sanity = 0;

    *pAtimWin = 0;
    *pErp = 0;	
    *pDtimCount = 0;
    *pDtimPeriod = 0;
    *pBcastFlag = 0;
    *pMessageToMe = 0;
    *pExtRateLen = 0;
    *pCkipFlag = 0;			        /* Default of CkipFlag is 0*/
    *pAironetCellPowerLimit = 0xFF;  /* Default of AironetCellPowerLimit is 0xFF*/
    *LengthVIE = 0;					/* Set the length of VIE to init value 0*/
    *pHtCapabilityLen = 0;					/* Set the length of VIE to init value 0*/
#ifdef CONFIG_STA_SUPPORT
	if (pAd->OpMode == OPMODE_STA)
		*pPreNHtCapabilityLen = 0;					/* Set the length of VIE to init value 0*/
#endif /* CONFIG_STA_SUPPORT */
    *AddHtInfoLen = 0;					/* Set the length of VIE to init value 0*/
    NdisZeroMemory(pExtCapInfo, sizeof(EXT_CAP_INFO_ELEMENT));
    *pRalinkIe = 0;
    *pNewChannel = 0;
    *NewExtChannelOffset = 0xff;	/*Default 0xff means no such IE*/
    pCfParm->bValid = FALSE;        /* default: no IE_CF found*/
    pQbssLoad->bValid = FALSE;      /* default: no IE_QBSS_LOAD found*/
    pEdcaParm->bValid = FALSE;      /* default: no IE_EDCA_PARAMETER found*/
    pQosCapability->bValid = FALSE; /* default: no IE_QOS_CAPABILITY found*/
    
    pFrame = (PFRAME_802_11)Msg;
    
    /* get subtype from header*/
    SubType = (UCHAR)pFrame->Hdr.FC.SubType;

    /* get Addr2 and BSSID from header*/
    COPY_MAC_ADDR(pAddr2, pFrame->Hdr.Addr2);
    COPY_MAC_ADDR(pBssid, pFrame->Hdr.Addr3);
    
/*	hex_dump("Beacon", Msg, MsgLen);*/

    Ptr = pFrame->Octet;
    Length += LENGTH_802_11;
    
    /* get timestamp from payload and advance the pointer*/
    NdisMoveMemory(pTimestamp, Ptr, TIMESTAMP_LEN);

	pTimestamp->u.LowPart = cpu2le32(pTimestamp->u.LowPart);
	pTimestamp->u.HighPart = cpu2le32(pTimestamp->u.HighPart);

    Ptr += TIMESTAMP_LEN;
    Length += TIMESTAMP_LEN;

    /* get beacon interval from payload and advance the pointer*/
    NdisMoveMemory(pBeaconPeriod, Ptr, 2);
    Ptr += 2;
    Length += 2;

    /* get capability info from payload and advance the pointer*/
    NdisMoveMemory(pCapabilityInfo, Ptr, 2);
    Ptr += 2;
    Length += 2;

    if (CAP_IS_ESS_ON(*pCapabilityInfo)) 
        *pBssType = BSS_INFRA;
    else 
        *pBssType = BSS_ADHOC;

    pEid = (PEID_STRUCT) Ptr;

    /* get variable fields from payload and advance the pointer*/
    while ((Length + 2 + pEid->Len) <= MsgLen)    
    {
        
        /* Secure copy VIE to VarIE[MAX_VIE_LEN] didn't overflow.*/
        if ((*LengthVIE + pEid->Len + 2) >= MAX_VIE_LEN)
        {
            DBGPRINT(RT_DEBUG_WARN, ("PeerBeaconAndProbeRspSanity - Variable IEs out of resource [len(=%d) > MAX_VIE_LEN(=%d)]\n",
                    (*LengthVIE + pEid->Len + 2), MAX_VIE_LEN));
            break;
        }

        switch(pEid->Eid)
        {
            case IE_SSID:
                /* Already has one SSID EID in this beacon, ignore the second one*/
                if (Sanity & 0x1)
                    break;
                if(pEid->Len <= MAX_LEN_OF_SSID)
                {
                    NdisMoveMemory(Ssid, pEid->Octet, pEid->Len);
                    *pSsidLen = pEid->Len;
                    Sanity |= 0x1;
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_SSID (len=%d)\n",pEid->Len));
                    goto SanityCheck;
                }
                break;

            case IE_SUPP_RATES:
                if(pEid->Len <= MAX_LEN_OF_SUPPORTED_RATES)
                {
                    Sanity |= 0x2;
                    NdisMoveMemory(SupRate, pEid->Octet, pEid->Len);
                    *pSupRateLen = pEid->Len;

                    /*
						TODO: 2004-09-14 not a good design here, cause it exclude extra 
							rates from ScanTab. We should report as is. And filter out 
							unsupported rates in MlmeAux
					*/
                    /* Check against the supported rates*/
                    /* RTMPCheckRates(pAd, SupRate, pSupRateLen);*/
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_SUPP_RATES (len=%d)\n",pEid->Len));
                    goto SanityCheck;
                }
                break;

            case IE_HT_CAP:
			if (pEid->Len >= SIZE_HT_CAP_IE)  /*Note: allow extension.!!*/
			{
				NdisMoveMemory(pHtCapability, pEid->Octet, sizeof(HT_CAPABILITY_IE));
				*pHtCapabilityLen = SIZE_HT_CAP_IE;	/* Nnow we only support 26 bytes.*/

				*(USHORT *)(&pHtCapability->HtCapInfo) = cpu2le16(*(USHORT *)(&pHtCapability->HtCapInfo));
#ifdef UNALIGNMENT_SUPPORT
				{
					EXT_HT_CAP_INFO extHtCapInfo;
					NdisMoveMemory((PUCHAR)(&extHtCapInfo), (PUCHAR)(&pHtCapability->ExtHtCapInfo), sizeof(EXT_HT_CAP_INFO));
					*(USHORT *)(&extHtCapInfo) = cpu2le16(*(USHORT *)(&extHtCapInfo));
					NdisMoveMemory((PUCHAR)(&pHtCapability->ExtHtCapInfo), (PUCHAR)(&extHtCapInfo), sizeof(EXT_HT_CAP_INFO));
				}
#else
				*(USHORT *)(&pHtCapability->ExtHtCapInfo) = cpu2le16(*(USHORT *)(&pHtCapability->ExtHtCapInfo));
#endif /* UNALIGNMENT_SUPPORT */

#ifdef CONFIG_STA_SUPPORT
				IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
				{
					*pPreNHtCapabilityLen = 0;	/* Now we only support 26 bytes.*/

					Ptr = (PUCHAR) pVIE;
					NdisMoveMemory(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
					*LengthVIE += (pEid->Len + 2);
				}
#endif /* CONFIG_STA_SUPPORT */
			}
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("PeerBeaconAndProbeRspSanity - wrong IE_HT_CAP. pEid->Len = %d\n", pEid->Len));
			}
			
		break;
            case IE_ADD_HT:
			if (pEid->Len >= sizeof(ADD_HT_INFO_IE))				
			{
				/* 
					This IE allows extension, but we can ignore extra bytes beyond our 
					knowledge , so only copy first sizeof(ADD_HT_INFO_IE)
				*/
				NdisMoveMemory(AddHtInfo, pEid->Octet, sizeof(ADD_HT_INFO_IE));
				*AddHtInfoLen = SIZE_ADD_HT_INFO_IE;

				CtrlChannel = AddHtInfo->ControlChan;
				
				*(USHORT *)(&AddHtInfo->AddHtInfo2) = cpu2le16(*(USHORT *)(&AddHtInfo->AddHtInfo2));
				*(USHORT *)(&AddHtInfo->AddHtInfo3) = cpu2le16(*(USHORT *)(&AddHtInfo->AddHtInfo3));
           
#ifdef CONFIG_STA_SUPPORT
				IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
				{
			                Ptr = (PUCHAR) pVIE;
			                NdisMoveMemory(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
			                *LengthVIE += (pEid->Len + 2);
				}
#endif /* CONFIG_STA_SUPPORT */
			}
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("PeerBeaconAndProbeRspSanity - wrong IE_ADD_HT. \n"));
			}
				
		break;
            case IE_SECONDARY_CH_OFFSET:
			if (pEid->Len == 1)
			{
				*NewExtChannelOffset = pEid->Octet[0];
			}
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("PeerBeaconAndProbeRspSanity - wrong IE_SECONDARY_CH_OFFSET. \n"));
			}
				
		break;
            case IE_FH_PARM:
                DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity(IE_FH_PARM) \n"));
                break;

            case IE_DS_PARM:
                if(pEid->Len == 1)
                {
                    *pChannel = *pEid->Octet;
#ifdef CONFIG_STA_SUPPORT
					IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
					{
						if (ChannelSanity(pAd, *pChannel) == 0)
						{
							
							goto SanityCheck;
						}
					}
#endif /* CONFIG_STA_SUPPORT */
                    Sanity |= 0x4;
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_DS_PARM (len=%d)\n",pEid->Len));
                    goto SanityCheck;
                }
                break;

            case IE_CF_PARM:
                if(pEid->Len == 6)
                {
                    pCfParm->bValid = TRUE;
                    pCfParm->CfpCount = pEid->Octet[0];
                    pCfParm->CfpPeriod = pEid->Octet[1];
                    pCfParm->CfpMaxDuration = pEid->Octet[2] + 256 * pEid->Octet[3];
                    pCfParm->CfpDurRemaining = pEid->Octet[4] + 256 * pEid->Octet[5];
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_CF_PARM\n"));
					if (pPeerWscIe)
						os_free_mem(NULL, pPeerWscIe);
                    return FALSE;
                }
                break;

            case IE_IBSS_PARM:
                if(pEid->Len == 2)
                {
                    NdisMoveMemory(pAtimWin, pEid->Octet, pEid->Len);
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_IBSS_PARM\n"));
					if (pPeerWscIe)
						os_free_mem(NULL, pPeerWscIe);
                    return FALSE;
                }
                break;

#ifdef CONFIG_STA_SUPPORT
            case IE_TIM:
                if(SubType == SUBTYPE_BEACON)
                {
#ifdef P2P_SUPPORT
                    if (P2P_CLI_ON(pAd) && NdisEqualMemory(pBssid, pAd->ApCfg.ApCliTab[BSS0].ApCliMlmeAux.Bssid, MAC_ADDR_LEN))
                    {
                        GetTimBit((PCHAR)pEid, pAd->ApCfg.ApCliTab[BSS0].ApCliMlmeAux.Aid, &TimLen, pBcastFlag, pDtimCount, pDtimPeriod, pMessageToMe);
                    }
#endif /* P2P_SUPPORT */
					if (INFRA_ON(pAd) && NdisEqualMemory(pBssid, pAd->CommonCfg.Bssid, MAC_ADDR_LEN))
                    {
                        GetTimBit((PCHAR)pEid, pAd->StaActive.Aid, &TimLen, pBcastFlag, pDtimCount, pDtimPeriod, pMessageToMe);
                    }
                }
                break;
#endif /* CONFIG_STA_SUPPORT */
            case IE_CHANNEL_SWITCH_ANNOUNCEMENT:
                if(pEid->Len == 3)
                {
                	*pNewChannel = pEid->Octet[1];	/*extract new channel number*/
                }
                break;

            /* 
				New for WPA
				CCX v2 has the same IE, we need to parse that too
				Wifi WMM use the same IE vale, need to parse that too
			*/
            /* case IE_WPA:*/
            case IE_VENDOR_SPECIFIC:
                /* Check the OUI version, filter out non-standard usage*/
                if (NdisEqualMemory(pEid->Octet, RALINK_OUI, 3) && (pEid->Len == 7))
                {
                    /**pRalinkIe = pEid->Octet[3];*/
                    if (pEid->Octet[3] != 0)
        				*pRalinkIe = pEid->Octet[3];
        			else
        				*pRalinkIe = 0xf0000000; /* Set to non-zero value (can't set bit0-2) to represent this is Ralink Chip. So at linkup, we will set ralinkchip flag.*/
                }
#ifdef CONFIG_STA_SUPPORT
#ifdef DOT11_N_SUPPORT
		/* This HT IE is before IEEE draft set HT IE value.2006-09-28 by Jan.*/
                
                /* Other vendors had production before IE_HT_CAP value is assigned. To backward support those old-firmware AP,*/
                /* Check broadcom-defiend pre-802.11nD1.0 OUI for HT related IE, including HT Capatilities IE and HT Information IE*/
                else if ((*pHtCapabilityLen == 0) && NdisEqualMemory(pEid->Octet, PRE_N_HT_OUI, 3) && (pEid->Len >= 4) && (pAd->OpMode == OPMODE_STA))
                {
                    if ((pEid->Octet[3] == OUI_PREN_HT_CAP) && (pEid->Len >= 30) && (*pHtCapabilityLen == 0))
                    {
                        NdisMoveMemory(pHtCapability, &pEid->Octet[4], sizeof(HT_CAPABILITY_IE));
                        *pPreNHtCapabilityLen = SIZE_HT_CAP_IE;
                    }

                    if ((pEid->Octet[3] == OUI_PREN_ADD_HT) && (pEid->Len >= 26))
                    {
                        NdisMoveMemory(AddHtInfo, &pEid->Octet[4], sizeof(ADD_HT_INFO_IE));
                        *AddHtInfoLen = SIZE_ADD_HT_INFO_IE;
                    }
                }
#endif /* DOT11_N_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */
                else if (NdisEqualMemory(pEid->Octet, WPA_OUI, 4))
                {
                    /* Copy to pVIE which will report to bssid list.*/
                    Ptr = (PUCHAR) pVIE;
                    NdisMoveMemory(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                    *LengthVIE += (pEid->Len + 2);
                }
                else if (NdisEqualMemory(pEid->Octet, WME_PARM_ELEM, 6) && (pEid->Len == 24))
                {
                    PUCHAR ptr;
                    int i;

                    /* parsing EDCA parameters*/
                    pEdcaParm->bValid          = TRUE;
                    pEdcaParm->bQAck           = FALSE; /* pEid->Octet[0] & 0x10;*/
                    pEdcaParm->bQueueRequest   = FALSE; /* pEid->Octet[0] & 0x20;*/
                    pEdcaParm->bTxopRequest    = FALSE; /* pEid->Octet[0] & 0x40;*/
                    pEdcaParm->EdcaUpdateCount = pEid->Octet[6] & 0x0f;
                    pEdcaParm->bAPSDCapable    = (pEid->Octet[6] & 0x80) ? 1 : 0;
                    ptr = &pEid->Octet[8];
                    for (i=0; i<4; i++)
                    {
                        UCHAR aci = (*ptr & 0x60) >> 5; /* b5~6 is AC INDEX*/
                        pEdcaParm->bACM[aci]  = (((*ptr) & 0x10) == 0x10);   /* b5 is ACM*/
                        pEdcaParm->Aifsn[aci] = (*ptr) & 0x0f;               /* b0~3 is AIFSN*/
                        pEdcaParm->Cwmin[aci] = *(ptr+1) & 0x0f;             /* b0~4 is Cwmin*/
                        pEdcaParm->Cwmax[aci] = *(ptr+1) >> 4;               /* b5~8 is Cwmax*/
                        pEdcaParm->Txop[aci]  = *(ptr+2) + 256 * (*(ptr+3)); /* in unit of 32-us*/
                        ptr += 4; /* point to next AC*/
                    }
                }
                else if (NdisEqualMemory(pEid->Octet, WME_INFO_ELEM, 6) && (pEid->Len == 7))
                {
                    /* parsing EDCA parameters*/
                    pEdcaParm->bValid          = TRUE;
                    pEdcaParm->bQAck           = FALSE; /* pEid->Octet[0] & 0x10;*/
                    pEdcaParm->bQueueRequest   = FALSE; /* pEid->Octet[0] & 0x20;*/
                    pEdcaParm->bTxopRequest    = FALSE; /* pEid->Octet[0] & 0x40;*/
                    pEdcaParm->EdcaUpdateCount = pEid->Octet[6] & 0x0f;
                    pEdcaParm->bAPSDCapable    = (pEid->Octet[6] & 0x80) ? 1 : 0;

                    /* use default EDCA parameter*/
                    pEdcaParm->bACM[QID_AC_BE]  = 0;
                    pEdcaParm->Aifsn[QID_AC_BE] = 3;
                    pEdcaParm->Cwmin[QID_AC_BE] = CW_MIN_IN_BITS;
                    pEdcaParm->Cwmax[QID_AC_BE] = CW_MAX_IN_BITS;
                    pEdcaParm->Txop[QID_AC_BE]  = 0;

                    pEdcaParm->bACM[QID_AC_BK]  = 0;
                    pEdcaParm->Aifsn[QID_AC_BK] = 7;
                    pEdcaParm->Cwmin[QID_AC_BK] = CW_MIN_IN_BITS;
                    pEdcaParm->Cwmax[QID_AC_BK] = CW_MAX_IN_BITS;
                    pEdcaParm->Txop[QID_AC_BK]  = 0;

                    pEdcaParm->bACM[QID_AC_VI]  = 0;
                    pEdcaParm->Aifsn[QID_AC_VI] = 2;
                    pEdcaParm->Cwmin[QID_AC_VI] = CW_MIN_IN_BITS-1;
                    pEdcaParm->Cwmax[QID_AC_VI] = CW_MAX_IN_BITS;
                    pEdcaParm->Txop[QID_AC_VI]  = 96;   /* AC_VI: 96*32us ~= 3ms*/

                    pEdcaParm->bACM[QID_AC_VO]  = 0;
                    pEdcaParm->Aifsn[QID_AC_VO] = 2;
                    pEdcaParm->Cwmin[QID_AC_VO] = CW_MIN_IN_BITS-2;
                    pEdcaParm->Cwmax[QID_AC_VO] = CW_MAX_IN_BITS-1;
                    pEdcaParm->Txop[QID_AC_VO]  = 48;   /* AC_VO: 48*32us ~= 1.5ms*/
                }
				else if ((4 <= pEid->Len) && (NdisEqualMemory(pEid->Octet, WPS_OUI, 4)
 #ifdef IWSC_SUPPORT
						 || NdisEqualMemory(pEid->Octet, IWSC_OUI, 4)
#endif // IWSC_SUPPORT //
						 ))
                {
#if 0
					if (PeerWscIeLen >= 512)
						DBGPRINT(RT_DEBUG_ERROR, ("%s: PeerWscIeLen = %d (>= 512)\n", __FUNCTION__, PeerWscIeLen));
					if (pPeerWscIe && (PeerWscIeLen < 512))
					{
						NdisMoveMemory(pPeerWscIe+PeerWscIeLen, pEid->Octet+4, pEid->Len-4);
						PeerWscIeLen += (pEid->Len - 4);
					}
#ifdef IWSC_SUPPORT
					if (NdisEqualMemory(pEid->Octet, IWSC_OUI, 4))
						bFoundIWscIe = TRUE;
#endif /* IWSC_SUPPORT */
#else
					if (pPeerWscIe)
					{
						/* Ignore old WPS IE fragments, if we get the version 0x10 */
						if (pEid->Octet[4] == 0x10) //First WPS IE will have version 0x10
						{
							if (pEid->Len >= 4)
							{
								NdisMoveMemory(pPeerWscIe, pEid->Octet+4, pEid->Len - 4);
								PeerWscIeLen = (pEid->Len - 4);
							}
						}
						else // reassembly remanning, other IE fragmentations will not have version 0x10
						{
							if (pEid->Len < 4)
							{
								bWscCheck = FALSE;
								DBGPRINT(RT_DEBUG_ERROR, ("%s: Error!!! element length = %d \n", __FUNCTION__, pEid->Len));
							}
							else if ((PeerWscIeLen +(pEid->Len - 4)) <= 512)
							{
								NdisMoveMemory(pPeerWscIe+PeerWscIeLen, pEid->Octet+4, pEid->Len - 4);
								PeerWscIeLen += (pEid->Len - 4);
							}
							else /* ((PeerWscIeLen +(pEid->Len - 4)) > 512) */
							{
								bWscCheck = FALSE;
								DBGPRINT(RT_DEBUG_ERROR, ("%s: Error!!! Sum of All PeerWscIeLen = %d (> 512)\n", __FUNCTION__, (PeerWscIeLen +(pEid->Len - 4))));
							}
						}
					}
					else
					{
						bWscCheck = FALSE;
						DBGPRINT(RT_DEBUG_ERROR, ("%s: Error!!! pPeerWscIe is empty!\n", __FUNCTION__));
					}
#endif			
                }

                
                break;

            case IE_EXT_SUPP_RATES:
                if (pEid->Len <= MAX_LEN_OF_SUPPORTED_RATES)
                {
                    NdisMoveMemory(ExtRate, pEid->Octet, pEid->Len);
                    *pExtRateLen = pEid->Len;

                    /*
						TODO: 2004-09-14 not a good design here, cause it exclude extra rates
								from ScanTab. We should report as is. And filter out unsupported
								rates in MlmeAux
					*/
                    /* Check against the supported rates*/
                    /* RTMPCheckRates(pAd, ExtRate, pExtRateLen);*/
                }
                break;

            case IE_ERP:
                if (pEid->Len == 1)
                {
                    *pErp = (UCHAR)pEid->Octet[0];
                }
                break;

            case IE_AIRONET_CKIP:
                /*
					0. Check Aironet IE length, it must be larger or equal to 28
						Cisco AP350 used length as 28
						Cisco AP12XX used length as 30
				*/
                if (pEid->Len < (CKIP_NEGOTIATION_LENGTH - 2))
                    break;

                /* 1. Copy CKIP flag byte to buffer for process*/
                *pCkipFlag = *(pEid->Octet + 8);				
                break;

            case IE_AP_TX_POWER:
                /* AP Control of Client Transmit Power*/
                /*0. Check Aironet IE length, it must be 6*/
                if (pEid->Len != 0x06)
                    break;

                /* Get cell power limit in dBm*/
                if (NdisEqualMemory(pEid->Octet, CISCO_OUI, 3) == 1)
                    *pAironetCellPowerLimit = *(pEid->Octet + 4);	
                break;

            /* WPA2 & 802.11i RSN*/
            case IE_RSN:
                /* There is no OUI for version anymore, check the group cipher OUI before copying*/
                if (RTMPEqualMemory(pEid->Octet + 2, RSN_OUI, 3))
                {
                    /* Copy to pVIE which will report to microsoft bssid list.*/
                    Ptr = (PUCHAR) pVIE;
                    NdisMoveMemory(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                    *LengthVIE += (pEid->Len + 2);
                }
                break;
#ifdef WAPI_SUPPORT
			/* WAPI information element*/
            case IE_WAPI:                
                if (RTMPEqualMemory(pEid->Octet + 4, WAPI_OUI, 3))
                {
                    /* Copy to pVIE*/
                    Ptr = (PUCHAR) pVIE;
                    NdisMoveMemory(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                    *LengthVIE += (pEid->Len + 2);
                }
                break;
#endif /* WAPI_SUPPORT */

#ifdef CONFIG_STA_SUPPORT
#if defined (EXT_BUILD_CHANNEL_LIST) || defined (RT_CFG80211_SUPPORT)
			case IE_COUNTRY:
				Ptr = (PUCHAR) pVIE;
                NdisMoveMemory(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                *LengthVIE += (pEid->Len + 2);
				break;
#endif /* EXT_BUILD_CHANNEL_LIST */
#endif /* CONFIG_STA_SUPPORT */

            case IE_QBSS_LOAD:
                if (pEid->Len == 5)
                {
                    pQbssLoad->bValid = TRUE;
                    pQbssLoad->StaNum = pEid->Octet[0] + pEid->Octet[1] * 256;
                    pQbssLoad->ChannelUtilization = pEid->Octet[2];
                    pQbssLoad->RemainingAdmissionControl = pEid->Octet[3] + pEid->Octet[4] * 256;

					/* Copy to pVIE*/
                    Ptr = (PUCHAR) pVIE;
                    NdisMoveMemory(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                    *LengthVIE += (pEid->Len + 2);
                }
                break;
                


			case IE_EXT_CAPABILITY:
			if (pEid->Len >= 1)
			{
				UCHAR MaxSize;
				UCHAR MySize = sizeof(EXT_CAP_INFO_ELEMENT);

				MaxSize = min(pEid->Len, MySize);

				NdisMoveMemory(pExtCapInfo,&pEid->Octet[0], MaxSize);
			}
			break;

            default:
                break;
        }
        
        Length = Length + 2 + pEid->Len;  /* Eid[1] + Len[1]+ content[Len]*/
        pEid = (PEID_STRUCT)((UCHAR*)pEid + 2 + pEid->Len);        
    }

	LatchRfChannel = MsgChannel;

		if ((pAd->LatchRfRegs.Channel > 14) && ((Sanity & 0x4) == 0))
		{
			if (CtrlChannel != 0)
				*pChannel = CtrlChannel;
			else
				*pChannel = LatchRfChannel;
			Sanity |= 0x4;
		}

		if (pPeerWscIe && (PeerWscIeLen > 0) && (PeerWscIeLen < 512) && (bWscCheck == TRUE))
		{
			UCHAR WscIe[] = {0xdd, 0x00, 0x00, 0x50, 0xF2, 0x04};
			Ptr = (PUCHAR) pVIE;
			WscIe[1] = PeerWscIeLen + 4;
			NdisMoveMemory(Ptr + *LengthVIE, WscIe, 6);
			NdisMoveMemory(Ptr + *LengthVIE + 6, pPeerWscIe, PeerWscIeLen);
			*LengthVIE += (PeerWscIeLen + 6);
#ifdef IWSC_SUPPORT
			if ((pAd->StaCfg.BssType == BSS_ADHOC) &&
				(SubType == SUBTYPE_PROBE_RSP) &&
				(bFoundIWscIe == TRUE))
			{
				BOOLEAN bSelReg = FALSE;
				USHORT DataLen = 0;
				
				/* re-use this boolean variable */
				bFoundIWscIe = FALSE;
				WscGetDataFromPeerByTag(pAd, pPeerWscIe, PeerWscIeLen, WSC_ID_SEL_REGISTRAR, &bSelReg, NULL);				
				if (bSelReg)
				{
					bFoundIWscIe = TRUE;
					if (WscGetDataFromPeerByTag(pAd, 
												pPeerWscIe, 
												PeerWscIeLen,
												WSC_ID_MAC_ADDR, 
												&pAd->StaCfg.WscControl.WscPeerMAC[0], 
												NULL) == FALSE)
					{
						NdisMoveMemory(&pAd->StaCfg.WscControl.WscPeerMAC[0], pAddr2, MAC_ADDR_LEN);
					}
					NdisMoveMemory(&pAd->StaCfg.WscControl.EntryAddr[0], 
							&pAd->StaCfg.WscControl.WscPeerMAC[0], 
							MAC_ADDR_LEN);
					hex_dump("PeerBeaconAndProbeRspSanity - WscPeerMAC", &pAd->StaCfg.WscControl.WscPeerMAC[0], MAC_ADDR_LEN);
					
					WscGetDataFromPeerByTag(pAd, 
											pPeerWscIe, 
											PeerWscIeLen,
											WSC_ID_SEL_REG_CFG_METHODS, 
											&PeerConfigMethod, 
											NULL);
				}
			}
#endif /* IWSC_SUPPORT */
		}
		

SanityCheck:
	if (pPeerWscIe)
		os_free_mem(NULL, pPeerWscIe);

	if ((Sanity != 0x7) || (bWscCheck == FALSE))
	{
		DBGPRINT(RT_DEBUG_LOUD, ("PeerBeaconAndProbeRspSanity - missing field, Sanity=0x%02x\n", Sanity));
		return FALSE;
	}
	else
	{
#ifdef IWSC_SUPPORT
		if (bFoundIWscIe && (pAd->StaCfg.BssType == BSS_ADHOC))
		{
			PWSC_CTRL pWscCtrl = &pAd->StaCfg.WscControl;
			if ((pWscCtrl->WscConfMode == WSC_ENROLLEE) &&
				(pWscCtrl->WscMode == WSC_PIN_MODE) &&
				(pWscCtrl->bWscTrigger == TRUE))
			{
				NdisZeroMemory(&pWscCtrl->WscSsid, sizeof(NDIS_802_11_SSID));
				if ((*pSsidLen) <= 32 && (*pSsidLen) != 0)
				{
					pWscCtrl->WscSsid.SsidLength = *pSsidLen;
					NdisMoveMemory(pWscCtrl->WscSsid.Ssid, Ssid, pWscCtrl->WscSsid.SsidLength);
					PeerConfigMethod = be2cpu16(PeerConfigMethod);
					MlmeEnqueue(pAd, IWSC_STATE_MACHINE, IWSC_MT2_PEER_PROBE_RSP, sizeof(USHORT), &PeerConfigMethod, 0);
				}
			}
		}
#endif /* IWSC_SUPPORT */
		return TRUE;
	}

}

#ifdef DOT11N_DRAFT3
/* 
	==========================================================================
	Description:
		MLME message sanity check for some IE addressed  in 802.11n d3.03.
	Return:
		TRUE if all parameters are OK, FALSE otherwise

	IRQL = DISPATCH_LEVEL

	==========================================================================
 */
BOOLEAN PeerBeaconAndProbeRspSanity2(
	IN PRTMP_ADAPTER pAd, 
	IN VOID *Msg, 
	IN ULONG MsgLen, 
	IN OVERLAP_BSS_SCAN_IE *BssScan,
	OUT UCHAR 	*RegClass)
{
	CHAR				*Ptr;
	PFRAME_802_11		pFrame;
	PEID_STRUCT			pEid;
	ULONG				Length = 0;	
	BOOLEAN				brc;

	pFrame = (PFRAME_802_11)Msg;

	*RegClass = 0;
	Ptr = pFrame->Octet;
	Length += LENGTH_802_11;

	/* get timestamp from payload and advance the pointer*/
	Ptr += TIMESTAMP_LEN;
	Length += TIMESTAMP_LEN;

	/* get beacon interval from payload and advance the pointer*/
	Ptr += 2;
	Length += 2;

	/* get capability info from payload and advance the pointer*/
	Ptr += 2;
	Length += 2;

	pEid = (PEID_STRUCT) Ptr;
	brc = FALSE;

	RTMPZeroMemory(BssScan, sizeof(OVERLAP_BSS_SCAN_IE));
	/* get variable fields from payload and advance the pointer*/
	while ((Length + 2 + pEid->Len) <= MsgLen)	  
	{	
		switch(pEid->Eid)
		{
			case IE_SUPP_REG_CLASS:
				if(pEid->Len > 0)
				{
					*RegClass = *pEid->Octet;
				}
				else
				{
					DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_SUPP_REG_CLASS (len=%d)\n",pEid->Len));
				}
				break;
			case IE_OVERLAPBSS_SCAN_PARM:
				if (pEid->Len == sizeof(OVERLAP_BSS_SCAN_IE))
				{
					brc = TRUE;
					RTMPMoveMemory(BssScan, pEid->Octet, sizeof(OVERLAP_BSS_SCAN_IE));
				}
				else
				{
					DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_OVERLAPBSS_SCAN_PARM (len=%d)\n",pEid->Len));
				}
				break;

			case IE_EXT_CHANNEL_SWITCH_ANNOUNCEMENT:
				DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - IE_EXT_CHANNEL_SWITCH_ANNOUNCEMENT\n"));
				break;

		}

		Length = Length + 2 + pEid->Len;  /* Eid[1] + Len[1]+ content[Len]	*/
		pEid = (PEID_STRUCT)((UCHAR*)pEid + 2 + pEid->Len); 	   
	}

	return brc;

}
#endif /* DOT11N_DRAFT3 */

#if defined(AP_SCAN_SUPPORT) || defined(CONFIG_STA_SUPPORT)
/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
    ==========================================================================
 */
BOOLEAN MlmeScanReqSanity(
	IN PRTMP_ADAPTER pAd, 
	IN VOID *Msg, 
	IN ULONG MsgLen, 
	OUT UCHAR *pBssType, 
	OUT CHAR Ssid[], 
	OUT UCHAR *pSsidLen, 
	OUT UCHAR *pScanType) 
{
	MLME_SCAN_REQ_STRUCT *Info;

	Info = (MLME_SCAN_REQ_STRUCT *)(Msg);
	*pBssType = Info->BssType;
	*pSsidLen = Info->SsidLen;	
	NdisMoveMemory(Ssid, Info->Ssid, *pSsidLen);
	*pScanType = Info->ScanType;

	if ((*pBssType == BSS_INFRA || *pBssType == BSS_ADHOC || *pBssType == BSS_ANY)
		&& (*pScanType == SCAN_ACTIVE || *pScanType == SCAN_PASSIVE
#ifdef WSC_INCLUDED
		|| (*pScanType == SCAN_WSC_ACTIVE)
#endif /* WSC_INCLUDED */
#ifdef DOT11_N_SUPPORT
#ifdef DOT11N_DRAFT3
		|| (*pScanType == SCAN_2040_BSS_COEXIST) 
#endif /*DOT11N_DRAFT3 */
#endif /* DOT11_N_SUPPORT */
#ifdef P2P_SUPPORT
		|| (*pScanType == SCAN_P2P) 
		|| (*pScanType == SCAN_P2P_SEARCH) 
#endif /* P2P_SUPPORT */
		))
	{
		return TRUE;
	}
	else
	{
		DBGPRINT(RT_DEBUG_TRACE, ("MlmeScanReqSanity fail - wrong BssType or ScanType\n"));
		return FALSE;
	}
}
#endif

/* IRQL = DISPATCH_LEVEL*/
UCHAR ChannelSanity(
    IN PRTMP_ADAPTER pAd, 
    IN UCHAR channel)
{
    int i;

    for (i = 0; i < pAd->ChannelListNum; i ++)
    {
        if (channel == pAd->ChannelList[i].Channel)
            return 1;
    }
    return 0;
}

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
        
	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
BOOLEAN PeerDeauthSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen, 
    OUT PUCHAR pAddr1, 
    OUT PUCHAR pAddr2, 
    OUT PUCHAR pAddr3, 
    OUT USHORT *pReason) 
{
    PFRAME_802_11 pFrame = (PFRAME_802_11)Msg;

	COPY_MAC_ADDR(pAddr1, pFrame->Hdr.Addr1);
    COPY_MAC_ADDR(pAddr2, pFrame->Hdr.Addr2);
	COPY_MAC_ADDR(pAddr3, pFrame->Hdr.Addr3);
    NdisMoveMemory(pReason, &pFrame->Octet[0], 2);

    return TRUE;
}

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
        
	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
BOOLEAN PeerAuthSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen, 
    OUT PUCHAR pAddr, 
    OUT USHORT *pAlg, 
    OUT USHORT *pSeq, 
    OUT USHORT *pStatus, 
    CHAR *pChlgText) 
{
    PFRAME_802_11 pFrame = (PFRAME_802_11)Msg;

    COPY_MAC_ADDR(pAddr,   pFrame->Hdr.Addr2);
    NdisMoveMemory(pAlg,    &pFrame->Octet[0], 2);
    NdisMoveMemory(pSeq,    &pFrame->Octet[2], 2);
    NdisMoveMemory(pStatus, &pFrame->Octet[4], 2);

    if (*pAlg == AUTH_MODE_OPEN)
    {
        if (*pSeq == 1 || *pSeq == 2) 
        {
            return TRUE;
        } 
        else 
        {
            DBGPRINT(RT_DEBUG_TRACE, ("PeerAuthSanity fail - wrong Seg#\n"));
            return FALSE;
        }
    } 
    else if (*pAlg == AUTH_MODE_KEY) 
    {
        if (*pSeq == 1 || *pSeq == 4) 
        {
            return TRUE;
        } 
        else if (*pSeq == 2 || *pSeq == 3) 
        {
            NdisMoveMemory(pChlgText, &pFrame->Octet[8], CIPHER_TEXT_LEN);
            return TRUE;
        } 
        else 
        {
            DBGPRINT(RT_DEBUG_TRACE, ("PeerAuthSanity fail - wrong Seg#\n"));
            return FALSE;
        }
    } 
    else 
    {
        DBGPRINT(RT_DEBUG_TRACE, ("PeerAuthSanity fail - wrong algorithm\n"));
        return FALSE;
    }
}

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
    ==========================================================================
 */
BOOLEAN MlmeAuthReqSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen, 
    OUT PUCHAR pAddr, 
    OUT ULONG *pTimeout, 
    OUT USHORT *pAlg) 
{
    MLME_AUTH_REQ_STRUCT *pInfo;

    pInfo  = (MLME_AUTH_REQ_STRUCT *)Msg;
    COPY_MAC_ADDR(pAddr, pInfo->Addr);
    *pTimeout = pInfo->Timeout;
    *pAlg = pInfo->Alg;
    
    if (((*pAlg == AUTH_MODE_KEY) ||(*pAlg == AUTH_MODE_OPEN)
     	) && 
        ((*pAddr & 0x01) == 0)) 
    {
#ifdef CONFIG_STA_SUPPORT
#ifdef WSC_INCLUDED
		if (pAd->StaCfg.WscControl.bWscTrigger && (pAd->StaCfg.WscControl.WscConfMode != WSC_DISABLE))
			*pAlg = AUTH_MODE_OPEN;
#endif /* WSC_INCLUDED */
#endif /* CONFIG_STA_SUPPORT */
        return TRUE;
    } 
    else 
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAuthReqSanity fail - wrong algorithm\n"));
        return FALSE;
    }
}

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
        
	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
BOOLEAN MlmeAssocReqSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen, 
    OUT PUCHAR pApAddr, 
    OUT USHORT *pCapabilityInfo, 
    OUT ULONG *pTimeout, 
    OUT USHORT *pListenIntv) 
{
    MLME_ASSOC_REQ_STRUCT *pInfo;

    pInfo = (MLME_ASSOC_REQ_STRUCT *)Msg;
    *pTimeout = pInfo->Timeout;                             /* timeout*/
    COPY_MAC_ADDR(pApAddr, pInfo->Addr);                   /* AP address*/
    *pCapabilityInfo = pInfo->CapabilityInfo;               /* capability info*/
    *pListenIntv = pInfo->ListenIntv;
    
    return TRUE;
}

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
        
	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
BOOLEAN PeerDisassocSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen, 
    OUT PUCHAR pAddr2, 
    OUT USHORT *pReason) 
{
    PFRAME_802_11 pFrame = (PFRAME_802_11)Msg;

    COPY_MAC_ADDR(pAddr2, pFrame->Hdr.Addr2);
    NdisMoveMemory(pReason, &pFrame->Octet[0], 2);

    return TRUE;
}

/*
	========================================================================
	Routine Description:
		Sanity check NetworkType (11b, 11g or 11a)
		
	Arguments:
		pBss - Pointer to BSS table.

	Return Value:
        Ndis802_11DS .......(11b)
        Ndis802_11OFDM24....(11g)
        Ndis802_11OFDM5.....(11a)
        
	IRQL = DISPATCH_LEVEL
	
	========================================================================
*/
NDIS_802_11_NETWORK_TYPE NetworkTypeInUseSanity(
    IN PBSS_ENTRY pBss)
{
	NDIS_802_11_NETWORK_TYPE	NetWorkType;
	UCHAR						rate, i;

	NetWorkType = Ndis802_11DS;
	
	if (pBss->Channel <= 14)
	{
		
		/* First check support Rate.*/
		for (i = 0; i < pBss->SupRateLen; i++)
		{
			rate = pBss->SupRate[i] & 0x7f; /* Mask out basic rate set bit*/
			if ((rate == 2) || (rate == 4) || (rate == 11) || (rate == 22))
			{
				continue;
			}
			else
			{
				
				/* Otherwise (even rate > 108) means Ndis802_11OFDM24*/
				NetWorkType = Ndis802_11OFDM24;
				break;
			}	
		}

		
		/* Second check Extend Rate.*/
		if (NetWorkType != Ndis802_11OFDM24)
		{
			for (i = 0; i < pBss->ExtRateLen; i++)
			{
				rate = pBss->SupRate[i] & 0x7f; /* Mask out basic rate set bit*/
				if ((rate == 2) || (rate == 4) || (rate == 11) || (rate == 22))
				{
					continue;
				}
				else
				{
					
					/* Otherwise (even rate > 108) means Ndis802_11OFDM24*/
					NetWorkType = Ndis802_11OFDM24;
					break;
				}
			}
		}
	}
	else
	{
		NetWorkType = Ndis802_11OFDM5;
	}

    if (pBss->HtCapabilityLen != 0)
    {
        if (NetWorkType == Ndis802_11OFDM5)
            NetWorkType = Ndis802_11OFDM5_N;
        else
            NetWorkType = Ndis802_11OFDM24_N;
    }

	return NetWorkType;
}	

#ifdef CONFIG_STA_SUPPORT
#ifdef QOS_DLS_SUPPORT
BOOLEAN MlmeDlsReqSanity(
	IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen,
    OUT PRT_802_11_DLS *pDLS,
    OUT PUSHORT pReason)
{
	MLME_DLS_REQ_STRUCT *pInfo;

    pInfo = (MLME_DLS_REQ_STRUCT *)Msg;
    
	*pDLS = pInfo->pDLS;
	*pReason = pInfo->Reason;

	return TRUE;
}
#endif /* QOS_DLS_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */

#ifdef QOS_DLS_SUPPORT
BOOLEAN PeerDlsReqSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen,
    OUT PUCHAR pDA,
    OUT PUCHAR pSA,
    OUT USHORT *pCapabilityInfo, 
    OUT USHORT *pDlsTimeout,
    OUT UCHAR *pRatesLen,
    OUT UCHAR Rates[],
	OUT UCHAR *pHtCapabilityLen,
    OUT HT_CAPABILITY_IE *pHtCapability)
{
	CHAR            *Ptr;
    PFRAME_802_11	Fr = (PFRAME_802_11)Msg;
	PEID_STRUCT  eid_ptr;

    /* to prevent caller from using garbage output value*/
    *pCapabilityInfo	= 0;
    *pDlsTimeout	= 0;
	*pHtCapabilityLen = 0;

    Ptr = (PCHAR)Fr->Octet;

	/* offset to destination MAC address (Category and Action field)*/
    Ptr += 2;

    /* get DA from payload and advance the pointer*/
    NdisMoveMemory(pDA, Ptr, MAC_ADDR_LEN);
    Ptr += MAC_ADDR_LEN;

    /* get SA from payload and advance the pointer*/
    NdisMoveMemory(pSA, Ptr, MAC_ADDR_LEN);
    Ptr += MAC_ADDR_LEN;

    /* get capability info from payload and advance the pointer*/
    NdisMoveMemory(pCapabilityInfo, Ptr, 2);
    Ptr += 2;

    /* get capability info from payload and advance the pointer*/
    NdisMoveMemory(pDlsTimeout, Ptr, 2);
    Ptr += 2;

	/* Category and Action field + DA + SA + capability + Timeout*/
	eid_ptr = (PEID_STRUCT) &Fr->Octet[18];	

	while (((UCHAR*)eid_ptr + eid_ptr->Len + 1) < ((UCHAR*)Fr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_SUPP_RATES:
                if ((eid_ptr->Len <= MAX_LEN_OF_SUPPORTED_RATES) && (eid_ptr->Len > 0))
                {
                    NdisMoveMemory(Rates, eid_ptr->Octet, eid_ptr->Len);
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsReqSanity - IE_SUPP_RATES., Len=%d. Rates[0]=%x\n",eid_ptr->Len, Rates[0]));
                    DBGPRINT(RT_DEBUG_TRACE, ("Rates[1]=%x %x %x %x %x %x %x\n", Rates[1], Rates[2], Rates[3], Rates[4], Rates[5], Rates[6], Rates[7]));
                    *pRatesLen = eid_ptr->Len;
                }
                else
                {
                    *pRatesLen = 8;
					Rates[0] = 0x82;
					Rates[1] = 0x84;
					Rates[2] = 0x8b;
					Rates[3] = 0x96;
					Rates[4] = 0x12;
					Rates[5] = 0x24;
					Rates[6] = 0x48;
					Rates[7] = 0x6c;
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsReqSanity - wrong IE_SUPP_RATES., Len=%d\n",eid_ptr->Len));
                }
				break;

			case IE_EXT_SUPP_RATES:
                if (eid_ptr->Len + *pRatesLen <= MAX_LEN_OF_SUPPORTED_RATES)
                {
                    NdisMoveMemory(&Rates[*pRatesLen], eid_ptr->Octet, eid_ptr->Len);
                    *pRatesLen = (*pRatesLen) + eid_ptr->Len;
                }
                else
                {
                    NdisMoveMemory(&Rates[*pRatesLen], eid_ptr->Octet, MAX_LEN_OF_SUPPORTED_RATES - (*pRatesLen));
                    *pRatesLen = MAX_LEN_OF_SUPPORTED_RATES;
                }
				break;

			case IE_HT_CAP:
				if (eid_ptr->Len >= sizeof(HT_CAPABILITY_IE))
				{
					NdisMoveMemory(pHtCapability, eid_ptr->Octet, sizeof(HT_CAPABILITY_IE));

					*(USHORT *)(&pHtCapability->HtCapInfo) = cpu2le16(*(USHORT *)(&pHtCapability->HtCapInfo));
#ifdef UNALIGNMENT_SUPPORT
					{
						EXT_HT_CAP_INFO extHtCapInfo;

						NdisMoveMemory((PUCHAR)(&extHtCapInfo), (PUCHAR)(&pHtCapability->ExtHtCapInfo), sizeof(EXT_HT_CAP_INFO));
						*(USHORT *)(&extHtCapInfo) = cpu2le16(*(USHORT *)(&extHtCapInfo));
						NdisMoveMemory((PUCHAR)(&pHtCapability->ExtHtCapInfo), (PUCHAR)(&extHtCapInfo), sizeof(EXT_HT_CAP_INFO));		
					}
#else				
					*(USHORT *)(&pHtCapability->ExtHtCapInfo) = cpu2le16(*(USHORT *)(&pHtCapability->ExtHtCapInfo));
#endif /* UNALIGNMENT_SUPPORT */
					*pHtCapabilityLen = sizeof(HT_CAPABILITY_IE);

					DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsReqSanity - IE_HT_CAP\n"));
				}
				else
				{
					DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsReqSanity - wrong IE_HT_CAP.eid_ptr->Len = %d\n", eid_ptr->Len));
				}
				break;

			default:
				break;
		}

		eid_ptr = (PEID_STRUCT)((UCHAR*)eid_ptr + 2 + eid_ptr->Len);
	}

    return TRUE;
}

BOOLEAN PeerDlsRspSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen,
    OUT PUCHAR pDA,
    OUT PUCHAR pSA,
    OUT USHORT *pCapabilityInfo, 
    OUT USHORT *pStatus,
    OUT UCHAR *pRatesLen,
    OUT UCHAR Rates[],
    OUT UCHAR *pHtCapabilityLen,
    OUT HT_CAPABILITY_IE *pHtCapability) 
{
    CHAR            *Ptr;
    PFRAME_802_11	Fr = (PFRAME_802_11)Msg;
	PEID_STRUCT  eid_ptr;

    /* to prevent caller from using garbage output value*/
	if (pStatus)
    *pStatus		= 0;
    *pCapabilityInfo	= 0;
	*pHtCapabilityLen = 0;

    Ptr = (PCHAR)Fr->Octet;

	/* offset to destination MAC address (Category and Action field)*/
    Ptr += 2;

	/* get status code from payload and advance the pointer*/
	if (pStatus)
		NdisMoveMemory(pStatus, Ptr, 2);
    Ptr += 2;

    /* get DA from payload and advance the pointer*/
    NdisMoveMemory(pDA, Ptr, MAC_ADDR_LEN);
    Ptr += MAC_ADDR_LEN;

    /* get SA from payload and advance the pointer*/
    NdisMoveMemory(pSA, Ptr, MAC_ADDR_LEN);
    Ptr += MAC_ADDR_LEN;

	if (pStatus == 0)
	{
	    /* get capability info from payload and advance the pointer*/
	    NdisMoveMemory(pCapabilityInfo, Ptr, 2);
	    Ptr += 2;
	}

	/* Category and Action field + status code + DA + SA + capability*/
	eid_ptr = (PEID_STRUCT) &Fr->Octet[18];	

	while (((UCHAR*)eid_ptr + eid_ptr->Len + 1) < ((UCHAR*)Fr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_SUPP_RATES:
                if ((eid_ptr->Len <= MAX_LEN_OF_SUPPORTED_RATES) && (eid_ptr->Len > 0))
                {
                    NdisMoveMemory(Rates, eid_ptr->Octet, eid_ptr->Len);
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsRspSanity - IE_SUPP_RATES., Len=%d. Rates[0]=%x\n",eid_ptr->Len, Rates[0]));
                    DBGPRINT(RT_DEBUG_TRACE, ("Rates[1]=%x %x %x %x %x %x %x\n", Rates[1], Rates[2], Rates[3], Rates[4], Rates[5], Rates[6], Rates[7]));
                    *pRatesLen = eid_ptr->Len;
                }
                else
                {
                    *pRatesLen = 8;
					Rates[0] = 0x82;
					Rates[1] = 0x84;
					Rates[2] = 0x8b;
					Rates[3] = 0x96;
					Rates[4] = 0x12;
					Rates[5] = 0x24;
					Rates[6] = 0x48;
					Rates[7] = 0x6c;
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsRspSanity - wrong IE_SUPP_RATES., Len=%d\n",eid_ptr->Len));
                }
				break;

			case IE_EXT_SUPP_RATES:
                if (eid_ptr->Len + *pRatesLen <= MAX_LEN_OF_SUPPORTED_RATES)
                {
                    NdisMoveMemory(&Rates[*pRatesLen], eid_ptr->Octet, eid_ptr->Len);
                    *pRatesLen = (*pRatesLen) + eid_ptr->Len;
                }
                else
                {
                    NdisMoveMemory(&Rates[*pRatesLen], eid_ptr->Octet, MAX_LEN_OF_SUPPORTED_RATES - (*pRatesLen));
                    *pRatesLen = MAX_LEN_OF_SUPPORTED_RATES;
                }
				break;

			case IE_HT_CAP:
				if (eid_ptr->Len >= sizeof(HT_CAPABILITY_IE))
				{
					NdisMoveMemory(pHtCapability, eid_ptr->Octet, sizeof(HT_CAPABILITY_IE));

					*(USHORT *)(&pHtCapability->HtCapInfo) = cpu2le16(*(USHORT *)(&pHtCapability->HtCapInfo));
#ifdef UNALIGNMENT_SUPPORT
					{
						EXT_HT_CAP_INFO extHtCapInfo;

						NdisMoveMemory((PUCHAR)(&extHtCapInfo), (PUCHAR)(&pHtCapability->ExtHtCapInfo), sizeof(EXT_HT_CAP_INFO));
						*(USHORT *)(&extHtCapInfo) = cpu2le16(*(USHORT *)(&extHtCapInfo));
						NdisMoveMemory((PUCHAR)(&pHtCapability->ExtHtCapInfo), (PUCHAR)(&extHtCapInfo), sizeof(EXT_HT_CAP_INFO));		
					}
#else				
					*(USHORT *)(&pHtCapability->ExtHtCapInfo) = cpu2le16(*(USHORT *)(&pHtCapability->ExtHtCapInfo));
#endif /* UNALIGNMENT_SUPPORT */
					*pHtCapabilityLen = sizeof(HT_CAPABILITY_IE);

					DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsRspSanity - IE_HT_CAP\n"));
				}
				else
				{
					DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsRspSanity - wrong IE_HT_CAP.eid_ptr->Len = %d\n", eid_ptr->Len));
				}
				break;

			default:
				break;
		}

		eid_ptr = (PEID_STRUCT)((UCHAR*)eid_ptr + 2 + eid_ptr->Len);
	}

    return TRUE;
}

BOOLEAN PeerDlsTearDownSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen,
    OUT PUCHAR pDA,
    OUT PUCHAR pSA,
    OUT USHORT *pReason) 
{
    CHAR            *Ptr;
    PFRAME_802_11	Fr = (PFRAME_802_11)Msg;

    /* to prevent caller from using garbage output value*/
    *pReason	= 0;

    Ptr = (PCHAR)Fr->Octet;

	/* offset to destination MAC address (Category and Action field)*/
    Ptr += 2;

    /* get DA from payload and advance the pointer*/
    NdisMoveMemory(pDA, Ptr, MAC_ADDR_LEN);
    Ptr += MAC_ADDR_LEN;

    /* get SA from payload and advance the pointer*/
    NdisMoveMemory(pSA, Ptr, MAC_ADDR_LEN);
    Ptr += MAC_ADDR_LEN;

	/* get reason code from payload and advance the pointer*/
    NdisMoveMemory(pReason, Ptr, 2);
    Ptr += 2;

    return TRUE;
}
#endif /* QOS_DLS_SUPPORT */

/* 
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        TRUE if all parameters are OK, FALSE otherwise
    ==========================================================================
 */
BOOLEAN PeerProbeReqSanity(
    IN PRTMP_ADAPTER pAd, 
    IN VOID *Msg, 
    IN ULONG MsgLen, 
    OUT PUCHAR pAddr2,
    OUT CHAR Ssid[], 
    OUT UCHAR *SsidLen, 
    OUT BOOLEAN *bRssiRequested)
{
    PFRAME_802_11 Fr = (PFRAME_802_11)Msg;
    UCHAR		*Ptr;
    UCHAR		eid =0, eid_len = 0, *eid_data;
#ifdef CONFIG_AP_SUPPORT
    UCHAR       apidx = MAIN_MBSSID;
	UCHAR       Addr1[MAC_ADDR_LEN];
#ifdef WSC_INCLUDED
	UCHAR		*pPeerWscIe = NULL;
	UINT		PeerWscIeLen = 0;
#endif /* WSC_INCLUDED */
#endif /* CONFIG_AP_SUPPORT */
	UINT		total_ie_len = 0;	

    /* to prevent caller from using garbage output value*/
#ifdef CONFIG_AP_SUPPORT
	apidx = apidx; /* avoid compile warning */
#endif /* CONFIG_AP_SUPPORT */
    *SsidLen = 0;

    COPY_MAC_ADDR(pAddr2, &Fr->Hdr.Addr2);

    if (Fr->Octet[0] != IE_SSID || Fr->Octet[1] > MAX_LEN_OF_SSID) 
    {
        DBGPRINT(RT_DEBUG_TRACE, ("APPeerProbeReqSanity fail - wrong SSID IE\n"));
        return FALSE;
    } 
    
    *SsidLen = Fr->Octet[1];
    NdisMoveMemory(Ssid, &Fr->Octet[2], *SsidLen);
	
#ifdef CONFIG_AP_SUPPORT
	COPY_MAC_ADDR(Addr1, &Fr->Hdr.Addr1);
#ifdef WSC_AP_SUPPORT
	os_alloc_mem(NULL, &pPeerWscIe, 512);
#endif /* WSC_AP_SUPPORT */
#endif /* CONFIG_AP_SUPPORT */

    Ptr = Fr->Octet;
    eid = Ptr[0];
    eid_len = Ptr[1];
	total_ie_len = eid_len + 2;
	eid_data = Ptr+2;
    
    /* get variable fields from payload and advance the pointer*/
	while((eid_data + eid_len) <= ((UCHAR*)Fr + MsgLen))
    {    	
        switch(eid)
        {
	        case IE_VENDOR_SPECIFIC:
				if (eid_len <= 4)
					break;
#ifdef RSSI_FEEDBACK
                if (bRssiRequested && NdisEqualMemory(eid_data, RALINK_OUI, 3) && (eid_len == 7))
                {
					if (*(eid_data + 3/* skip RALINK_OUI */) & 0x8)
                    	*bRssiRequested = TRUE;
                    break;
                }
#endif /* RSSI_FEEDBACK */

                if (NdisEqualMemory(eid_data, WPS_OUI, 4)
 #ifdef IWSC_SUPPORT
					|| NdisEqualMemory(eid_data, IWSC_OUI, 4) 
#endif // IWSC_SUPPORT //
					)
                {
#ifdef CONFIG_AP_SUPPORT
#endif /* CONFIG_AP_SUPPORT */

#ifdef WSC_INCLUDED


#ifdef IWSC_SUPPORT
#ifdef CONFIG_STA_SUPPORT
					if (pAd->StaCfg.BssType == BSS_ADHOC)
					{
						if (NdisEqualMemory(eid_data, IWSC_OUI, 4))
							WscCheckPeerDPID(pAd, Fr, eid_data, eid_len);
					}
					else if (NdisEqualMemory(eid_data, WPS_OUI, 4))
#endif /* CONFIG_STA_SUPPORT */
#endif /* IWSC_SUPPORT */
					WscCheckPeerDPID(pAd, Fr, eid_data, eid_len);

#ifdef CONFIG_AP_SUPPORT
					if (PeerWscIeLen >= 512)
						DBGPRINT(RT_DEBUG_ERROR, ("APPeerProbeReqSanity : PeerWscIeLen = %d (>= 512)\n", PeerWscIeLen));
					if (pPeerWscIe && (PeerWscIeLen < 512))
					{
						NdisMoveMemory(pPeerWscIe+PeerWscIeLen, eid_data+4, eid_len-4);
						PeerWscIeLen += (eid_len - 4);
					}
#endif /* CONFIG_AP_SUPPORT */
#endif /* WSC_INCLUDED */
                    break;
                }

            default:
                break;
        }
		eid = Ptr[total_ie_len];
    	eid_len = Ptr[total_ie_len + 1];
		eid_data = Ptr + total_ie_len + 2;
		total_ie_len += (eid_len + 2);
	}

#ifdef CONFIG_AP_SUPPORT
#ifdef WSC_INCLUDED
	if (pPeerWscIe && (PeerWscIeLen > 0))
	{
		for (apidx = 0; apidx < pAd->ApCfg.BssidNum; apidx++)
		{
			if (NdisEqualMemory(Addr1, pAd->ApCfg.MBSSID[apidx].Bssid, MAC_ADDR_LEN))
				break;
		}

		/*
			Due to Addr1 in Probe Request may be FF:FF:FF:FF:FF:FF 
			and we need to send out this information to external registrar.
			Therefore we choose ra0 to send this probe req when we couldn't find apidx by Addr1.
		*/
		if (apidx >= pAd->ApCfg.BssidNum)
		{
			apidx = MAIN_MBSSID;
		}
		
		if ((pAd->ApCfg.MBSSID[apidx].WscControl.WscConfMode & WSC_PROXY) != WSC_DISABLE)
		{
	    	int bufLen = 0;
	    	PUCHAR pBuf = NULL;
	    	WSC_IE_PROBREQ_DATA	*pprobreq = NULL;

			/*
				PeerWscIeLen: Len of WSC IE without WSC OUI
			*/
			bufLen = sizeof(WSC_IE_PROBREQ_DATA) + PeerWscIeLen;
			os_alloc_mem(NULL, &pBuf, bufLen);
			if(pBuf)
			{
				/*Send WSC probe req to UPnP*/
				NdisZeroMemory(pBuf, bufLen);
				pprobreq = (WSC_IE_PROBREQ_DATA*)pBuf;
				if (32 >= *SsidLen)	/*Well, I think that it must be TRUE!*/
				{
					NdisMoveMemory(pprobreq->ssid, Ssid, *SsidLen);			/* SSID*/
					NdisMoveMemory(pprobreq->macAddr, Fr->Hdr.Addr2, 6);	/* Mac address*/
					pprobreq->data[0] = PeerWscIeLen>>8; 									/* element ID*/
					pprobreq->data[1] = PeerWscIeLen & 0xff;							/* element Length					*/
					NdisMoveMemory((pBuf+sizeof(WSC_IE_PROBREQ_DATA)), pPeerWscIe, PeerWscIeLen);	/* (WscProbeReqData)*/
					WscSendUPnPMessage(pAd, apidx, 
											WSC_OPCODE_UPNP_MGMT, WSC_UPNP_MGMT_SUB_PROBE_REQ, 
											pBuf, bufLen, 0, 0, &Fr->Hdr.Addr2[0], AP_MODE);
				}
				os_free_mem(NULL, pBuf);
			}
		}		
	}
	if (pPeerWscIe)
		os_free_mem(NULL, pPeerWscIe);
#endif /* WSC_INCLUDED */
#endif /* CONFIG_AP_SUPPORT */

    return TRUE;
}



