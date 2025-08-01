/****************************************************************************
 * Ralink Tech Inc.
 * Taiwan, R.O.C.
 *
 * (c) Copyright 2010, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************/

/****************************************************************************

	Abstract:

	All related Dynamic Rate Switch (AP/STA) function body.

	History:

***************************************************************************/

#include "rt_config.h"


#ifdef CONFIG_AP_SUPPORT
/*
    ==========================================================================
    Description:
        This routine walks through the MAC table, see if TX rate change is 
        required for each associated client. 
    Output:
        pEntry->CurrTxRate - 
    NOTE:
        call this routine every second
    ==========================================================================
 */
VOID APMlmeDynamicTxRateSwitching(
    IN PRTMP_ADAPTER pAd)
{
	ULONG					i;
	PUCHAR					pTable;
	UCHAR					TableSize = 0;
	UCHAR					UpRateIdx, DownRateIdx, CurrRateIdx;
	ULONG					TxTotalCnt;
	ULONG					TxErrorRatio = 0;
	MAC_TABLE_ENTRY			*pEntry;
	PRTMP_TX_RATE_SWITCH	pCurrTxRate, pTmpTxRate = NULL;
	UCHAR					InitTxRateIdx, TrainUp, TrainDown;
	CHAR					Rssi, TmpIdx = 0;
	ULONG					TxSuccess, TxRetransmit, TxFailCount;
	UINT32					MaxWcidNum = MAX_LEN_OF_MAC_TABLE;

#ifdef RALINK_ATE
   	if (ATE_ON(pAd))
   	{
		return;
   	}
#endif /* RALINK_ATE */

#ifdef MAC_REPEATER_SUPPORT
	if (pAd->ApCfg.bMACRepeaterEn)
		MaxWcidNum = MAX_MAC_TABLE_SIZE_WITH_REPEATER;
#endif /* MAC_REPEATER_SUPPORT */


	/* walk through MAC table, see if need to change AP's TX rate toward each entry */
	for (i = 1; i < MaxWcidNum; i++) 
	{
		/* point to information of the individual station */
		pEntry = &pAd->MacTab.Content[i];

		if (IS_ENTRY_NONE(pEntry))
			continue;

		if (IS_ENTRY_CLIENT(pEntry) && (pEntry->Sst != SST_ASSOC))
			continue;

#ifdef APCLI_SUPPORT
		if (IS_ENTRY_APCLI(pEntry) && (pEntry->Sst != SST_ASSOC))
			continue;
#endif /* APCLI_SUPPORT */

#ifdef WDS_SUPPORT
		if (IS_ENTRY_WDS(pEntry) && !WDS_IF_UP_CHECK(pAd, pEntry->MatchWDSTabIdx))
			continue;
#endif /* WDS_SUPPORT */


		/* check if this entry need to switch rate automatically */
		if (RTMPCheckEntryEnableAutoRateSwitch(pAd, pEntry) == FALSE)
			continue;


		MlmeSelectTxRateTable(pAd, pEntry, &pTable, &TableSize, &InitTxRateIdx);
		pEntry->pTable = pTable;

#ifdef NEW_RATE_ADAPT_SUPPORT
		if (ADAPT_RATE_TABLE(pTable))
		{
			APMlmeDynamicTxRateSwitchingAdapt(pAd, i);

			continue;
		}
#endif /* NEW_RATE_ADAPT_SUPPORT */

		/* NICUpdateFifoStaCounters(pAd); */

		if (pAd->MacTab.Size == 1)
		{
			TX_STA_CNT1_STRUC		StaTx1;
			TX_STA_CNT0_STRUC		TxStaCnt0;

			/* Update statistic counter */
			NicGetTxRawCounters(pAd, &TxStaCnt0, &StaTx1);

			TxRetransmit = StaTx1.field.TxRetransmit;
			TxSuccess = StaTx1.field.TxSuccess;
			TxFailCount = TxStaCnt0.field.TxFailCount;
			TxTotalCnt = TxRetransmit + TxSuccess + TxFailCount;

			if (TxTotalCnt)
				TxErrorRatio = ((TxRetransmit + TxFailCount) * 100) / TxTotalCnt;
		}
		else
		{
			TxRetransmit = pEntry->OneSecTxRetryOkCount;
			TxSuccess = pEntry->OneSecTxNoRetryOkCount;
			TxFailCount = pEntry->OneSecTxFailCount;
			TxTotalCnt = TxRetransmit + TxSuccess + TxFailCount;

			if (TxTotalCnt)
				TxErrorRatio = ((TxRetransmit + TxFailCount) * 100) / TxTotalCnt;

#ifdef FIFO_EXT_SUPPORT
			if (pAd->chipCap.FlgHwFifoExtCap)
			{
				if (pEntry->Aid >= 1 && pEntry->Aid <= 8)
				{
					ULONG 	HwTxCnt, HwErrRatio;

					NicGetMacFifoTxCnt(pAd, pEntry);
					HwTxCnt = pEntry->fifoTxSucCnt + pEntry->fifoTxRtyCnt;
					if (HwTxCnt)
						HwErrRatio = (pEntry->fifoTxRtyCnt * 100) / HwTxCnt;
					else
						HwErrRatio = 0;

					DBGPRINT(RT_DEBUG_TRACE | DBG_FUNC_RA,
							("%s():Aid:%d, MCS:%d, CuTxRaIdx=%d,TxErrRatio(Hw:%d-%d%%, Sw:%d-%d%%)\n", 
							__FUNCTION__, pEntry->Aid, pEntry->HTPhyMode.field.MCS,
							pEntry->CurrTxRateIndex,
							HwTxCnt, HwErrRatio, TxTotalCnt, TxErrorRatio));

					TxSuccess = pEntry->fifoTxSucCnt;
					TxRetransmit = pEntry->fifoTxRtyCnt;
					TxTotalCnt = HwTxCnt;
					TxErrorRatio = HwErrRatio;
				}
			}
#endif /* FIFO_EXT_SUPPORT */
		}

		/* Save LastTxOkCount, LastTxPER and last MCS action for APQuickResponeForRateUpExec */
		pEntry->LastTxOkCount = TxSuccess;
		pEntry->LastTxPER = (TxTotalCnt == 0 ? 0 : (UCHAR)TxErrorRatio);
		pEntry->LastTimeTxRateChangeAction = pEntry->LastSecTxRateChangeAction;

		/* different calculation in APQuickResponeForRateUpExec() */
		/* Rssi = RTMPMaxRssi(pAd, (CHAR)pEntry->RssiSample.AvgRssi0, (CHAR)pEntry->RssiSample.AvgRssi1, (CHAR)pEntry->RssiSample.AvgRssi2); */
		Rssi = RTMPAvgRssi(pAd, &pEntry->RssiSample);

		CurrRateIdx = UpRateIdx = DownRateIdx = pEntry->CurrTxRateIndex;

		/* decide the next upgrade rate and downgrade rate, if any */
		pCurrTxRate = PTX_RATE_SWITCH_ENTRY(pTable, CurrRateIdx);

		/* decide the next upgrade rate and downgrade rate, if any*/
		if ((CurrRateIdx > 0) && (CurrRateIdx < (TableSize - 1)))
		{
			TmpIdx = CurrRateIdx + 1;
			while(TmpIdx < TableSize)
			{
				pTmpTxRate = PTX_RATE_SWITCH_ENTRY(pTable, TmpIdx);
				if (pTmpTxRate->Mode <= MODE_CCK)
				{
					if (pEntry->SupportCCKMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				else if (pTmpTxRate->Mode <= MODE_OFDM)
				{
					if (pEntry->SupportOFDMMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				else
				{
					if (pEntry->SupportHTMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				TmpIdx++;
			}

			TmpIdx = CurrRateIdx - 1;
			while(TmpIdx >= 0)
			{
				pTmpTxRate = PTX_RATE_SWITCH_ENTRY(pTable, TmpIdx);

				if (pTmpTxRate->Mode <= MODE_CCK)
				{
					if (pEntry->SupportCCKMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				else if (pTmpTxRate->Mode <= MODE_OFDM)
				{
					if (pEntry->SupportOFDMMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				else
				{
					if (pEntry->SupportHTMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				TmpIdx--;
			}
		}
		else if (CurrRateIdx == 0)
		{
			TmpIdx = CurrRateIdx + 1;
			while(TmpIdx < TableSize)
			{
				pTmpTxRate = PTX_RATE_SWITCH_ENTRY(pTable, TmpIdx);
				if (pTmpTxRate->Mode <= MODE_CCK)
				{
					if (pEntry->SupportCCKMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				else if (pTmpTxRate->Mode <= MODE_OFDM)
				{
					if (pEntry->SupportOFDMMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				else
				{
					if (pEntry->SupportHTMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				TmpIdx++;
			}

			DownRateIdx = CurrRateIdx;
		}
		else if (CurrRateIdx == (TableSize - 1))
		{
			UpRateIdx = CurrRateIdx;

			TmpIdx = CurrRateIdx - 1;
			while(TmpIdx >= 0)
			{
				pTmpTxRate = PTX_RATE_SWITCH_ENTRY(pTable, TmpIdx);

				if (pTmpTxRate->Mode <= MODE_CCK)
				{
					if (pEntry->SupportCCKMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				else if (pTmpTxRate->Mode <= MODE_OFDM)
				{
					if (pEntry->SupportOFDMMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				else
				{
					if (pEntry->SupportHTMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				TmpIdx--;
			}
		}

#ifdef DOT11_N_SUPPORT
		/*
			when Rssi > -65, there is a lot of interference usually. therefore, the algorithm
			tends to choose the mcs lower than the optimal one.
			by increasing the thresholds, the chosen mcs will be closer to the optimal mcs
		*/
		//if ((Rssi > -65) && (pCurrTxRate->Mode >= MODE_HTMIX))
		if (Rssi > -65)
		{
			//	TrainUp		= (pCurrTxRate->TrainUp + (pCurrTxRate->TrainUp >> 1));
		//	TrainDown	= (pCurrTxRate->TrainDown + (pCurrTxRate->TrainDown >> 1));
     			 TrainUp = 2 * (pCurrTxRate->TrainUp);
      			TrainDown = 2 * (pCurrTxRate->TrainDown);
		}
		else
#endif /* DOT11_N_SUPPORT */
		{
			TrainUp		= pCurrTxRate->TrainUp;
			TrainDown	= pCurrTxRate->TrainDown;
		}



#ifdef DBG_CTRL_SUPPORT
		/* Debug option: Concise RA log */
		if (pAd->CommonCfg.DebugFlags & DBF_SHOW_RA_LOG)
			MlmeRALog(pAd, pEntry, RAL_OLD_DRS, TxErrorRatio, TxTotalCnt);
#endif /* DBG_CTRL_SUPPORT */

#if defined (RT2883) || defined (RT3883)
		/* Debug Option: Force the MCS. FixedRate is index into current rate table. */
		if ((pAd->CommonCfg.FixedRate != -1) && (pAd->CommonCfg.FixedRate < RATE_TABLE_SIZE(pTable)))
		{
			pEntry->CurrTxRateIndex = pAd->CommonCfg.FixedRate;
			MlmeNewTxRate(pAd, pEntry);

			/* reset all OneSecTx counters */
			RESET_ONE_SEC_TX_CNT(pEntry);

#ifdef TXBF_SUPPORT
			if (pAd->chipCap.FlgHwTxBfCap)
			eTxBFProbing(pAd, pEntry);
#endif /* TXBF_SUPPORT */

			continue;
		}
#endif

		/* Check for low traffic case */
        if (TxTotalCnt <= 15)
        {
			UCHAR	TxRateIdx;
			CHAR	mcs[24];

			/* Check existence and get the index of each MCS */
			MlmeGetSupportedMcs(pAd, pTable, mcs);

			/* Select the Tx rate based on the RSSI */
			TxRateIdx = MlmeSelectTxRate(pAd, pEntry, mcs, Rssi, 0);


			if (TxRateIdx != pEntry->CurrTxRateIndex
#ifdef TXBF_SUPPORT
				|| pEntry->phyETxBf || pEntry->phyITxBf
#endif /* TXBF_SUPPORT */
				)
			{
				pEntry->CurrTxRateIndex = TxRateIdx;
#ifdef TXBF_SUPPORT
				pEntry->phyETxBf = pEntry->phyITxBf = FALSE;
#endif /* TXBF_SUPPORT */
				MlmeNewTxRate(pAd, pEntry);
				if (!pEntry->fLastSecAccordingRSSI)
					DBGPRINT(RT_DEBUG_INFO,("DRS: TxTotalCnt <= 15, switch MCS according to RSSI (%d)\n", Rssi));
			}

			MlmeClearAllTxQuality(pEntry);
			pEntry->fLastSecAccordingRSSI = TRUE;

			/* reset all OneSecTx counters */
			RESET_ONE_SEC_TX_CNT(pEntry);


#ifdef TXBF_SUPPORT
#ifdef DBG_CTRL_SUPPORT
			/* In Unaware mode always try to send sounding */
			if (pAd->CommonCfg.DebugFlags & DBF_NO_BF_AWARE_RA)
				eTxBFProbing(pAd, pEntry);
#endif /* DBG_CTRL_SUPPORT */
#endif /* TXBF_SUPPORT */
			continue;
        }

		if (pEntry->fLastSecAccordingRSSI == TRUE)
		{
			pEntry->fLastSecAccordingRSSI = FALSE;
			pEntry->LastSecTxRateChangeAction = RATE_NO_CHANGE;
			/* reset all OneSecTx counters */
			RESET_ONE_SEC_TX_CNT(pEntry);

#ifdef TXBF_SUPPORT
			if (pAd->chipCap.FlgHwTxBfCap)
			eTxBFProbing(pAd, pEntry);
#endif /* TXBF_SUPPORT */

			continue;
		}

		pEntry->PER[CurrRateIdx] = (UCHAR)TxErrorRatio;

		/* Select rate based on PER */
		MlmeOldRateAdapt(pAd, pEntry, CurrRateIdx, UpRateIdx, DownRateIdx, TrainUp, TrainDown, TxErrorRatio);

#ifdef DOT11N_SS3_SUPPORT
		/* Turn off RDG when 3s and rx count > tx count*5 */
		MlmeCheckRDG(pAd, pEntry);
#endif /* DOT11N_SS3_SUPPORT */

		/* reset all OneSecTx counters */
		RESET_ONE_SEC_TX_CNT(pEntry);

#ifdef TXBF_SUPPORT
		if (pAd->chipCap.FlgHwTxBfCap)
		eTxBFProbing(pAd, pEntry);
#endif /* TXBF_SUPPORT */

    }
}


/*
    ========================================================================
    Routine Description:
        AP side, Auto TxRate faster train up timer call back function.
        
    Arguments:
        SystemSpecific1         - Not used.
        FunctionContext         - Pointer to our Adapter context.
        SystemSpecific2         - Not used.
        SystemSpecific3         - Not used.
        
    Return Value:
        None
        
    ========================================================================
*/
VOID APQuickResponeForRateUpExec(
    IN PVOID SystemSpecific1, 
    IN PVOID FunctionContext, 
    IN PVOID SystemSpecific2, 
    IN PVOID SystemSpecific3)
{
	PRTMP_ADAPTER			pAd = (PRTMP_ADAPTER)FunctionContext;
	ULONG					i;
	PUCHAR					pTable;
	UCHAR					TableSize = 0;
	UCHAR					CurrRateIdx;
	ULONG					AccuTxTotalCnt, TxTotalCnt, TxCnt;
	ULONG					TxErrorRatio = 0;
	MAC_TABLE_ENTRY			*pEntry;
	PRTMP_TX_RATE_SWITCH	pCurrTxRate;
	UCHAR					InitTxRateIdx, TrainUp, TrainDown;
	CHAR					Rssi, ratio;
	ULONG					TxSuccess, TxRetransmit, TxFailCount;
#ifdef TXBF_SUPPORT
	BOOLEAN					CurrPhyETxBf, CurrPhyITxBf;
#endif /* TXBF_SUPPORT */
	UINT32					MaxWcidNum = MAX_LEN_OF_MAC_TABLE;

	pAd->ApCfg.ApQuickResponeForRateUpTimerRunning = FALSE;

#ifdef MAC_REPEATER_SUPPORT
	if (pAd->ApCfg.bMACRepeaterEn)
		MaxWcidNum = MAX_MAC_TABLE_SIZE_WITH_REPEATER;
#endif /* MAC_REPEATER_SUPPORT */

    /* walk through MAC table, see if need to change AP's TX rate toward each entry */
   	for (i = 1; i < MaxWcidNum; i++) 
	{
       	 pEntry = &pAd->MacTab.Content[i];

		if (IS_ENTRY_NONE(pEntry))
			continue;

		if (IS_ENTRY_CLIENT(pEntry) && (pEntry->Sst != SST_ASSOC))
			continue;

#ifdef APCLI_SUPPORT
		if (IS_ENTRY_APCLI(pEntry) && (pEntry->Sst != SST_ASSOC))
			continue;
#endif /* APCLI_SUPPORT */

#ifdef WDS_SUPPORT
		if (IS_ENTRY_WDS(pEntry) && !WDS_IF_UP_CHECK(pAd, pEntry->MatchWDSTabIdx))
			continue;
#endif /* WDS_SUPPORT */



		/* Do nothing if this entry didn't change */
		if (pEntry->LastSecTxRateChangeAction == RATE_NO_CHANGE
#ifdef DBG_CTRL_SUPPORT
			&& (pAd->CommonCfg.DebugFlags & DBF_FORCE_QUICK_DRS)==0
#endif /* DBG_CTRL_SUPPORT */
		)
			continue;

		MlmeSelectTxRateTable(pAd, pEntry, &pTable, &TableSize, &InitTxRateIdx);
		pEntry->pTable = pTable;

#ifdef NEW_RATE_ADAPT_SUPPORT
		if (ADAPT_RATE_TABLE(pTable))
		{
			APQuickResponeForRateUpExecAdapt(pAd, i);
			continue;
		}
#endif /* NEW_RATE_ADAPT_SUPPORT */

    	/*Rssi = RTMPMaxRssi(pAd, (CHAR)pEntry->RssiSample.AvgRssi0, (CHAR)pEntry->RssiSample.AvgRssi1, (CHAR)pEntry->RssiSample.AvgRssi2); */
		Rssi = RTMPAvgRssi(pAd, &pEntry->RssiSample);


		if (pAd->MacTab.Size == 1)
		{
            TX_STA_CNT1_STRUC		StaTx1;
			TX_STA_CNT0_STRUC		TxStaCnt0;

       		/* Update statistic counter */
			NicGetTxRawCounters(pAd, &TxStaCnt0, &StaTx1);

			TxRetransmit = StaTx1.field.TxRetransmit;
			TxSuccess = StaTx1.field.TxSuccess;
			TxFailCount = TxStaCnt0.field.TxFailCount;
			TxTotalCnt = TxRetransmit + TxSuccess + TxFailCount;

			AccuTxTotalCnt = pAd->RalinkCounters.OneSecTxNoRetryOkCount + 
					 pAd->RalinkCounters.OneSecTxRetryOkCount + 
					 pAd->RalinkCounters.OneSecTxFailCount;

			if (TxTotalCnt)
				TxErrorRatio = ((TxRetransmit + TxFailCount) * 100) / TxTotalCnt;

			if (pAd->Antenna.field.TxPath > 1)
				Rssi = (pEntry->RssiSample.AvgRssi0 + pEntry->RssiSample.AvgRssi1) >> 1;
			else
				Rssi = pEntry->RssiSample.AvgRssi0;

			TxCnt = AccuTxTotalCnt;
		}
		else
		{
			TxRetransmit = pEntry->OneSecTxRetryOkCount;
			TxSuccess = pEntry->OneSecTxNoRetryOkCount;
			TxFailCount = pEntry->OneSecTxFailCount;
			TxTotalCnt = TxRetransmit + TxSuccess + TxFailCount;

			TxCnt = TxTotalCnt;

			if (TxTotalCnt)
				TxErrorRatio = ((TxRetransmit + TxFailCount) * 100) / TxTotalCnt;

#ifdef FIFO_EXT_SUPPORT
			if (pAd->chipCap.FlgHwFifoExtCap)
			{
				if ((pEntry->Aid >= 1) && (pEntry->Aid <= 8))
				{
					ULONG	HwTxCnt, HwErrRatio;

					NicGetMacFifoTxCnt(pAd, pEntry);
					HwTxCnt = pEntry->fifoTxSucCnt + pEntry->fifoTxRtyCnt;
					if (HwTxCnt)
						HwErrRatio = (pEntry->fifoTxRtyCnt * 100) / HwTxCnt;
					else
						HwErrRatio = 0;

					DBGPRINT(RT_DEBUG_INFO | DBG_FUNC_RA,("%s():Aid:%d, MCS:%d, TxErrRation(Hw:0x%lx-0x%lx, Sw:0x%lx-%lx)\n", 
							__FUNCTION__, pEntry->Aid, pEntry->HTPhyMode.field.MCS, 
							HwTxCnt, HwErrRatio, TxTotalCnt, TxErrorRatio));

					TxSuccess = pEntry->fifoTxSucCnt;
					TxRetransmit = pEntry->fifoTxRtyCnt;
					TxErrorRatio = HwErrRatio;
					TxTotalCnt = HwTxCnt;
					TxCnt = HwTxCnt;
				}
			}
#endif /* FIFO_EXT_SUPPORT */
		}

		CurrRateIdx = pEntry->CurrTxRateIndex;
#ifdef TXBF_SUPPORT
		CurrPhyETxBf = pEntry->phyETxBf;
		CurrPhyITxBf = pEntry->phyITxBf;
#endif /* TXBF_SUPPORT */
		pCurrTxRate = PTX_RATE_SWITCH_ENTRY(pTable, CurrRateIdx);

#ifdef DOT11_N_SUPPORT
		if ((Rssi > -65) && (pCurrTxRate->Mode >= MODE_HTMIX))
		{
			TrainUp		= (pCurrTxRate->TrainUp + (pCurrTxRate->TrainUp >> 1));
			TrainDown	= (pCurrTxRate->TrainDown + (pCurrTxRate->TrainDown >> 1));
		}
		else
#endif /* DOT11_N_SUPPORT */
		{
			TrainUp		= pCurrTxRate->TrainUp;
			TrainDown	= pCurrTxRate->TrainDown;
		}

			
#ifdef DBG_CTRL_SUPPORT
		/* Debug option: Concise RA log */
		if (pAd->CommonCfg.DebugFlags & DBF_SHOW_RA_LOG)
			MlmeRALog(pAd, pEntry, RAL_QUICK_DRS, TxErrorRatio, TxTotalCnt);
#endif /* DBG_CTRL_SUPPORT */

        if (TxCnt <= 15 && pEntry->HTPhyMode.field.MCS > 1)
        {
			MlmeClearAllTxQuality(pEntry);

			/* Set current up MCS at the worst quality */
			if (pEntry->LastSecTxRateChangeAction == RATE_UP)
			{
				MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND);
			}

			/* Go back to the original rate */
			MlmeRestoreLastRate(pEntry);

			MlmeNewTxRate(pAd, pEntry);


		// TODO: should we reset all OneSecTx counters?
		/* RESET_ONE_SEC_TX_CNT(pEntry); */

			continue;
        }

		pEntry->PER[CurrRateIdx] = (UCHAR)TxErrorRatio;

       /* Compare throughput */
		do
		{
			ULONG OneSecTxNoRetryOKRationCount;

			/* Compare throughput. LastTxCount is based on a 500 msec or 500-DEF_QUICK_RA_TIME_INTERVAL interval. */
			if ((pEntry->LastTimeTxRateChangeAction == RATE_NO_CHANGE)
#ifdef DBG_CTRL_SUPPORT
				&& (pAd->CommonCfg.DebugFlags & DBF_FORCE_QUICK_DRS)==0
#endif /* DBG_CTRL_SUPPORT */
			)
				ratio = RA_INTERVAL/DEF_QUICK_RA_TIME_INTERVAL;
			else
				ratio = (RA_INTERVAL-DEF_QUICK_RA_TIME_INTERVAL)/DEF_QUICK_RA_TIME_INTERVAL;

			/* downgrade TX quality if PER >= Rate-Down threshold */
			if (TxErrorRatio >= TrainDown)
			{
				MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND);
			}

			if (pAd->MacTab.Size == 1)
			{
				OneSecTxNoRetryOKRationCount = (TxSuccess * ratio);
			}
			else
			{
				OneSecTxNoRetryOKRationCount = pEntry->OneSecTxNoRetryOkCount * ratio + (pEntry->OneSecTxNoRetryOkCount >> 1);
			}

			/* perform DRS - consider TxRate Down first, then rate up. */
			if (pEntry->LastSecTxRateChangeAction == RATE_UP)
			{
// TODO: gaa - use different criterion for train up in Old RA?
				/*if ((pEntry->LastTxOkCount + 2) >= OneSecTxNoRetryOKRationCount) */
				if (TxErrorRatio >= TrainDown)
				{
#ifdef TXBF_SUPPORT
					/* If PER>50% or TP<lastTP/2 then double the TxQuality delay */
					if ((TxErrorRatio > 50) || (OneSecTxNoRetryOKRationCount < pEntry->LastTxOkCount/2))
						MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND*2);
					else
#endif /* TXBF_SUPPORT */
						MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND);

					MlmeRestoreLastRate(pEntry);
				}
				else
				{
				}
			}
			else if (pEntry->LastSecTxRateChangeAction == RATE_DOWN)
			{
				/* if ((TxErrorRatio >= 50) || (TxErrorRatio >= TrainDown)) */
				if ((TxErrorRatio >= 50) && (TxErrorRatio >= TrainDown))
				{
				}
				else if ((pEntry->LastTxOkCount + 2) >= OneSecTxNoRetryOKRationCount)
				{
					MlmeRestoreLastRate(pEntry);
				}
				else
				{
					DBGPRINT(RT_DEBUG_INFO | DBG_FUNC_RA,("QuickDRS: (Down) keep rate-down (L:%ld, C:%ld)\n", pEntry->LastTxOkCount, OneSecTxNoRetryOKRationCount));
				}
			}
		}while (FALSE);

#ifdef TXBF_SUPPORT
		/* Remember last good non-BF rate */
		if (!pEntry->phyETxBf && !pEntry->phyITxBf)
			pEntry->lastNonBfRate = pEntry->CurrTxRateIndex;
#endif /* TXBF_SUPPORT */

		/* If rate changed then update the history and set the new tx rate */
		if ((pEntry->CurrTxRateIndex != CurrRateIdx)
#ifdef TXBF_SUPPORT
			|| (pEntry->phyETxBf!=CurrPhyETxBf) || (pEntry->phyITxBf!=CurrPhyITxBf)
#endif /* TXBF_SUPPORT */
		)
		{
			/* if rate-up happen, clear all bad history of all TX rates */
			if (pEntry->LastSecTxRateChangeAction == RATE_DOWN)
			{
				pEntry->TxRateUpPenalty = 0;
				if (pEntry->CurrTxRateIndex != CurrRateIdx)
					MlmeClearTxQuality(pEntry);
			}
			/* if rate-down happen, only clear DownRate's bad history */
			else if (pEntry->LastSecTxRateChangeAction == RATE_UP)
			{
				pEntry->TxRateUpPenalty = 0;           /* no penalty */
				MlmeSetTxQuality(pEntry, pEntry->CurrTxRateIndex, 0);
				pEntry->PER[pEntry->CurrTxRateIndex] = 0;
			}

			MlmeNewTxRate(pAd, pEntry);
		}

		// TODO: should we reset all OneSecTx counters?
		/* RESET_ONE_SEC_TX_CNT(pEntry); */
    }
}
#endif /* CONFIG_AP_SUPPORT */


#ifdef CONFIG_STA_SUPPORT
/*
	==========================================================================
	Description:
		This routine calculates the acumulated TxPER of eaxh TxRate. And
		according to the calculation result, change CommonCfg.TxRate which
		is the stable TX Rate we expect the Radio situation could sustained.

		CommonCfg.TxRate will change dynamically within {RATE_1/RATE_6, MaxTxRate}
	Output:
		CommonCfg.TxRate -

	IRQL = DISPATCH_LEVEL

	NOTE:
		call this routine every second
	==========================================================================
 */
VOID MlmeDynamicTxRateSwitching(
	IN PRTMP_ADAPTER pAd)
{
	PUCHAR					pTable;
	UCHAR					TableSize = 0;
	UCHAR					UpRateIdx = 0, DownRateIdx = 0, CurrRateIdx;
	ULONG					i, TxTotalCnt;
	ULONG					TxErrorRatio = 0;
	MAC_TABLE_ENTRY			*pEntry;
	PRTMP_TX_RATE_SWITCH	pCurrTxRate, pTmpTxRate = NULL;
	UCHAR					InitTxRateIdx, TrainUp, TrainDown;
	TX_STA_CNT1_STRUC		StaTx1;
	TX_STA_CNT0_STRUC		TxStaCnt0;
	CHAR					Rssi, TmpIdx = 0;
	ULONG					TxRetransmit = 0, TxSuccess = 0, TxFailCount = 0;
	RSSI_SAMPLE				*pRssi = &pAd->StaCfg.RssiSample;
#ifdef AGS_SUPPORT
	AGS_STATISTICS_INFO		AGSStatisticsInfo = {0};
#endif /* AGS_SUPPORT */

#ifdef RALINK_ATE
	if (ATE_ON(pAd))
	{
		return;
	}
#endif /* RALINK_ATE */

	/* Update statistic counter */
	NicGetTxRawCounters(pAd, &TxStaCnt0, &StaTx1);

	TxRetransmit = StaTx1.field.TxRetransmit;
	TxSuccess = StaTx1.field.TxSuccess;
	TxFailCount = TxStaCnt0.field.TxFailCount;
	TxTotalCnt = TxRetransmit + TxSuccess + TxFailCount;

	/* walk through MAC table, see if need to change AP's TX rate toward each entry */
   	for (i = 1; i < MAX_LEN_OF_MAC_TABLE; i++)
	{
		pEntry = &pAd->MacTab.Content[i];

		if (IS_ENTRY_NONE(pEntry))
			continue;

		/* check if this entry need to switch rate automatically */
		if (RTMPCheckEntryEnableAutoRateSwitch(pAd, pEntry) == FALSE)
			continue;

		MlmeSelectTxRateTable(pAd, pEntry, &pTable, &TableSize, &InitTxRateIdx);
		pEntry->pTable = pTable;

#ifdef NEW_RATE_ADAPT_SUPPORT
		if (ADAPT_RATE_TABLE(pTable))
		{
			MlmeDynamicTxRateSwitchingAdapt(pAd, i, TxSuccess, TxRetransmit, TxFailCount);
			continue;
		}
#endif /* NEW_RATE_ADAPT_SUPPORT */

		if ((pAd->MacTab.Size == 1) || IS_ENTRY_DLS(pEntry))
		{
			/* Rssi = RTMPMaxRssi(pAd, pRssi->AvgRssi0, pRssi->AvgRssi1, pRssi->AvgRssi2); */
			Rssi = RTMPAvgRssi(pAd, pRssi);

			if (TxTotalCnt)
				TxErrorRatio = ((TxRetransmit + TxFailCount) * 100) / TxTotalCnt;


			DBGPRINT_RAW(RT_DEBUG_INFO,("DRS:Aid=%d, TxSuccess=%ld, TxRetransmit=%ld, TxFailCount=%ld \n",
					pEntry->Aid, TxSuccess, TxRetransmit, TxFailCount));

#ifdef AGS_SUPPORT
			if (SUPPORT_AGS(pAd))
			{
				
				/* Gather the statistics information*/
				
				AGSStatisticsInfo.RSSI = Rssi;
				AGSStatisticsInfo.TxErrorRatio = TxErrorRatio;
				AGSStatisticsInfo.AccuTxTotalCnt = TxTotalCnt;
				AGSStatisticsInfo.TxTotalCnt = TxTotalCnt;
				AGSStatisticsInfo.TxSuccess = TxSuccess;
				AGSStatisticsInfo.TxRetransmit = TxRetransmit;
				AGSStatisticsInfo.TxFailCount = TxFailCount;
			}
#endif /* AGS_SUPPORT */
		}
		else
		{
			if (INFRA_ON(pAd) && (i == 1))
				Rssi = RTMPAvgRssi(pAd, pRssi);
			else
				Rssi = RTMPAvgRssi(pAd, &pEntry->RssiSample);
			TxSuccess = pEntry->OneSecTxNoRetryOkCount;

			TxTotalCnt = pEntry->OneSecTxNoRetryOkCount +
				 pEntry->OneSecTxRetryOkCount +
				 pEntry->OneSecTxFailCount;

			if (TxTotalCnt)
				TxErrorRatio = ((pEntry->OneSecTxRetryOkCount + pEntry->OneSecTxFailCount) * 100) / TxTotalCnt;

			DBGPRINT_RAW(RT_DEBUG_INFO,("DRS:Aid=%d, OneSecTxNoRetry=%d, OneSecTxRetry=%d, OneSecTxFail=%d\n",
				pEntry->Aid,
				pEntry->OneSecTxNoRetryOkCount,
				pEntry->OneSecTxRetryOkCount,
				pEntry->OneSecTxFailCount));

#ifdef FIFO_EXT_SUPPORT
			if (pAd->chipCap.FlgHwFifoExtCap)
			{
				if (pEntry->Aid >= 1 && pEntry->Aid <= 8)
				{
					ULONG 	HwTxCnt, HwErrRatio;

					NicGetMacFifoTxCnt(pAd, pEntry);
					HwTxCnt = pEntry->fifoTxSucCnt + pEntry->fifoTxRtyCnt;
					if (HwTxCnt)
						HwErrRatio = (pEntry->fifoTxRtyCnt * 100) / HwTxCnt;
					else
						HwErrRatio = 0;

					DBGPRINT(RT_DEBUG_INFO | DBG_FUNC_RA,
							("%s():Aid:%d, MCS:%d, CuTxRaIdx=%d,TxErrRatio(Hw:%d-%d%%, Sw:%d-%d%%)\n", 
							__FUNCTION__, pEntry->Aid, pEntry->HTPhyMode.field.MCS,
							pEntry->CurrTxRateIndex,
							HwTxCnt, HwErrRatio, TxTotalCnt, TxErrorRatio));

					TxSuccess = pEntry->fifoTxSucCnt;
					TxRetransmit = pEntry->fifoTxRtyCnt;
					TxTotalCnt = HwTxCnt;
					TxErrorRatio = HwErrRatio;
				}
			}
#endif /* FIFO_EXT_SUPPORT */


#ifdef AGS_SUPPORT
			if (SUPPORT_AGS(pAd))
			{
				
				/* Gather the statistics information*/
				
				AGSStatisticsInfo.RSSI = Rssi;
				AGSStatisticsInfo.TxErrorRatio = TxErrorRatio;
				AGSStatisticsInfo.AccuTxTotalCnt = TxTotalCnt;
				AGSStatisticsInfo.TxTotalCnt = TxTotalCnt;
				AGSStatisticsInfo.TxSuccess = pEntry->OneSecTxNoRetryOkCount;
				AGSStatisticsInfo.TxRetransmit = pEntry->OneSecTxRetryOkCount;
				AGSStatisticsInfo.TxFailCount = pEntry->OneSecTxFailCount;
			}
#endif /* AGS_SUPPORT */
		}

		if (TxTotalCnt)
		{
			if (TxErrorRatio == 100)
			{
				TX_RTY_CFG_STRUC	TxRtyCfg,TxRtyCfgtmp;
				ULONG	Index;
				UINT32	MACValue;

				RTMP_IO_READ32(pAd, TX_RTY_CFG, &TxRtyCfg.word);
				TxRtyCfgtmp.word = TxRtyCfg.word;
				TxRtyCfg.field.LongRtyLimit = 0x0;
				TxRtyCfg.field.ShortRtyLimit = 0x0;
				RTMP_IO_WRITE32(pAd, TX_RTY_CFG, TxRtyCfg.word);

				RTMPusecDelay(1);

				Index = 0;
				MACValue = 0;
				do
				{
					RTMP_IO_READ32(pAd, TXRXQ_PCNT, &MACValue);
					if ((MACValue & 0xffffff) == 0)
						break;
					Index++;
					RTMPusecDelay(1000);
				}while((Index < 330)&&(!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS)));

				RTMP_IO_READ32(pAd, TX_RTY_CFG, &TxRtyCfg.word);
				TxRtyCfg.field.LongRtyLimit = TxRtyCfgtmp.field.LongRtyLimit;
				TxRtyCfg.field.ShortRtyLimit = TxRtyCfgtmp.field.ShortRtyLimit;
				RTMP_IO_WRITE32(pAd, TX_RTY_CFG, TxRtyCfg.word);
			}

		}

		CurrRateIdx = pEntry->CurrTxRateIndex;

#ifdef AGS_SUPPORT
		if (AGS_IS_USING(pAd, pTable))
		{
/*
			*ppTable = AGS3x3HTRateTable;
			*pTableSize = AGS3x3HTRateTable[0];
			*pInitTxRateIdx = AGS3x3HTRateTable[1];
*/
			
			/* The dynamic Tx rate switching for AGS (Adaptive Group Switching)*/
			
			MlmeDynamicTxRateSwitchingAGS(pAd, pEntry, pTable, TableSize, &AGSStatisticsInfo, InitTxRateIdx);

			continue; /* Skip the remaining procedure of the old Tx rate switching*/
		}
#endif /* AGS_SUPPORT */

		if (CurrRateIdx >= TableSize)
		{
			CurrRateIdx = TableSize - 1;
		}

		UpRateIdx = DownRateIdx = CurrRateIdx;

		/* Save LastTxOkCount, LastTxPER and last MCS action for StaQuickResponeForRateUpExec */
		pEntry->LastTxOkCount = TxSuccess;
		pEntry->LastTxPER = (TxTotalCnt == 0 ? 0 : (UCHAR)TxErrorRatio);
		pEntry->LastTimeTxRateChangeAction = pEntry->LastSecTxRateChangeAction;

		/*
			When switch from Fixed rate -> auto rate, the REAL TX rate might be different from pEntry->TxRateIndex.
			So need to sync here.
		*/
		pCurrTxRate = PTX_RATE_SWITCH_ENTRY(pTable, CurrRateIdx);
		if ((pEntry->HTPhyMode.field.MCS != pCurrTxRate->CurrMCS)
			/*&& (pAd->StaCfg.bAutoTxRateSwitch == TRUE) */
			)
		{
			/*
				Need to sync Real Tx rate and our record.
				Then return for next DRS.
			*/
			pEntry->CurrTxRateIndex = InitTxRateIdx;
#ifdef TXBF_SUPPORT
			pEntry->phyETxBf = pEntry->phyITxBf = FALSE;
#endif /* TXBF_SUPPORT */
			MlmeNewTxRate(pAd, pEntry);

			/* reset all OneSecTx counters */
			RESET_ONE_SEC_TX_CNT(pEntry);
			continue;
		}

		/* decide the next upgrade rate and downgrade rate, if any*/
		if ((CurrRateIdx > 0) && (CurrRateIdx < (TableSize - 1)))
		{
			TmpIdx = CurrRateIdx + 1;
			while(TmpIdx < TableSize)
			{
				pTmpTxRate = PTX_RATE_SWITCH_ENTRY(pTable, TmpIdx);
				if (pTmpTxRate->Mode <= MODE_CCK)
				{
					if (pEntry->SupportCCKMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				else if (pTmpTxRate->Mode <= MODE_OFDM)
				{
					if (pEntry->SupportOFDMMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				else
				{
					if (pEntry->SupportHTMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				TmpIdx++;
			}

			TmpIdx = CurrRateIdx - 1;
			while(TmpIdx >= 0)
			{
				pTmpTxRate = PTX_RATE_SWITCH_ENTRY(pTable, TmpIdx);

				if (pTmpTxRate->Mode <= MODE_CCK)
				{
					if (pEntry->SupportCCKMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				else if (pTmpTxRate->Mode <= MODE_OFDM)
				{
					if (pEntry->SupportOFDMMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				else
				{
					if (pEntry->SupportHTMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				TmpIdx--;
			}
		}
		else if (CurrRateIdx == 0)
		{
			TmpIdx = CurrRateIdx + 1;
			while(TmpIdx < TableSize)
			{
				pTmpTxRate = PTX_RATE_SWITCH_ENTRY(pTable, TmpIdx);
				if (pTmpTxRate->Mode <= MODE_CCK)
				{
					if (pEntry->SupportCCKMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				else if (pTmpTxRate->Mode <= MODE_OFDM)
				{
					if (pEntry->SupportOFDMMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				else
				{
					if (pEntry->SupportHTMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						UpRateIdx = TmpIdx;
						break;
					}
				}
				TmpIdx++;
			}

			DownRateIdx = CurrRateIdx;
		}
		else if (CurrRateIdx == (TableSize - 1))
		{
			UpRateIdx = CurrRateIdx;

			TmpIdx = CurrRateIdx - 1;
			while(TmpIdx >= 0)
			{
				pTmpTxRate = PTX_RATE_SWITCH_ENTRY(pTable, TmpIdx);

				if (pTmpTxRate->Mode <= MODE_CCK)
				{
					if (pEntry->SupportCCKMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				else if (pTmpTxRate->Mode <= MODE_OFDM)
				{
					if (pEntry->SupportOFDMMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				else
				{
					if (pEntry->SupportHTMCS[pTmpTxRate->CurrMCS] == TRUE)
					{
						DownRateIdx = TmpIdx;
						break;
					}
				}
				TmpIdx--;
			}
		}

		pCurrTxRate = PTX_RATE_SWITCH_ENTRY(pTable, CurrRateIdx);

#ifdef DOT11_N_SUPPORT

		/*
			when Rssi > -65, there is a lot of interference usually. therefore, the 
			algorithm tends to choose the mcs lower than the optimal one.
			by increasing the thresholds, the chosen mcs will be closer to the optimal mcs
		*/
		if ((Rssi > -65) && (pCurrTxRate->Mode >= MODE_HTMIX))
		{
			TrainUp		= (pCurrTxRate->TrainUp + (pCurrTxRate->TrainUp >> 1));
			TrainDown	= (pCurrTxRate->TrainDown + (pCurrTxRate->TrainDown >> 1));
		}
		else
#endif /* DOT11_N_SUPPORT */
		{
			TrainUp		= pCurrTxRate->TrainUp;
			TrainDown	= pCurrTxRate->TrainDown;
		}


#ifdef DBG_CTRL_SUPPORT
		/* Debug option: Concise RA log */
		if (pAd->CommonCfg.DebugFlags & DBF_SHOW_RA_LOG)
			MlmeRALog(pAd, pEntry, RAL_OLD_DRS, TxErrorRatio, TxTotalCnt);
#endif /* DBG_CTRL_SUPPORT */

#if defined (RT2883) || defined (RT3883)
		if (IS_RT2883(pAd) || IS_RT3883(pAd))
		{
			/* Debug Option: Force the MCS. FixedRate is index into current rate table. */
			if ((pAd->CommonCfg.FixedRate != -1) && (pAd->CommonCfg.FixedRate < RATE_TABLE_SIZE(pTable)))
			{
				pEntry->CurrTxRateIndex = pAd->CommonCfg.FixedRate;
				MlmeNewTxRate(pAd, pEntry);

				/* reset all OneSecTx counters */
				RESET_ONE_SEC_TX_CNT(pEntry);
#ifdef TXBF_SUPPORT
				if (pAd->chipCap.FlgHwTxBfCap)
					eTxBFProbing(pAd, pEntry);
#endif /* TXBF_SUPPORT */

				continue;
			}
		}
#endif /* defined (RT2883) || defined (RT3883) */


		/*
			CASE 1. when TX samples are fewer than 15, then decide TX rate solely on RSSI
			     (criteria copied from RT2500 for Netopia case)
		*/
		if (TxTotalCnt <= 15)
		{
			UCHAR	TxRateIdx;
			CHAR	mcs[24];
			CHAR	RssiOffset = 0;

			/* Check existence and get the index of each MCS */
			MlmeGetSupportedMcs(pAd, pTable, mcs);

			if (pAd->LatchRfRegs.Channel <= 14)
			{
				RssiOffset = pAd->NicConfig2.field.ExternalLNAForG? 2: 5;
			}
			else
			{
				RssiOffset = pAd->NicConfig2.field.ExternalLNAForA? 5: 8;
			}

			/* Select the Tx rate based on the RSSI */
			TxRateIdx = MlmeSelectTxRate(pAd, pEntry, mcs, Rssi, RssiOffset);



	/*		if (TxRateIdx != pAd->CommonCfg.TxRateIndex) */
			{
				pEntry->CurrTxRateIndex = TxRateIdx;
#ifdef TXBF_SUPPORT
				pEntry->phyETxBf = pEntry->phyITxBf = FALSE;
#endif /* TXBF_SUPPORT */
				MlmeNewTxRate(pAd, pEntry);
				if (!pEntry->fLastSecAccordingRSSI)
					DBGPRINT_RAW(RT_DEBUG_INFO,("DRS: TxTotalCnt <= 15, switch MCS according to RSSI (%d), RssiOffset=%d\n", Rssi, RssiOffset));
			}

			MlmeClearAllTxQuality(pEntry);
			pEntry->fLastSecAccordingRSSI = TRUE;

			/* reset all OneSecTx counters */
			RESET_ONE_SEC_TX_CNT(pEntry);

#ifdef TXBF_SUPPORT
#ifdef DBG_CTRL_SUPPORT
			/* In Unaware mode always try to send sounding */
			if (pAd->CommonCfg.DebugFlags & DBF_NO_BF_AWARE_RA)
				eTxBFProbing(pAd, pEntry);
#endif /* DBG_CTRL_SUPPORT */
#endif /* TXBF_SUPPORT */

			continue;
		}

		if (pEntry->fLastSecAccordingRSSI == TRUE)
		{
			pEntry->fLastSecAccordingRSSI = FALSE;
			pEntry->LastSecTxRateChangeAction = RATE_NO_CHANGE;
			/* reset all OneSecTx counters */
			RESET_ONE_SEC_TX_CNT(pEntry);

#ifdef TXBF_SUPPORT
			if (pAd->chipCap.FlgHwTxBfCap)
			eTxBFProbing(pAd, pEntry);
#endif /* TXBF_SUPPORT */

			continue;
		}

		pEntry->PER[CurrRateIdx] = (UCHAR)TxErrorRatio;

		/* Select rate based on PER */
		MlmeOldRateAdapt(pAd, pEntry, CurrRateIdx, UpRateIdx, DownRateIdx, TrainUp, TrainDown, TxErrorRatio);

#ifdef DOT11N_SS3_SUPPORT
		/* Turn off RDG when 3s and rx count > tx count*5 */
		MlmeCheckRDG(pAd, pEntry);
#endif /* DOT11N_SS3_SUPPORT */

		/* reset all OneSecTx counters */
		RESET_ONE_SEC_TX_CNT(pEntry);

#ifdef TXBF_SUPPORT
		if (pAd->chipCap.FlgHwTxBfCap)
		eTxBFProbing(pAd, pEntry);
#endif /* TXBF_SUPPORT */
		}
}


/*
	========================================================================
	Routine Description:
		Station side, Auto TxRate faster train up timer call back function.

	Arguments:
		SystemSpecific1			- Not used.
		FunctionContext			- Pointer to our Adapter context.
		SystemSpecific2			- Not used.
		SystemSpecific3			- Not used.

	Return Value:
		None

	========================================================================
*/
VOID StaQuickResponeForRateUpExec(
	IN PVOID SystemSpecific1, 
	IN PVOID FunctionContext, 
	IN PVOID SystemSpecific2, 
	IN PVOID SystemSpecific3) 
{
	PRTMP_ADAPTER			pAd = (PRTMP_ADAPTER)FunctionContext;
	ULONG					i;
	PUCHAR					pTable;
	UCHAR					TableSize = 0;
	UCHAR					CurrRateIdx;
	ULONG					TxTotalCnt;
	ULONG					TxErrorRatio = 0;
	PRTMP_TX_RATE_SWITCH	pCurrTxRate;
	UCHAR					InitTxRateIdx, TrainUp, TrainDown;
	CHAR					Rssi, ratio;
	ULONG					TxSuccess, TxRetransmit, TxFailCount;
	MAC_TABLE_ENTRY			*pEntry;
#ifdef TXBF_SUPPORT
	BOOLEAN					CurrPhyETxBf, CurrPhyITxBf;
#endif /* TXBF_SUPPORT */
#ifdef AGS_SUPPORT
	AGS_STATISTICS_INFO		AGSStatisticsInfo = {0};
#endif /* AGS_SUPPORT */

	pAd->StaCfg.StaQuickResponeForRateUpTimerRunning = FALSE;

    /* walk through MAC table, see if need to change AP's TX rate toward each entry */
	for (i = 1; i < MAX_LEN_OF_MAC_TABLE; i++) 
	{
		pEntry = &pAd->MacTab.Content[i];

		if (IS_ENTRY_NONE(pEntry))
			continue;

		/* check if this entry need to switch rate automatically */
		if (RTMPCheckEntryEnableAutoRateSwitch(pAd, pEntry) == FALSE)
			continue;

		/* Do nothing if this entry didn't change */
		if (pEntry->LastSecTxRateChangeAction == RATE_NO_CHANGE
#ifdef DBG_CTRL_SUPPORT
			&& (pAd->CommonCfg.DebugFlags & DBF_FORCE_QUICK_DRS)==0
#endif /* DBG_CTRL_SUPPORT */
		)
			continue;

		if (INFRA_ON(pAd) && (i == 1))
			Rssi = RTMPAvgRssi(pAd, &pAd->StaCfg.RssiSample);
		else
			Rssi = RTMPAvgRssi(pAd, &pEntry->RssiSample);

		MlmeSelectTxRateTable(pAd, pEntry, &pTable, &TableSize, &InitTxRateIdx);
		pEntry->pTable = pTable;

#ifdef NEW_RATE_ADAPT_SUPPORT
		if (ADAPT_RATE_TABLE(pTable))
		{
			StaQuickResponeForRateUpExecAdapt(pAd, i, Rssi);
			continue;
		}
#endif /* NEW_RATE_ADAPT_SUPPORT */

		CurrRateIdx = pEntry->CurrTxRateIndex;
#ifdef TXBF_SUPPORT
		CurrPhyETxBf = pEntry->phyETxBf;
		CurrPhyITxBf = pEntry->phyITxBf;
#endif /* TXBF_SUPPORT */
		pCurrTxRate = PTX_RATE_SWITCH_ENTRY(pTable, CurrRateIdx);

#ifdef DOT11_N_SUPPORT
		if ((Rssi > -65) && (pCurrTxRate->Mode >= MODE_HTMIX))
		{
			TrainUp		= (pCurrTxRate->TrainUp + (pCurrTxRate->TrainUp >> 1));
			TrainDown	= (pCurrTxRate->TrainDown + (pCurrTxRate->TrainDown >> 1));
		}
		else
#endif /* DOT11_N_SUPPORT */
		{
			TrainUp		= pCurrTxRate->TrainUp;
			TrainDown	= pCurrTxRate->TrainDown;
		}

		if (pAd->MacTab.Size == 1)
		{
			/* Update statistic counter */
			TX_STA_CNT1_STRUC	StaTx1;
			TX_STA_CNT0_STRUC	TxStaCnt0;

			RTMP_IO_READ32(pAd, TX_STA_CNT0, &TxStaCnt0.word);
			RTMP_IO_READ32(pAd, TX_STA_CNT1, &StaTx1.word);

			TxRetransmit = StaTx1.field.TxRetransmit;
			TxSuccess = StaTx1.field.TxSuccess;
			TxFailCount = TxStaCnt0.field.TxFailCount;
			TxTotalCnt = TxRetransmit + TxSuccess + TxFailCount;

			pAd->RalinkCounters.OneSecTxRetryOkCount += StaTx1.field.TxRetransmit;
			pAd->RalinkCounters.OneSecTxNoRetryOkCount += StaTx1.field.TxSuccess;
			pAd->RalinkCounters.OneSecTxFailCount += TxStaCnt0.field.TxFailCount;

#ifdef STATS_COUNT_SUPPORT
			pAd->WlanCounters.TransmittedFragmentCount.u.LowPart += StaTx1.field.TxSuccess;
			pAd->WlanCounters.RetryCount.u.LowPart += StaTx1.field.TxRetransmit;
			pAd->WlanCounters.FailedCount.u.LowPart += TxStaCnt0.field.TxFailCount;
#endif /* STATS_COUNT_SUPPORT */

			if (TxTotalCnt)
				TxErrorRatio = ((TxRetransmit + TxFailCount) * 100) / TxTotalCnt;

#ifdef AGS_SUPPORT
			if (SUPPORT_AGS(pAd))
			{
				
				/* Gather the statistics information*/
				
				AGSStatisticsInfo.RSSI = Rssi;
				AGSStatisticsInfo.TxErrorRatio = TxErrorRatio;
				AGSStatisticsInfo.AccuTxTotalCnt = TxTotalCnt;
				AGSStatisticsInfo.TxTotalCnt = TxTotalCnt;
				AGSStatisticsInfo.TxSuccess = TxSuccess;
				AGSStatisticsInfo.TxRetransmit = TxRetransmit;
				AGSStatisticsInfo.TxFailCount = TxFailCount;
			}
#endif /* AGS_SUPPORT */
		}
		else
		{
			TxRetransmit = pEntry->OneSecTxRetryOkCount;
			TxSuccess = pEntry->OneSecTxNoRetryOkCount;
			TxFailCount = pEntry->OneSecTxFailCount;

			TxTotalCnt = TxRetransmit + TxSuccess + TxFailCount;
			if (TxTotalCnt)
				TxErrorRatio = ((TxRetransmit + TxFailCount) * 100) / TxTotalCnt;

#ifdef FIFO_EXT_SUPPORT
			if (pAd->chipCap.FlgHwFifoExtCap)
			{
				if (pEntry->Aid >= 1 && pEntry->Aid <= 8)
				{
					WCID_TX_CNT_STRUC wcidTxCnt;
					UINT32 regAddr, offset;
					ULONG HwTxCnt, HwErrRatio = 0;

					regAddr = WCID_TX_CNT_0 + (pEntry->Aid - 1) * 4;
					RTMP_IO_READ32(pAd, regAddr, &wcidTxCnt.word);

					HwTxCnt = wcidTxCnt.field.succCnt + wcidTxCnt.field.reTryCnt;
					if (HwTxCnt)
						HwErrRatio = (wcidTxCnt.field.reTryCnt * 100) / HwTxCnt;

					DBGPRINT(RT_DEBUG_INFO ,("%s():TxErrRatio(Aid:%d, MCS:%d, Hw:0x%x-0x%x, Sw:0x%x-%x)\n", 
							__FUNCTION__, pEntry->Aid, pEntry->HTPhyMode.field.MCS, 
							HwTxCnt, HwErrRatio, TxTotalCnt, TxErrorRatio));

					TxSuccess = wcidTxCnt.field.succCnt;
					TxRetransmit = wcidTxCnt.field.reTryCnt;
					TxErrorRatio = HwErrRatio;
					TxTotalCnt = HwTxCnt;
				}
			}
#endif /* FIFO_EXT_SUPPORT */

#ifdef AGS_SUPPORT
			if (SUPPORT_AGS(pAd))
			{
				
				/* Gather the statistics information*/
				
				AGSStatisticsInfo.RSSI = Rssi;
				AGSStatisticsInfo.TxErrorRatio = TxErrorRatio;
				AGSStatisticsInfo.AccuTxTotalCnt = TxTotalCnt;
				AGSStatisticsInfo.TxTotalCnt = TxTotalCnt;
				AGSStatisticsInfo.TxSuccess = pEntry->OneSecTxNoRetryOkCount;
				AGSStatisticsInfo.TxRetransmit = pEntry->OneSecTxRetryOkCount;
				AGSStatisticsInfo.TxFailCount = pEntry->OneSecTxFailCount;
			}
#endif /* AGS_SUPPORT */
		}

#ifdef AGS_SUPPORT
		if (AGS_IS_USING(pAd, pTable))
		{
			
			/* The dynamic Tx rate switching for AGS (Adaptive Group Switching)*/
			
			StaQuickResponeForRateUpExecAGS(pAd, pEntry, pTable, TableSize, &AGSStatisticsInfo, InitTxRateIdx);
			
			continue; /* Skip the remaining procedure of the old Tx rate switching*/
		}
#endif /* AGS_SUPPORT */

#ifdef DBG_CTRL_SUPPORT
		/* Debug option: Concise RA log */
		if (pAd->CommonCfg.DebugFlags & DBF_SHOW_RA_LOG)
			MlmeRALog(pAd, pEntry, RAL_QUICK_DRS, TxErrorRatio, TxTotalCnt);
#endif /* DBG_CTRL_SUPPORT */

		/*
			CASE 1. when TX samples are fewer than 15, then decide TX rate solely on RSSI
			     (criteria copied from RT2500 for Netopia case)
		*/
		if (TxTotalCnt <= 12)
		{
			MlmeClearAllTxQuality(pEntry);

			/* Set current up MCS at the worst quality */
			if (pEntry->LastSecTxRateChangeAction == RATE_UP)
			{
				MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND);
			}

			/* Go back to the original rate */
			MlmeRestoreLastRate(pEntry);
			MlmeNewTxRate(pAd, pEntry);

			// TODO: should we reset all OneSecTx counters?
			/* RESET_ONE_SEC_TX_CNT(pEntry); */

			continue;
		}

		pEntry->PER[CurrRateIdx] = (UCHAR)TxErrorRatio;

       /* Compare throughput */
		do
		{
			ULONG OneSecTxNoRetryOKRationCount;

			/* Compare throughput. LastTxCount is based on a 500 msec or 500-DEF_QUICK_RA_TIME_INTERVAL interval. */
			if ((pEntry->LastTimeTxRateChangeAction == RATE_NO_CHANGE)
#ifdef DBG_CTRL_SUPPORT
				&& (pAd->CommonCfg.DebugFlags & DBF_FORCE_QUICK_DRS)==0
#endif /* DBG_CTRL_SUPPORT */
			)
				ratio = RA_INTERVAL/DEF_QUICK_RA_TIME_INTERVAL;
			else
				ratio = (RA_INTERVAL-DEF_QUICK_RA_TIME_INTERVAL)/DEF_QUICK_RA_TIME_INTERVAL;

			OneSecTxNoRetryOKRationCount = (TxSuccess * ratio);

			/* downgrade TX quality if PER >= Rate-Down threshold */
			if (TxErrorRatio >= TrainDown)
			{
				MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND);
			}

			/* perform DRS - consider TxRate Down first, then rate up. */
			if (pEntry->LastSecTxRateChangeAction == RATE_UP)
			{
				if (TxErrorRatio >= TrainDown)
				{
#ifdef TXBF_SUPPORT
					/* If PER>50% or TP<lastTP/2 then double the TxQuality delay */
					if ((TxErrorRatio > 50) || (OneSecTxNoRetryOKRationCount < pEntry->LastTxOkCount/2))
						MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND*2);
					else
#endif /* TXBF_SUPPORT */
						MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND);

					MlmeRestoreLastRate(pEntry);
					DBGPRINT(RT_DEBUG_INFO | DBG_FUNC_RA,("   QuickDRS: (Up) bad tx ok count (L:%ld, C:%ld)\n", pEntry->LastTxOkCount, OneSecTxNoRetryOKRationCount));
				}
				else
				{
					DBGPRINT(RT_DEBUG_INFO | DBG_FUNC_RA,("   QuickDRS: (Up) keep rate-up (L:%ld, C:%ld)\n", pEntry->LastTxOkCount, OneSecTxNoRetryOKRationCount));
				}
			}
			else if (pEntry->LastSecTxRateChangeAction == RATE_DOWN)
			{
				/* Note: AP had "(TxErrorRatio >= 50) && (TxErrorRatio >= TrainDown)" */
				if ((TxErrorRatio >= 50) || (TxErrorRatio >= TrainDown))
				{
					DBGPRINT(RT_DEBUG_INFO | DBG_FUNC_RA,("   QuickDRS: (Down) direct train down (TxErrorRatio >= TrainDown)\n"));
				}
				else if ((pEntry->LastTxOkCount + 2) >= OneSecTxNoRetryOKRationCount)
				{
					MlmeRestoreLastRate(pEntry);
					DBGPRINT(RT_DEBUG_INFO | DBG_FUNC_RA,("   QuickDRS: (Down) bad tx ok count (L:%ld, C:%ld)\n", pEntry->LastTxOkCount, OneSecTxNoRetryOKRationCount));
				}
				else
					DBGPRINT(RT_DEBUG_INFO | DBG_FUNC_RA,("   QuickDRS: (Down) keep rate-down (L:%ld, C:%ld)\n", pEntry->LastTxOkCount, OneSecTxNoRetryOKRationCount));
			}
		}while (FALSE);

#ifdef TXBF_SUPPORT
		/* Remember last good non-BF rate */
		if (!pEntry->phyETxBf && !pEntry->phyITxBf)
			pEntry->lastNonBfRate = pEntry->CurrTxRateIndex;
#endif /* TXBF_SUPPORT */

		/* If rate changed then update the history and set the new tx rate */
		if ((pEntry->CurrTxRateIndex != CurrRateIdx)
#ifdef TXBF_SUPPORT
			|| (pEntry->phyETxBf!=CurrPhyETxBf) || (pEntry->phyITxBf!=CurrPhyITxBf)
#endif /* TXBF_SUPPORT */
		)
		{
			/* if rate-up happen, clear all bad history of all TX rates */
			if (pEntry->LastSecTxRateChangeAction == RATE_DOWN)
			{
				/* DBGPRINT_RAW(RT_DEBUG_INFO,("   QuickDRS: ++TX rate from %d to %d \n", CurrRateIdx, pEntry->CurrTxRateIndex)); */

				pEntry->TxRateUpPenalty = 0;
				if (pEntry->CurrTxRateIndex != CurrRateIdx)
					MlmeClearTxQuality(pEntry);
			}
			/* if rate-down happen, only clear DownRate's bad history */
			else if (pEntry->LastSecTxRateChangeAction == RATE_UP)
			{
				/* DBGPRINT_RAW(RT_DEBUG_INFO,("   QuickDRS: --TX rate from %d to %d \n", CurrRateIdx, pEntry->CurrTxRateIndex)); */

				pEntry->TxRateUpPenalty = 0;           /* no penalty */
				MlmeSetTxQuality(pEntry, pEntry->CurrTxRateIndex, 0);
				pEntry->PER[pEntry->CurrTxRateIndex] = 0;
			}

			MlmeNewTxRate(pAd, pEntry);
		}

		// TODO: should we reset all OneSecTx counters?
		/* RESET_ONE_SEC_TX_CNT(pEntry); */
	}
}
#endif /* CONFIG_STA_SUPPORT */


/*
	MlmeOldRateAdapt - perform Rate Adaptation based on PER using old RA algorithm
		pEntry - the MAC table entry
		CurrRateIdx - the index of the current rate
		UpRateIdx, DownRateIdx - UpRate and DownRate index
		TrainUp, TrainDown - TrainUp and Train Down threhsolds
		TxErrorRatio - the PER

		On exit:
			pEntry->LastSecTxRateChangeAction = RATE_UP or RATE_DOWN if there was a change
			pEntry->CurrTxRateIndex = new rate index
			pEntry->TxQuality is updated
*/
VOID MlmeOldRateAdapt(
	IN PRTMP_ADAPTER 	pAd,
	IN PMAC_TABLE_ENTRY	pEntry,
	IN UCHAR			CurrRateIdx,
	IN UCHAR			UpRateIdx,
	IN UCHAR			DownRateIdx,
	IN ULONG			TrainUp,
	IN ULONG			TrainDown,
	IN ULONG			TxErrorRatio)
{
	BOOLEAN	bTrainUp = FALSE;
#ifdef TXBF_SUPPORT
	UCHAR *pTable = pEntry->pTable;
	BOOLEAN invertTxBf = FALSE;
#endif /* TXBF_SUPPORT */

	pEntry->LastSecTxRateChangeAction = RATE_NO_CHANGE;

	pEntry->CurrTxRateStableTime++;

	/* Downgrade TX quality if PER >= Rate-Down threshold */
	if (TxErrorRatio >= TrainDown)
	{
		MlmeSetTxQuality(pEntry, CurrRateIdx, DRS_TX_QUALITY_WORST_BOUND);
#ifdef TXBF_SUPPORT
		/*
			Need to train down. If BF and last Non-BF isn't too much lower then
			go to last Non-BF rate. Otherwise just go to the down rate
		*/
		if ((pEntry->phyETxBf || pEntry->phyITxBf) &&
			(DownRateIdx - pEntry->lastNonBfRate)<2 
#ifdef DBG_CTRL_SUPPORT
			&& ((pAd->CommonCfg.DebugFlags & DBF_NO_BF_AWARE_RA)==0)
#endif /* DBG_CTRL_SUPPORT */
		)
		{
			/* Go directly to last non-BF rate without 100 msec check */
			pEntry->CurrTxRateIndex = pEntry->lastNonBfRate;
			pEntry->phyETxBf = pEntry->phyITxBf = FALSE;
			MlmeNewTxRate(pAd, pEntry);
			DBGPRINT_RAW(RT_DEBUG_INFO | DBG_FUNC_RA,("DRS: --TX rate from %d to %d \n", CurrRateIdx, pEntry->CurrTxRateIndex));
			return;
		}
		else
#endif /* TXBF_SUPPORT */
		if (CurrRateIdx != DownRateIdx)
		{

#ifdef FIX_LOWER_RATE_MCS
						UCHAR *pTable = pEntry->pTable;
						CHAR Rssi;
						PRTMP_TX_RATE_SWITCH	pCurrTxRate;
			
						Rssi = RTMPAvgRssi(pAd, &pEntry->RssiSample);
						pCurrTxRate = PTX_RATE_SWITCH_ENTRY(pTable, CurrRateIdx);
						
						
						if(Rssi > -60 && pCurrTxRate->CurrMCS == 3)
						{
							pEntry->LastSecTxRateChangeAction = RATE_NO_CHANGE;
						}
						else	
						{
							pEntry->CurrTxRateIndex = DownRateIdx;
							pEntry->LastSecTxRateChangeAction = RATE_DOWN;
						}
#else	


			pEntry->CurrTxRateIndex = DownRateIdx;
			pEntry->LastSecTxRateChangeAction = RATE_DOWN;
#endif
		}
	}
	else
	{
		/* Upgrade TX quality if PER <= Rate-Up threshold */
		if (TxErrorRatio <= TrainUp)
		{
			bTrainUp = TRUE;
			MlmeDecTxQuality(pEntry, CurrRateIdx);  /* quality very good in CurrRate */

			if (pEntry->TxRateUpPenalty)
				pEntry->TxRateUpPenalty --;
			else
				MlmeDecTxQuality(pEntry, UpRateIdx);    /* may improve next UP rate's quality */
		}

		if (bTrainUp)
		{
			/* Train up if up rate quality is 0 */
			if ((CurrRateIdx != UpRateIdx) && (MlmeGetTxQuality(pEntry, UpRateIdx) <= 0))
			{
				pEntry->CurrTxRateIndex = UpRateIdx;
				pEntry->LastSecTxRateChangeAction = RATE_UP;
			}
#ifdef TXBF_SUPPORT
			else if (((CurrRateIdx != UpRateIdx) || (TxErrorRatio > TrainUp))
#ifdef DBG_CTRL_SUPPORT
					&& ((pAd->CommonCfg.DebugFlags & DBF_NO_BF_AWARE_RA)==0)
#endif /* DBG_CTRL_SUPPORT */
			)
			{
				/* UpRate TxQuality is not 0. Try to invert BF state */
				if (pEntry->phyETxBf || pEntry->phyITxBf)
				{
					/* BF tries same MCS, non-BF */
					if (pEntry->TxQuality[CurrRateIdx])
						pEntry->TxQuality[CurrRateIdx]--;

					if (pEntry->TxQuality[CurrRateIdx]==0)
					{
						invertTxBf = TRUE;
						pEntry->CurrTxRateIndex = CurrRateIdx;
						pEntry->LastSecTxRateChangeAction = RATE_UP;
					}
				}
				else if (pEntry->eTxBfEnCond>0 || pEntry->iTxBfEn)
				{
					PRTMP_TX_RATE_SWITCH pUpRate = PTX_RATE_SWITCH_ENTRY(pTable, UpRateIdx);
					PRTMP_TX_RATE_SWITCH pCurrTxRate = PTX_RATE_SWITCH_ENTRY(pTable, CurrRateIdx);

					/* First try Up Rate with BF */
					if ((CurrRateIdx != UpRateIdx) && MlmeTxBfAllowed(pAd, pEntry, pUpRate))
					{
						if (pEntry->BfTxQuality[UpRateIdx])
							pEntry->BfTxQuality[UpRateIdx]--;

						if (pEntry->BfTxQuality[UpRateIdx]==0)
						{
							invertTxBf = TRUE;
							pEntry->CurrTxRateIndex = UpRateIdx;
							pEntry->LastSecTxRateChangeAction = RATE_UP;
						}
					}

					/* Try Same Rate if Up Rate failed */
					if (pEntry->LastSecTxRateChangeAction==RATE_NO_CHANGE &&
						MlmeTxBfAllowed(pAd, pEntry, pCurrTxRate))
					{
						if (pEntry->BfTxQuality[CurrRateIdx])
							pEntry->BfTxQuality[CurrRateIdx]--;

						if (pEntry->BfTxQuality[CurrRateIdx]==0)
						{
							invertTxBf = TRUE;
							pEntry->CurrTxRateIndex = CurrRateIdx;
							pEntry->LastSecTxRateChangeAction = RATE_UP;
						}
					}
				}
			}
#endif /* TXBF_SUPPORT */
		}
	}

	/* Handle the rate change */
	if (pEntry->LastSecTxRateChangeAction != RATE_NO_CHANGE)
	{
		pEntry->CurrTxRateStableTime = 0;
		pEntry->TxRateUpPenalty = 0;

		/* Save last rate information */
		pEntry->lastRateIdx = CurrRateIdx;
#ifdef TXBF_SUPPORT
		if (pEntry->eTxBfEnCond>0)
		{
			pEntry->lastRatePhyTxBf = pEntry->phyETxBf;
			pEntry->phyETxBf ^= invertTxBf;
		}
		else
		{
			pEntry->lastRatePhyTxBf = pEntry->phyITxBf;
			pEntry->phyITxBf ^= invertTxBf;
		}
#endif /* TXBF_SUPPORT */

		/* Update TxQuality */
		if (pEntry->LastSecTxRateChangeAction == RATE_UP)
		{
			/* Clear history if normal train up */
			if (pEntry->lastRateIdx != pEntry->CurrTxRateIndex)
				MlmeClearTxQuality(pEntry);
		}
		else
		{
			/* Clear the down rate history */
			MlmeSetTxQuality(pEntry, pEntry->CurrTxRateIndex, 0);
			pEntry->PER[pEntry->CurrTxRateIndex] = 0;
		}

		/* Set timer for check in 100 msec */
#ifdef CONFIG_AP_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_AP(pAd)
		{
			if (!pAd->ApCfg.ApQuickResponeForRateUpTimerRunning)
			{
				RTMPSetTimer(&pAd->ApCfg.ApQuickResponeForRateUpTimer, DEF_QUICK_RA_TIME_INTERVAL);
				pAd->ApCfg.ApQuickResponeForRateUpTimerRunning = TRUE;
			}
		}
#endif /* CONFIG_AP_SUPPORT */
#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			if (!pAd->StaCfg.StaQuickResponeForRateUpTimerRunning)
			{
				RTMPSetTimer(&pAd->StaCfg.StaQuickResponeForRateUpTimer, DEF_QUICK_RA_TIME_INTERVAL);
				pAd->StaCfg.StaQuickResponeForRateUpTimerRunning = TRUE;
			}
		}
#endif /* CONFIG_STA_SUPPORT */

		/* Update PHY rate */
		MlmeNewTxRate(pAd, pEntry);
	}
}
