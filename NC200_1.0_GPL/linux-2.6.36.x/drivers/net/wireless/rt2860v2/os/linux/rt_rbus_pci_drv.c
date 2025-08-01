/****************************************************************************
 * Ralink Tech Inc.
 * Taiwan, R.O.C.
 *
 * (c) Copyright 2002, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************/



#ifdef RTMP_MAC_PCI
#include	"rt_config.h"


#ifdef WORKQUEUE_BH
static void rx_done_workq(struct work_struct *work);
static void mgmt_dma_done_workq(struct work_struct *work);
static void ac0_dma_done_workq(struct work_struct *work);
static void ac1_dma_done_workq(struct work_struct *work);
static void ac2_dma_done_workq(struct work_struct *work);
static void ac3_dma_done_workq(struct work_struct *work);
static void hcca_dma_done_workq(struct work_struct *work);
static void fifo_statistic_full_workq(struct work_struct *work);
#else
static void rx_done_tasklet(unsigned long data);
static void mgmt_dma_done_tasklet(unsigned long data);
static void ac0_dma_done_tasklet(unsigned long data);
#ifdef RALINK_ATE
static void ate_ac0_dma_done_tasklet(unsigned long data);
#endif /* RALINK_ATE */
static void ac1_dma_done_tasklet(unsigned long data);
static void ac2_dma_done_tasklet(unsigned long data);
static void ac3_dma_done_tasklet(unsigned long data);
static void hcca_dma_done_tasklet(unsigned long data);
static void fifo_statistic_full_tasklet(unsigned long data);
#endif /* WORKQUEUE_BH */

#ifdef UAPSD_SUPPORT
#ifdef WORKQUEUE_BH
static void uapsd_eosp_sent_workq(struct work_struct *work);
#else
static void uapsd_eosp_sent_tasklet(unsigned long data);
#endif /* WORKQUEUE_BH */
#endif /* UAPSD_SUPPORT */


/*---------------------------------------------------------------------*/
/* Symbol & Macro Definitions                                          */
/*---------------------------------------------------------------------*/
#define RT2860_INT_RX_DLY				(1<<0)		/* bit 0 */
#define RT2860_INT_TX_DLY				(1<<1)		/* bit 1 */
#define RT2860_INT_RX_DONE				(1<<2)		/* bit 2 */
#define RT2860_INT_AC0_DMA_DONE			(1<<3)		/* bit 3 */
#define RT2860_INT_AC1_DMA_DONE			(1<<4)		/* bit 4 */
#define RT2860_INT_AC2_DMA_DONE			(1<<5)		/* bit 5 */
#define RT2860_INT_AC3_DMA_DONE			(1<<6)		/* bit 6 */
#define RT2860_INT_HCCA_DMA_DONE		(1<<7)		/* bit 7 */
#define RT2860_INT_MGMT_DONE			(1<<8)		/* bit 8 */
#ifdef CARRIER_DETECTION_SUPPORT
#define RT2860_INT_TONE_RADAR			(1<<20)		/* bit 20 */
#endif /* CARRIER_DETECTION_SUPPORT*/

#define INT_RX			RT2860_INT_RX_DONE

#define INT_AC0_DLY		(RT2860_INT_AC0_DMA_DONE) /*| RT2860_INT_TX_DLY) */
#define INT_AC1_DLY		(RT2860_INT_AC1_DMA_DONE) /*| RT2860_INT_TX_DLY) */
#define INT_AC2_DLY		(RT2860_INT_AC2_DMA_DONE) /*| RT2860_INT_TX_DLY) */
#define INT_AC3_DLY		(RT2860_INT_AC3_DMA_DONE) /*| RT2860_INT_TX_DLY) */
#define INT_HCCA_DLY 	(RT2860_INT_HCCA_DMA_DONE) /*| RT2860_INT_TX_DLY) */
#define INT_MGMT_DLY	RT2860_INT_MGMT_DONE
#ifdef CARRIER_DETECTION_SUPPORT
#define INT_TONE_RADAR	(RT2860_INT_TONE_RADAR)
#endif /* CARRIER_DETECTION_SUPPORT*/

NDIS_STATUS RtmpNetTaskInit(IN RTMP_ADAPTER *pAd)
{
	POS_COOKIE pObj;

	pObj = (POS_COOKIE) pAd->OS_Cookie;
	
#ifdef WORKQUEUE_BH
	RTMP_OS_TASKLET_INIT(pAd, &pObj->rx_done_work, rx_done_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->mgmt_dma_done_work, mgmt_dma_done_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ac0_dma_done_work, ac0_dma_done_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ac1_dma_done_work, ac1_dma_done_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ac2_dma_done_work, ac2_dma_done_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ac3_dma_done_work, ac3_dma_done_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->hcca_dma_done_work, hcca_dma_done_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->tbtt_work, tbtt_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->pretbtt_work, pretbtt_workq);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->fifo_statistic_full_work, fifo_statistic_full_workq);
#ifdef UAPSD_SUPPORT
	RTMP_OS_TASKLET_INIT(pAd, &pObj->uapsd_eosp_sent_work, uapsd_eosp_sent_workq);
#endif /* UAPSD_SUPPORT */

#ifdef CONFIG_AP_SUPPORT
#ifdef P2P_SUPPORT
#else
	IF_DEV_CONFIG_OPMODE_ON_AP(pAd)
#endif /* P2P_SUPPORT */
	{
#ifdef DFS_SUPPORT
		RTMP_OS_TASKLET_INIT(pAd, &pObj->dfs_work, dfs_workq);
#endif /* DFS_SUPPORT */
	}
#endif /* CONFIG_AP_SUPPORT */
#else
	RTMP_OS_TASKLET_INIT(pAd, &pObj->rx_done_task, rx_done_tasklet, (unsigned long)pAd);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->mgmt_dma_done_task, mgmt_dma_done_tasklet, (unsigned long)pAd);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ac0_dma_done_task, ac0_dma_done_tasklet, (unsigned long)pAd);
#ifdef RALINK_ATE
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ate_ac0_dma_done_task, ate_ac0_dma_done_tasklet, (unsigned long)pAd);
#endif /* RALINK_ATE */
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ac1_dma_done_task, ac1_dma_done_tasklet, (unsigned long)pAd);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ac2_dma_done_task, ac2_dma_done_tasklet, (unsigned long)pAd);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->ac3_dma_done_task, ac3_dma_done_tasklet, (unsigned long)pAd);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->hcca_dma_done_task, hcca_dma_done_tasklet, (unsigned long)pAd);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->tbtt_task, tbtt_tasklet, (unsigned long)pAd);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->pretbtt_task, pretbtt_tasklet, (unsigned long)pAd);
	RTMP_OS_TASKLET_INIT(pAd, &pObj->fifo_statistic_full_task, fifo_statistic_full_tasklet, (unsigned long)pAd);
#ifdef UAPSD_SUPPORT	
	RTMP_OS_TASKLET_INIT(pAd, &pObj->uapsd_eosp_sent_task, uapsd_eosp_sent_tasklet, (unsigned long)pAd);
#endif /* UAPSD_SUPPORT */
#ifdef CONFIG_AP_SUPPORT
#ifdef P2P_SUPPORT
#else
	IF_DEV_CONFIG_OPMODE_ON_AP(pAd)
#endif /* P2P_SUPPORT */
	{
#ifdef DFS_SUPPORT
		RTMP_OS_TASKLET_INIT(pAd, &pObj->dfs_task, dfs_tasklet, (unsigned long)pAd);
#endif /* DFS_SUPPORT */
	}
#endif /* CONFIG_AP_SUPPORT */
#endif /* WORKQUEUE_BH */

	return NDIS_STATUS_SUCCESS;
}


void RtmpNetTaskExit(IN RTMP_ADAPTER *pAd)
{
	POS_COOKIE pObj;

	pObj = (POS_COOKIE) pAd->OS_Cookie;

#ifndef WORKQUEUE_BH
	RTMP_OS_TASKLET_KILL(&pObj->rx_done_task);
	RTMP_OS_TASKLET_KILL(&pObj->mgmt_dma_done_task);
	RTMP_OS_TASKLET_KILL(&pObj->ac0_dma_done_task);
#ifdef RALINK_ATE
	RTMP_OS_TASKLET_KILL(&pObj->ate_ac0_dma_done_task);
#endif /* RALINK_ATE */
	RTMP_OS_TASKLET_KILL(&pObj->ac1_dma_done_task);
	RTMP_OS_TASKLET_KILL(&pObj->ac2_dma_done_task);
	RTMP_OS_TASKLET_KILL(&pObj->ac3_dma_done_task);
	RTMP_OS_TASKLET_KILL(&pObj->hcca_dma_done_task);
	RTMP_OS_TASKLET_KILL(&pObj->tbtt_task);
	RTMP_OS_TASKLET_KILL(&pObj->pretbtt_task);
	RTMP_OS_TASKLET_KILL(&pObj->fifo_statistic_full_task);
#ifdef UAPSD_SUPPORT
		RTMP_OS_TASKLET_KILL(&pObj->uapsd_eosp_sent_task);
#endif /* UAPSD_SUPPORT */
#ifdef CONFIG_AP_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_AP(pAd)
	{
#ifdef DFS_SUPPORT
		RTMP_OS_TASKLET_KILL(&pObj->dfs_task);
#endif /* DFS_SUPPORT */

	}
#endif /* CONFIG_AP_SUPPORT */
#endif /* WORKQUEUE_BH */
}


NDIS_STATUS RtmpMgmtTaskInit(IN RTMP_ADAPTER *pAd)
{
	RTMP_OS_TASK *pTask;
	NDIS_STATUS status;


	/* Creat Command Thread */
	pTask = &pAd->cmdQTask;
	RTMP_OS_TASK_INIT(pTask, "RtmpCmdQTask", pAd);
	status = RtmpOSTaskAttach(pTask, RTPCICmdThread, (ULONG)pTask);
	if (status == NDIS_STATUS_FAILURE) 
	{
/*		printk ("%s: unable to start RTPCICmdThread\n", RTMP_OS_NETDEV_GET_DEVNAME(pAd->net_dev)); */
		printk ("Unable to start RTPCICmdThread!\n");
		return NDIS_STATUS_FAILURE;
	}

#ifdef WSC_INCLUDED
	/* start the crediential write task first. */
	WscThreadInit(pAd);
#endif /* WSC_INCLUDED */

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
    Close kernel threads.

Arguments:
	*pAd				the raxx interface data pointer

Return Value:
    NONE

Note:
========================================================================
*/
VOID RtmpMgmtTaskExit(
	IN RTMP_ADAPTER *pAd)
{
	INT ret;


	/* Terminate cmdQ thread */
	RTMP_OS_TASK_LEGALITY(&pAd->cmdQTask)
	{
		NdisAcquireSpinLock(&pAd->CmdQLock);
		pAd->CmdQ.CmdQState = RTMP_TASK_STAT_STOPED;
		NdisReleaseSpinLock(&pAd->CmdQLock);
		
		/*RTUSBCMDUp(&pAd->cmdQTask); */
		ret = RtmpOSTaskKill(&pAd->cmdQTask);
		if (ret == NDIS_STATUS_FAILURE)
		{
			DBGPRINT(RT_DEBUG_ERROR, ("Kill command task fail!\n"));
/*			DBGPRINT(RT_DEBUG_ERROR, ("%s: kill task(%s) failed!\n", */
/*					RTMP_OS_NETDEV_GET_DEVNAME(pAd->net_dev), pTask->taskName)); */
		}
		pAd->CmdQ.CmdQState = RTMP_TASK_STAT_UNKNOWN;
	}

#ifdef WSC_INCLUDED
	WscThreadExit(pAd);
#endif /* WSC_INCLUDED */

	return;
}


static inline void rt2860_int_enable(PRTMP_ADAPTER pAd, unsigned int mode)
{
	u32 regValue;

	pAd->int_disable_mask &= ~(mode);
	regValue = pAd->int_enable_reg & ~(pAd->int_disable_mask);		
	/*if (!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_DOZE)) */
	{
		RTMP_IO_WRITE32(pAd, INT_MASK_CSR, regValue);     /* 1:enable */
	}
	/*else */
	/*	DBGPRINT(RT_DEBUG_TRACE, ("fOP_STATUS_DOZE !\n")); */

	if (regValue != 0)
		RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_INTERRUPT_ACTIVE);
}


static inline void rt2860_int_disable(PRTMP_ADAPTER pAd, unsigned int mode)
{
	u32 regValue;

	pAd->int_disable_mask |= mode;
	regValue = 	pAd->int_enable_reg & ~(pAd->int_disable_mask);
	RTMP_IO_WRITE32(pAd, INT_MASK_CSR, regValue);     /* 0: disable */
	
	if (regValue == 0)
	{
		RTMP_CLEAR_FLAG(pAd, fRTMP_ADAPTER_INTERRUPT_ACTIVE);		
	}
}


/***************************************************************************
  *
  *	tasklet related procedures.
  *
  **************************************************************************/
#ifdef WORKQUEUE_BH
static void mgmt_dma_done_workq(struct work_struct *work)
#else
static void mgmt_dma_done_tasklet(unsigned long data)
#endif /* WORKQUEUE_BH */
{
	unsigned long flags;
    INT_SOURCE_CSR_STRUC	IntSource;
#ifdef WORKQUEUE_BH
	POS_COOKIE pObj = container_of(work, struct os_cookie, mgmt_dma_done_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
#else
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	POS_COOKIE pObj;
#endif /* WORKQUEUE_BH */
	
	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_disable_mask &= ~INT_MGMT_DLY;
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
		return;
	}
	
    pObj = (POS_COOKIE) pAd->OS_Cookie;

/*	printk("mgmt_dma_done_process\n"); */
	IntSource.word = 0;
	IntSource.field.MgmtDmaDone = 1;
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	pAd->int_pending &= ~INT_MGMT_DLY;
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	
	RTMPHandleMgmtRingDmaDoneInterrupt(pAd);

	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	/*
	 * double check to avoid lose of interrupts
	 */
	if (pAd->int_pending & INT_MGMT_DLY) 
	{
#ifdef WORKQUEUE_BH
		RTMP_OS_TASKLET_SCHE(&pObj->mgmt_dma_done_work);
#else
		RTMP_OS_TASKLET_SCHE(&pObj->mgmt_dma_done_task);
#endif /* WORKQUEUE_BH */
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
		return;
	}

	/* enable TxDataInt again */
	rt2860_int_enable(pAd, INT_MGMT_DLY);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
}


#ifdef WORKQUEUE_BH
static void rx_done_workq(struct work_struct *work)
#else
static void rx_done_tasklet(unsigned long data)
#endif /* WORKQUEUE_BH */
{
	unsigned long flags;
	BOOLEAN	bReschedule = 0;
#ifdef WORKQUEUE_BH
	POS_COOKIE pObj = container_of(work, struct os_cookie, rx_done_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
#else
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	POS_COOKIE pObj;
#endif /* WORKQUEUE_BH */
	
	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_disable_mask &= ~(INT_RX); 
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
		return;
	}
#ifdef UAPSD_SUPPORT
	UAPSD_TIMING_RECORD(pAd, UAPSD_TIMING_RECORD_TASKLET);
#endif /* UAPSD_SUPPORT */

    pObj = (POS_COOKIE) pAd->OS_Cookie;
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	pAd->int_pending &= ~(INT_RX);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
#ifdef P2P_SUPPORT
           bReschedule = RxDoneInterruptHandle(pAd);
#else  	
#ifdef CONFIG_AP_SUPPORT	
	IF_DEV_CONFIG_OPMODE_ON_AP(pAd)
		bReschedule = APRxDoneInterruptHandle(pAd);
#endif /* CONFIG_AP_SUPPORT */	

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		bReschedule = STARxDoneInterruptHandle(pAd, 0);
#endif /* CONFIG_STA_SUPPORT */
#endif /* P2P_SUPPORT */

#ifdef UAPSD_SUPPORT
	UAPSD_TIMING_RECORD_STOP();
#endif /* UAPSD_SUPPORT */

	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	/*
	 * double check to avoid rotting packet 
	 */
	if (pAd->int_pending & INT_RX || bReschedule) 
	{
#ifdef WORKQUEUE_BH
		RTMP_OS_TASKLET_SCHE(&pObj->rx_done_work);
#else
		RTMP_OS_TASKLET_SCHE(&pObj->rx_done_task);
#endif /* WORKQUEUE_BH */
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
		return;
	}

	/* enable RxINT again */
	rt2860_int_enable(pAd, INT_RX);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);

}

#ifdef WORKQUEUE_BH
void fifo_statistic_full_workq(struct work_struct *work)
#else
void fifo_statistic_full_tasklet(unsigned long data)
#endif /* WORKQUEUE_BH */
{
	unsigned long flags;
#ifdef WORKQUEUE_BH
	POS_COOKIE pObj = container_of(work, struct os_cookie, fifo_statistic_full_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
#else
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	POS_COOKIE pObj;
#endif /* WORKQUEUE_BH */
	
	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	 {
		  RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		  pAd->int_disable_mask &= ~(FifoStaFullInt); 
		  RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
		return;
 	  }
	
    pObj = (POS_COOKIE) pAd->OS_Cookie;

	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	pAd->int_pending &= ~(FifoStaFullInt); 
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	
	NICUpdateFifoStaCounters(pAd);
	
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);  
	/*
	 * double check to avoid rotting packet 
	 */
	if (pAd->int_pending & FifoStaFullInt) 
	{
#ifdef WORKQUEUE_BH
		RTMP_OS_TASKLET_SCHE(&pObj->fifo_statistic_full_work);
#else
		RTMP_OS_TASKLET_SCHE(&pObj->fifo_statistic_full_task);
#endif /* WORKQUEUE_BH */
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
		return;
	}

	/* enable RxINT again */

	rt2860_int_enable(pAd, FifoStaFullInt);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);

}

#ifdef WORKQUEUE_BH
static void hcca_dma_done_workq(struct work_struct *work)
#else
static void hcca_dma_done_tasklet(unsigned long data)
#endif /* WORKQUEUE_BH */
{
	unsigned long flags;
    INT_SOURCE_CSR_STRUC	IntSource;
#ifdef WORKQUEUE_BH
	POS_COOKIE pObj = container_of(work, struct os_cookie, hcca_dma_done_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
#else
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	POS_COOKIE pObj;
#endif /* WORKQUEUE_BH */
	BOOLEAN bReschedule = 0;
	
	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_disable_mask &= ~INT_HCCA_DLY; 
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
		return;
	}
	
    pObj = (POS_COOKIE) pAd->OS_Cookie;


	IntSource.word = 0;
	IntSource.field.HccaDmaDone = 1;
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	pAd->int_pending &= ~INT_HCCA_DLY;

	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	
	bReschedule = RTMPHandleTxRingDmaDoneInterrupt(pAd, IntSource);

	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	/*
	 * double check to avoid lose of interrupts
	 */
	if ((pAd->int_pending & INT_HCCA_DLY) || bReschedule)
	{
#ifdef WORKQUEUE_BH
		RTMP_OS_TASKLET_SCHE(&pObj->hcca_dma_done_work);
#else
		RTMP_OS_TASKLET_SCHE(&pObj->hcca_dma_done_task);
#endif /* WORKQUEUE_BH */
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
		return;
	}

	/* enable TxDataInt again */
	rt2860_int_enable(pAd, INT_HCCA_DLY);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
}

#ifdef WORKQUEUE_BH
static void ac3_dma_done_workq(struct work_struct *work)
#else
static void ac3_dma_done_tasklet(unsigned long data)
#endif /* WORKQUEUE_BH */
{
	unsigned long flags;
    INT_SOURCE_CSR_STRUC	IntSource;
	BOOLEAN bReschedule = 0;
#ifdef WORKQUEUE_BH
	POS_COOKIE pObj = container_of(work, struct os_cookie, ac3_dma_done_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
#else
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	POS_COOKIE pObj;
#endif /* WORKQUEUE_BH */

	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_disable_mask &= ~(INT_AC3_DLY); 
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
		return;
	}
	
    pObj = (POS_COOKIE) pAd->OS_Cookie;

/*	printk("ac0_dma_done_process\n"); */
	IntSource.word = 0;
	IntSource.field.Ac3DmaDone = 1;
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	pAd->int_pending &= ~INT_AC3_DLY;
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);

	bReschedule = RTMPHandleTxRingDmaDoneInterrupt(pAd, IntSource);

	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	/*
	 * double check to avoid lose of interrupts
	 */
	if ((pAd->int_pending & INT_AC3_DLY) || bReschedule)
	{
#ifdef WORKQUEUE_BH
		RTMP_OS_TASKLET_SCHE(&pObj->ac3_dma_done_work);
#else
		RTMP_OS_TASKLET_SCHE(&pObj->ac3_dma_done_task);
#endif /* WORKQUEUE_BH */
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
		return;
	}

	/* enable TxDataInt again */
	rt2860_int_enable(pAd, INT_AC3_DLY);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
}

#ifdef WORKQUEUE_BH
static void ac2_dma_done_workq(struct work_struct *work)
#else
static void ac2_dma_done_tasklet(unsigned long data)
#endif /* WORKQUEUE_BH */
{
	unsigned long flags;
    INT_SOURCE_CSR_STRUC	IntSource;
	BOOLEAN bReschedule = 0;
#ifdef WORKQUEUE_BH
	POS_COOKIE pObj = container_of(work, struct os_cookie, ac2_dma_done_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
#else
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	POS_COOKIE pObj;
#endif /* WORKQUEUE_BH */
	
	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_disable_mask &= ~(INT_AC2_DLY); 
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
		return;
	}
	
    pObj = (POS_COOKIE) pAd->OS_Cookie;

	IntSource.word = 0;
	IntSource.field.Ac2DmaDone = 1;
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	pAd->int_pending &= ~INT_AC2_DLY;
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);

	bReschedule = RTMPHandleTxRingDmaDoneInterrupt(pAd, IntSource);

	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);

	/*
	 * double check to avoid lose of interrupts
	 */
	if ((pAd->int_pending & INT_AC2_DLY) || bReschedule) 
	{
#ifdef WORKQUEUE_BH
		RTMP_OS_TASKLET_SCHE(&pObj->ac2_dma_done_work);
#else
		RTMP_OS_TASKLET_SCHE(&pObj->ac2_dma_done_task);
#endif /* WORKQUEUE_BH */
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
		return;
	}

	/* enable TxDataInt again */
	rt2860_int_enable(pAd, INT_AC2_DLY);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
}

#ifdef WORKQUEUE_BH
static void ac1_dma_done_workq(struct work_struct *work)
#else
static void ac1_dma_done_tasklet(unsigned long data)
#endif /* WORKQUEUE_BH */
{
	unsigned long flags;
	BOOLEAN bReschedule = 0;
    INT_SOURCE_CSR_STRUC	IntSource;
#ifdef WORKQUEUE_BH
	POS_COOKIE pObj = container_of(work, struct os_cookie, ac1_dma_done_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
#else
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	POS_COOKIE pObj;
#endif /* WORKQUEUE_BH */

	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_disable_mask &= ~(INT_AC1_DLY); 
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
		return;
	}
	
    pObj = (POS_COOKIE) pAd->OS_Cookie;

/*	printk("ac0_dma_done_process\n"); */
	IntSource.word = 0;
	IntSource.field.Ac1DmaDone = 1;
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	pAd->int_pending &= ~INT_AC1_DLY;
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);

	bReschedule = RTMPHandleTxRingDmaDoneInterrupt(pAd, IntSource);

	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	/*
	 * double check to avoid lose of interrupts
	 */
	if ((pAd->int_pending & INT_AC1_DLY) || bReschedule) 
	{
#ifdef WORKQUEUE_BH
		RTMP_OS_TASKLET_SCHE(&pObj->ac1_dma_done_work);
#else
		RTMP_OS_TASKLET_SCHE(&pObj->ac1_dma_done_task);
#endif /* WORKQUEUE_BH */

		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
		return;
	}

	/* enable TxDataInt again */
	rt2860_int_enable(pAd, INT_AC1_DLY);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
}

#ifdef WORKQUEUE_BH
static void ac0_dma_done_workq(struct work_struct *work)
#else
static void ac0_dma_done_tasklet(unsigned long data)
#endif /* WORKQUEUE_BH */
{
	unsigned long flags;
	INT_SOURCE_CSR_STRUC	IntSource;
	BOOLEAN bReschedule = 0;
#ifdef WORKQUEUE_BH
	POS_COOKIE pObj = container_of(work, struct os_cookie, ac0_dma_done_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
#else
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	POS_COOKIE pObj;
#endif /* WORKQUEUE_BH */

	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_disable_mask &= ~(INT_AC0_DLY); 
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
		return;
	}
	
	pObj = (POS_COOKIE) pAd->OS_Cookie;

/*	printk("ac0_dma_done_process\n"); */
	IntSource.word = 0;
	IntSource.field.Ac0DmaDone = 1;
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	pAd->int_pending &= ~INT_AC0_DLY;
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);

/*	RTMPHandleMgmtRingDmaDoneInterrupt(pAd); */
	bReschedule = RTMPHandleTxRingDmaDoneInterrupt(pAd, IntSource);
	
	RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
	/*
	 * double check to avoid lose of interrupts
	 */
	if ((pAd->int_pending & INT_AC0_DLY) || bReschedule)
	{
#ifdef WORKQUEUE_BH
		RTMP_OS_TASKLET_SCHE(&pObj->ac0_dma_done_work);
#else
		RTMP_OS_TASKLET_SCHE(&pObj->ac0_dma_done_task);
#endif /* WORKQUEUE_BH */
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
		return;
	}

	/* enable TxDataInt again */
	rt2860_int_enable(pAd, INT_AC0_DLY);
	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);    
}


#ifdef RALINK_ATE
static void ate_ac0_dma_done_tasklet(unsigned long data)
{
	return;
}
#endif /* RALINK_ATE */


#ifdef UAPSD_SUPPORT
/*
========================================================================
Routine Description:
    Used to send the EOSP frame.

Arguments:
    data			Pointer to our adapter

Return Value:
    None

Note:
========================================================================
*/
#ifdef WORKQUEUE_BH
static void uapsd_eosp_sent_workq(struct work_struct *work)
{
	POS_COOKIE pObj = container_of(work, struct os_cookie, uapsd_eosp_sent_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
	
	RTMPDeQueuePacket(pAd, FALSE, NUM_OF_TX_RING, MAX_TX_PROCESS);
}
#else
static void uapsd_eosp_sent_tasklet(unsigned long data)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;

	RTMPDeQueuePacket(pAd, FALSE, NUM_OF_TX_RING, MAX_TX_PROCESS);
}
#endif /* WORKQUEUE_BH */
#endif /* UAPSD_SUPPORT */

#ifdef CONFIG_AP_SUPPORT
#ifdef DFS_SUPPORT
void schedule_dfs_task(PRTMP_ADAPTER pAd)
{
	POS_COOKIE pObj;
	
    pObj = (POS_COOKIE) pAd->OS_Cookie;
#ifdef WORKQUEUE_BH
	RTMP_OS_TASKLET_SCHE(&pObj->dfs_work);
#else
	RTMP_OS_TASKLET_SCHE(&pObj->dfs_task);
#endif /* WORKQUEUE_BH */
}

#ifdef WORKQUEUE_BH
void dfs_workq(struct work_struct *work)
{
	POS_COOKIE pObj = container_of(work, struct os_cookie, dfs_work);
	PRTMP_ADAPTER pAd = pObj->pAd_va;
	PRADAR_DETECT_STRUCT pRadarDetect = &pAd->CommonCfg.RadarDetect;
	PDFS_SW_DETECT_PARAM pDfsSwParam = &pRadarDetect->DfsSwParam;

	if (pRadarDetect->DFSAPRestart == 1)
	{
		int i, j;

		pDfsSwParam->dfs_w_counter += 10;
		/* reset period table */
		for (i = 0; i < pAd->chipCap.DfsEngineNum; i++)
		{
			for (j = 0; j < NEW_DFS_MPERIOD_ENT_NUM; j++)
			{
				pDfsSwParam->DFS_T[i][j].period = 0;
				pDfsSwParam->DFS_T[i][j].idx = 0;
				pDfsSwParam->DFS_T[i][j].idx2 = 0;
			}
		}

		APStop(pAd);
		APStartUp(pAd);
		pRadarDetect->DFSAPRestart = 0;
	}
	else
	/* check radar here */
	{
		int idx;
		if (pRadarDetect->radarDeclared == 0)
		{
			for (idx = 0; idx < 3; idx++)
			{
				if (SWRadarCheck(pAd, idx) == 1)
				{
					/*find the radar signals */
					pRadarDetect->radarDeclared = 1;
					break;
				}
			}
		}
	}
}
#else
void dfs_tasklet(unsigned long data)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER) data;
	PRADAR_DETECT_STRUCT pRadarDetect = &pAd->CommonCfg.RadarDetect;
	PDFS_SW_DETECT_PARAM pDfsSwParam = &pRadarDetect->DfsSwParam;
	
	if (pRadarDetect->DFSAPRestart == 1)
	{
		int i, j;

		pDfsSwParam->dfs_w_counter += 10;
		/* reset period table */
		for (i = 0; i < pAd->chipCap.DfsEngineNum; i++)
		{
			for (j = 0; j < NEW_DFS_MPERIOD_ENT_NUM; j++)
			{
				pDfsSwParam->DFS_T[i][j].period = 0;
				pDfsSwParam->DFS_T[i][j].idx = 0;
				pDfsSwParam->DFS_T[i][j].idx2 = 0;
			}
		}

		APStop(pAd);
		APStartUp(pAd);
		pRadarDetect->DFSAPRestart = 0;
	}
	else
	/* check radar here */
	{
		int idx;
		if (pRadarDetect->radarDeclared == 0)
		{
			for (idx = 0; idx < 3; idx++)
			{
				if (SWRadarCheck(pAd, idx) == 1)
				{
					/*find the radar signals */
					pRadarDetect->radarDeclared = 1;
					break;
				}
			}
		}
	}
}
#endif /* WORKQUEUE_BH */
#endif /* DFS_SUPPORT */
#endif /* CONFIG_AP_SUPPORT */


int print_int_count;

VOID RTMPHandleInterrupt(
	IN	VOID			*pAdSrc)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER)pAdSrc;
	INT_SOURCE_CSR_STRUC	IntSource;
	POS_COOKIE pObj;
	unsigned long flags=0;
	

	pObj = (POS_COOKIE) pAd->OS_Cookie;

	/* Note 03312008: we can not return here before
		RTMP_IO_READ32(pAd, INT_SOURCE_CSR, &IntSource.word);
		RTMP_IO_WRITE32(pAd, INT_SOURCE_CSR, IntSource.word);
		Or kernel will panic after ifconfig ra0 down sometimes */


	/* */
	/* Inital the Interrupt source. */
	/* */
	IntSource.word = 0x00000000L;
/*	McuIntSource.word = 0x00000000L; */

	/* */
	/* Get the interrupt sources & saved to local variable */
	/* */
	/*RTMP_IO_READ32(pAd, where, &McuIntSource.word); */
	/*RTMP_IO_WRITE32(pAd, , McuIntSource.word); */

	/* */
	/* Flag fOP_STATUS_DOZE On, means ASIC put to sleep, elase means ASICK WakeUp */
	/* And at the same time, clock maybe turned off that say there is no DMA service. */
	/* when ASIC get to sleep. */
	/* To prevent system hang on power saving. */
	/* We need to check it before handle the INT_SOURCE_CSR, ASIC must be wake up. */
	/* */
	/* RT2661 => when ASIC is sleeping, MAC register cannot be read and written. */
	/* RT2860 => when ASIC is sleeping, MAC register can be read and written. */
/*	if (!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_DOZE)) */
	{
		RTMP_IO_READ32(pAd, INT_SOURCE_CSR, &IntSource.word);
		RTMP_IO_WRITE32(pAd, INT_SOURCE_CSR, IntSource.word); /* write 1 to clear */
	}
/*	else */
/*		DBGPRINT(RT_DEBUG_TRACE, (">>>fOP_STATUS_DOZE<<<\n")); */

/*	RTMP_IO_READ32(pAd, INT_SOURCE_CSR, &IsrAfterClear); */
/*	RTMP_IO_READ32(pAd, MCU_INT_SOURCE_CSR, &McuIsrAfterClear); */
/*	DBGPRINT(RT_DEBUG_INFO, ("====> RTMPHandleInterrupt(ISR=%08x,Mcu ISR=%08x, After clear ISR=%08x, MCU ISR=%08x)\n", */
/*			IntSource.word, McuIntSource.word, IsrAfterClear, McuIsrAfterClear)); */

	if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_START_UP))
        return;

	/* Do nothing if Reset in progress */
	if (RTMP_TEST_FLAG(pAd, (fRTMP_ADAPTER_RESET_IN_PROGRESS |fRTMP_ADAPTER_HALT_IN_PROGRESS)))
        return;

	/* */
	/* Handle interrupt, walk through all bits */
	/* Should start from highest priority interrupt */
	/* The priority can be adjust by altering processing if statement */
	/* */

#ifdef DBG

#endif
		
#ifdef  INF_VR9_HW_INT_WORKAROUND	
redo: 
#endif 

	pAd->bPCIclkOff = FALSE;

	/* If required spinlock, each interrupt service routine has to acquire */
	/* and release itself. */
	/* */
	
	/* Do nothing if NIC doesn't exist */
	if (IntSource.word == 0xffffffff)
	{
		RTMP_SET_FLAG(pAd, (fRTMP_ADAPTER_NIC_NOT_EXIST | fRTMP_ADAPTER_HALT_IN_PROGRESS));
		return;
	}


	if (IntSource.word & TxCoherent)
	{
		/*
			When the interrupt occurs, it means we kick a register to send
			a packet, such as TX_MGMT CTX_IDX, but MAC finds some fields in
			the transmit buffer descriptor is not correct, ex: all zeros.
		*/
		DBGPRINT(RT_DEBUG_WARN, (">>>TxCoherent<<<\n"));
	}

	if (IntSource.word & RxCoherent)
	{
		DBGPRINT(RT_DEBUG_WARN, (">>>RxCoherent<<<\n"));
	}

	if (IntSource.word & FifoStaFullInt) 
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		if ((pAd->int_disable_mask & FifoStaFullInt) == 0) 
		{
			/* mask FifoStaFullInt */
			rt2860_int_disable(pAd, FifoStaFullInt);
#ifdef WORKQUEUE_BH
			RTMP_OS_TASKLET_SCHE(&pObj->fifo_statistic_full_work);
#else
			RTMP_OS_TASKLET_SCHE(&pObj->fifo_statistic_full_task);
#endif /* WORKQUEUE_BH */
		}
		pAd->int_pending |= FifoStaFullInt; 
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	}

	if (IntSource.word & INT_MGMT_DLY) 
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		if ((pAd->int_disable_mask & INT_MGMT_DLY) ==0 )
		{
			rt2860_int_disable(pAd, INT_MGMT_DLY);
#ifdef WORKQUEUE_BH
			RTMP_OS_TASKLET_SCHE(&pObj->mgmt_dma_done_work);
#else
			RTMP_OS_TASKLET_SCHE(&pObj->mgmt_dma_done_task);			
#endif /* WORKQUEUE_BH */
		}
		pAd->int_pending |= INT_MGMT_DLY ;
        RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	}

	if (IntSource.word & INT_RX)
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		if ((pAd->int_disable_mask & INT_RX) == 0) 
		{
#ifdef UAPSD_SUPPORT
			UAPSD_TIMING_RECORD_START();
			UAPSD_TIMING_RECORD(pAd, UAPSD_TIMING_RECORD_ISR);
#endif /* UAPSD_SUPPORT */

			/* mask RxINT */
			rt2860_int_disable(pAd, INT_RX);
#ifdef WORKQUEUE_BH
			RTMP_OS_TASKLET_SCHE(&pObj->rx_done_work);
#else
			RTMP_OS_TASKLET_SCHE(&pObj->rx_done_task);
#endif /* WORKQUEUE_BH */
		}
		pAd->int_pending |= INT_RX; 		
       	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	}

	if (IntSource.word & INT_HCCA_DLY)
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		if ((pAd->int_disable_mask & INT_HCCA_DLY) == 0) 
		{
			/* mask TxDataInt */
			rt2860_int_disable(pAd, INT_HCCA_DLY);
#ifdef WORKQUEUE_BH
			RTMP_OS_TASKLET_SCHE(&pObj->hcca_dma_done_work);
#else
			RTMP_OS_TASKLET_SCHE(&pObj->hcca_dma_done_task);
#endif /* WORKQUEUE_BH */
		}
		pAd->int_pending |= INT_HCCA_DLY;						
        RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	}

	if (IntSource.word & INT_AC3_DLY)
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		if ((pAd->int_disable_mask & INT_AC3_DLY) == 0) 
		{
			/* mask TxDataInt */
			rt2860_int_disable(pAd, INT_AC3_DLY);
#ifdef WORKQUEUE_BH
			RTMP_OS_TASKLET_SCHE(&pObj->ac3_dma_done_work);
#else
			RTMP_OS_TASKLET_SCHE(&pObj->ac3_dma_done_task);
#endif /* WORKQUEUE_BH */
		}
		pAd->int_pending |= INT_AC3_DLY;						
       	RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	}

	if (IntSource.word & INT_AC2_DLY)
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		if ((pAd->int_disable_mask & INT_AC2_DLY) == 0) 
		{
			/* mask TxDataInt */
			rt2860_int_disable(pAd, INT_AC2_DLY);
#ifdef WORKQUEUE_BH
			RTMP_OS_TASKLET_SCHE(&pObj->ac2_dma_done_work);
#else
			RTMP_OS_TASKLET_SCHE(&pObj->ac2_dma_done_task);
#endif /* WORKQUEUE_BH */
		}
		pAd->int_pending |= INT_AC2_DLY;						
        RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	}

	if (IntSource.word & INT_AC1_DLY)
	{
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_pending |= INT_AC1_DLY;						

		if ((pAd->int_disable_mask & INT_AC1_DLY) == 0) 
		{
			/* mask TxDataInt */
			rt2860_int_disable(pAd, INT_AC1_DLY);
#ifdef WORKQUEUE_BH
			RTMP_OS_TASKLET_SCHE(&pObj->ac1_dma_done_work);		
#else
			RTMP_OS_TASKLET_SCHE(&pObj->ac1_dma_done_task);
#endif /* WORKQUEUE_BH */
		}
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	}

	if (IntSource.word & INT_AC0_DLY)
	{

/*
		if (IntSource.word & 0x2) {
			u32 reg;
			RTMP_IO_READ32(pAd, DELAY_INT_CFG, &reg);
			printk("IntSource = %08x, DELAY_REG = %08x\n", IntSource.word, reg);
		}
*/
		RTMP_INT_LOCK(&pAd->LockInterrupt, flags);
		pAd->int_pending |= INT_AC0_DLY;

		if ((pAd->int_disable_mask & INT_AC0_DLY) == 0) 
		{
			/* mask TxDataInt */
			rt2860_int_disable(pAd, INT_AC0_DLY);
#ifdef WORKQUEUE_BH
			RTMP_OS_TASKLET_SCHE(&pObj->ac0_dma_done_work);
#else
			RTMP_OS_TASKLET_SCHE(&pObj->ac0_dma_done_task);
#endif /* WORKQUEUE_BH */
		}
		RTMP_INT_UNLOCK(&pAd->LockInterrupt, flags);
	}

	if (IntSource.word & PreTBTTInt)
	{
		RTMPHandlePreTBTTInterrupt(pAd);
	}

	if (IntSource.word & TBTTInt)
	{
		RTMPHandleTBTTInterrupt(pAd);
	}

#ifdef CONFIG_AP_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_AP(pAd)
	{
#ifdef DFS_SUPPORT
		if (IntSource.word & GPTimeOutInt)
		{
		      NewTimerCB_Radar(pAd);
		}
#endif /* DFS_SUPPORT */

#ifdef CARRIER_DETECTION_SUPPORT
		if ((IntSource.word & INT_TONE_RADAR))
		{
			if (pAd->CommonCfg.CarrierDetect.Enable == TRUE)
				RTMPHandleRadarInterrupt(pAd);
		}
#endif /* CARRIER_DETECTION_SUPPORT*/

		if (IntSource.word & McuCommand)
		{
			/*RTMPHandleMcuInterrupt(pAd);*/
		}
	}

#endif /* CONFIG_AP_SUPPORT */


#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		if (IntSource.word & AutoWakeupInt)
			RTMPHandleTwakeupInterrupt(pAd);
	}
#endif /* CONFIG_STA_SUPPORT */

#ifdef  INF_VR9_HW_INT_WORKAROUND
	/*
		We found the VR9 Demo board provide from Lantiq at 2010.3.8 will miss interrup sometime caused of Rx-Ring Full
		and our driver no longer receive any packet after the interrupt missing.
		Below patch was recommand by Lantiq for temp workaround.
		And shall be remove in next VR9 platform.
	*/
	IntSource.word = 0x00000000L;
	{
		RTMP_IO_READ32(pAd, INT_SOURCE_CSR, &IntSource.word);
		RTMP_IO_WRITE32(pAd, INT_SOURCE_CSR, IntSource.word); /* write 1 to clear */
	}	
	if (IntSource.word != 0) 
	{		
		goto redo;
	}	
#endif
	return;
}


/*
========================================================================
Routine Description:
    PCI command kernel thread.

Arguments:
	*Context			the pAd, driver control block pointer

Return Value:
    0					close the thread

Note:
========================================================================
*/
INT RTPCICmdThread(
	IN ULONG Context)
{
	RTMP_ADAPTER *pAd;
	RTMP_OS_TASK *pTask;
	int status;
	status = 0;

	pTask = (RTMP_OS_TASK *)Context;
	pAd = (PRTMP_ADAPTER)RTMP_OS_TASK_DATA_GET(pTask);
	
	RtmpOSTaskCustomize(pTask);

	NdisAcquireSpinLock(&pAd->CmdQLock);
	pAd->CmdQ.CmdQState = RTMP_TASK_STAT_RUNNING;
	NdisReleaseSpinLock(&pAd->CmdQLock);

	while (pAd->CmdQ.CmdQState == RTMP_TASK_STAT_RUNNING)
	{
		if (RtmpOSTaskWait(pAd, pTask, &status) == FALSE)
		{
			RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS);
			break;
		}

		if (pAd->CmdQ.CmdQState == RTMP_TASK_STAT_STOPED)
			break;

		if (!pAd->PM_FlgSuspend)
			CMDHandler(pAd);
	}

	if (!pAd->PM_FlgSuspend)
	{	/* Clear the CmdQElements. */
		CmdQElmt	*pCmdQElmt = NULL;

		NdisAcquireSpinLock(&pAd->CmdQLock);
		pAd->CmdQ.CmdQState = RTMP_TASK_STAT_STOPED;
		while(pAd->CmdQ.size)
		{
			RTThreadDequeueCmd(&pAd->CmdQ, &pCmdQElmt);
			if (pCmdQElmt)
			{
				if (pCmdQElmt->CmdFromNdis == TRUE)
				{
					if (pCmdQElmt->buffer != NULL)
						os_free_mem(pAd, pCmdQElmt->buffer);
					os_free_mem(pAd, (PUCHAR)pCmdQElmt);
				}
				else
				{
					if ((pCmdQElmt->buffer != NULL) && (pCmdQElmt->bufferlength != 0))
						os_free_mem(pAd, pCmdQElmt->buffer);
					os_free_mem(pAd, (PUCHAR)pCmdQElmt);
				}
			}
		}

		NdisReleaseSpinLock(&pAd->CmdQLock);
	}
	/* notify the exit routine that we're actually exiting now 
	 *
	 * complete()/wait_for_completion() is similar to up()/down(),
	 * except that complete() is safe in the case where the structure
	 * is getting deleted in a parallel mode of execution (i.e. just
	 * after the down() -- that's necessary for the thread-shutdown
	 * case.
	 *
	 * complete_and_exit() goes even further than this -- it is safe in
	 * the case that the thread of the caller is going away (not just
	 * the structure) -- this is necessary for the module-remove case.
	 * This is important in preemption kernels, which transfer the flow
	 * of execution immediately upon a complete().
	 */
	DBGPRINT(RT_DEBUG_TRACE,( "<---RTPCICmdThread\n"));

	RtmpOSTaskNotifyToExit(pTask);
	return 0;

}


#ifdef CONFIG_STA_SUPPORT
#ifdef PCIE_PS_SUPPORT
/*
	========================================================================
	
	Routine Description:

	Arguments:
		Level = RESTORE_HALT : Restore PCI host and Ralink PCIe Link Control field to its default value.
		Level = Other Value : Restore from dot11 power save or radio off status. And force PCI host Link Control fields to 0x1

	========================================================================
*/
VOID RTMPPCIeLinkCtrlValueRestore(
	IN	PRTMP_ADAPTER	pAd,
	IN   UCHAR		Level)
{
	USHORT  PCIePowerSaveLevel, reg16;
	USHORT	Configuration;
	POS_COOKIE 	pObj;

	pObj = (POS_COOKIE) pAd->OS_Cookie;

	if (!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_ADVANCE_POWER_SAVE_PCIE_DEVICE))
		return;

	/* Check PSControl Configuration */
	if (pAd->StaCfg.PSControl.field.EnableNewPS == FALSE)
		return;

	/*3090 will not execute the following codes. */
    	/* Check interface : If not PCIe interface, return. */
#ifdef RT2860
	if (!((pObj->DeviceID == NIC2860_PCIe_DEVICE_ID) 
		||(pObj->DeviceID == NIC2790_PCIe_DEVICE_ID)))
		return;
#endif /* RT2860 */


	if (RT3593_DEVICE_ID_CHECK(pObj->DeviceID))
		return;


#ifdef RT3590
	if ((pObj->DeviceID == NIC3590_PCIe_DEVICE_ID) 
		||(pObj->DeviceID == NIC3591_PCIe_DEVICE_ID)
		||(pObj->DeviceID == NIC3592_PCIe_DEVICE_ID))
		return;
#endif /* RT3390 */

	DBGPRINT(RT_DEBUG_TRACE, ("%s.===>\n", __FUNCTION__));
	PCIePowerSaveLevel = pAd->PCIePowerSaveLevel;
	if ((PCIePowerSaveLevel&0xff) == 0xff)
	{
		DBGPRINT(RT_DEBUG_TRACE,("return  \n"));
		return;
	}

	if (pObj->parent_pci_dev && (pAd->HostLnkCtrlOffset != 0))
    {
        PCI_REG_READ_WORD(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, Configuration);
        if ((Configuration != 0) &&
            (Configuration != 0xFFFF))
        {
    		Configuration &= 0xfefc;
    		/* If call from interface down, restore to orginial setting. */
    		if (Level == RESTORE_CLOSE)
    		{
    			Configuration |= pAd->HostLnkCtrlConfiguration;
    		}
    		else
    			Configuration |= 0x0;
            PCI_REG_WIRTE_WORD(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, Configuration);
    		DBGPRINT(RT_DEBUG_TRACE, ("Restore PCI host : offset 0x%x = 0x%x\n", pAd->HostLnkCtrlOffset, Configuration));
        }
        else
            DBGPRINT(RT_DEBUG_ERROR, ("Restore PCI host : PCI_REG_READ_WORD failed (Configuration = 0x%x)\n", Configuration));
    }
	
    if (pObj->pci_dev && (pAd->RLnkCtrlOffset != 0))
    {           
        PCI_REG_READ_WORD(pObj->pci_dev, pAd->RLnkCtrlOffset, Configuration);
        if ((Configuration != 0) &&
            (Configuration != 0xFFFF))
        {
    		Configuration &= 0xfefc;
			/* If call from interface down, restore to orginial setting. */
			if (Level == RESTORE_CLOSE)
            	Configuration |= pAd->RLnkCtrlConfiguration;
			else
				Configuration |= 0x0;
            PCI_REG_WIRTE_WORD(pObj->pci_dev, pAd->RLnkCtrlOffset, Configuration);
    		DBGPRINT(RT_DEBUG_TRACE, ("Restore Ralink : offset 0x%x = 0x%x\n", pAd->RLnkCtrlOffset, Configuration));
        }
        else
            DBGPRINT(RT_DEBUG_ERROR, ("Restore Ralink : PCI_REG_READ_WORD failed (Configuration = 0x%x)\n", Configuration));
	}
    
	DBGPRINT(RT_DEBUG_TRACE,("%s <===\n", __FUNCTION__));
}

/*
	========================================================================
	
	Routine Description:

	Arguments:
		Max : limit Host PCI and Ralink PCIe device's LINK CONTROL field's value. 
		Because now frequently set our device to mode 1 or mode 3 will cause problem.
		
	========================================================================
*/
VOID RTMPPCIeLinkCtrlSetting(
	IN	PRTMP_ADAPTER	pAd,
	IN 	USHORT		Max)
{
	USHORT  PCIePowerSaveLevel, reg16;
	USHORT	Configuration;
	POS_COOKIE 	pObj;

	pObj = (POS_COOKIE) pAd->OS_Cookie;

	if (!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_ADVANCE_POWER_SAVE_PCIE_DEVICE))
		return;

	/* Check PSControl Configuration */
	if (pAd->StaCfg.PSControl.field.EnableNewPS == FALSE)
		return;

	/* Check interface : If not PCIe interface, return. */
	/*Block 3090 to enter the following function */
	
#ifdef RT2860
	if (!((pObj->DeviceID == NIC2860_PCIe_DEVICE_ID) 
		||(pObj->DeviceID == NIC2790_PCIe_DEVICE_ID)))
		return;
#endif /* RT2860 */

	if (RT3593_DEVICE_ID_CHECK(pObj->DeviceID))
		return;

	if (!RTMP_TEST_PSFLAG(pAd, fRTMP_PS_CAN_GO_SLEEP))
	{
		DBGPRINT(RT_DEBUG_INFO, ("RTMPPCIePowerLinkCtrl return on fRTMP_PS_CAN_GO_SLEEP flag\n"));			
		return;
	}
	DBGPRINT(RT_DEBUG_TRACE,("%s===>\n", __FUNCTION__));
	PCIePowerSaveLevel = pAd->PCIePowerSaveLevel;
	if ((PCIePowerSaveLevel&0xff) == 0xff)
	{
		DBGPRINT(RT_DEBUG_TRACE,("return  \n"));
		return;
	}
	PCIePowerSaveLevel = PCIePowerSaveLevel>>6;	    

    /* Skip non-exist deice right away */
	if (pObj->parent_pci_dev && (pAd->HostLnkCtrlOffset != 0))
	{
        PCI_REG_READ_WORD(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, Configuration);
		switch (PCIePowerSaveLevel)
		{
			case 0:
				/* Set b0 and b1 of LinkControl (both 2892 and PCIe bridge) to 00 */
				Configuration &= 0xfefc;
				break;
			case 1:
				/* Set b0 and b1 of LinkControl (both 2892 and PCIe bridge) to 01 */
				Configuration &= 0xfefc;
				Configuration |= 0x1;
				break;
			case 2:
				/*  Set b0 and b1 of LinkControl (both 2892 and PCIe bridge) to 11 */
				Configuration &= 0xfefc;
				Configuration |= 0x3;
				break;
			case 3:
				/* Set b0 and b1 of LinkControl (both 2892 and PCIe bridge) to 11 and bit 8 of LinkControl of 2892 to 1 */
				Configuration &= 0xfefc;
				Configuration |= 0x103;				
				break;
		}
        PCI_REG_WIRTE_WORD(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, Configuration);
		DBGPRINT(RT_DEBUG_TRACE, ("Write PCI host offset 0x%x = 0x%x\n", pAd->HostLnkCtrlOffset, Configuration));
	}

	if (pObj->pci_dev && (pAd->RLnkCtrlOffset != 0))
	{
		/* first 2892 chip not allow to frequently set mode 3. will cause hang problem. */
		if (PCIePowerSaveLevel > Max)
			PCIePowerSaveLevel = Max;        

        PCI_REG_READ_WORD(pObj->pci_dev, pAd->RLnkCtrlOffset, Configuration);
		Configuration |= 0x100;
        PCI_REG_WIRTE_WORD(pObj->pci_dev, pAd->RLnkCtrlOffset, Configuration);
		DBGPRINT(RT_DEBUG_TRACE, ("Write Ralink device : offset 0x%x = 0x%x\n", pAd->RLnkCtrlOffset, Configuration));
	}

	DBGPRINT(RT_DEBUG_TRACE,("RTMPPCIePowerLinkCtrl <==============\n"));
}
#endif /* PCIE_PS_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */


/***************************************************************************
 *
 *	PCIe device initialization related procedures.
 *
 ***************************************************************************/
VOID RTMPInitPCIeDevice(
    IN	RT_CMD_PCIE_INIT	*pConfig,
    IN	VOID				*pAdSrc)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER)pAdSrc;
	VOID *pci_dev = pConfig->pPciDev;
	USHORT  device_id;
	POS_COOKIE pObj;

	pObj = (POS_COOKIE) pAd->OS_Cookie;
	pci_read_config_word(pci_dev, pConfig->ConfigDeviceID, &device_id);
	device_id = le2cpu16(device_id);
	pObj->DeviceID = device_id;

	OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_ADVANCE_POWER_SAVE_PCIE_DEVICE);
	if (
#ifdef RT2860
		(device_id == NIC2860_PCIe_DEVICE_ID) || 
		(device_id == NIC2790_PCIe_DEVICE_ID) ||
		(device_id == VEN_AWT_PCIe_DEVICE_ID) ||
#endif /* RT2860 */
	(RT3593_DEVICE_ID_CHECK(device_id))||
	(RT3592_DEVICE_ID_CHECK(device_id))||
		 0)
	{
		UINT32 MacCsr0 = 0;//, Index= 0;
		WaitForAsicReady(pAd);
		RTMP_IO_READ32(pAd, MAC_CSR0, &MacCsr0);

#ifdef CONFIG_STA_SUPPORT
		pAd->chipCap.HW_PCIE_PS_SUPPORT=FALSE;

		if  (
		RT3593_DEVICE_ID_CHECK(device_id)||
	 	0)
		{
			/*Support HW new PCIe power-saving. */
			DBGPRINT(RT_DEBUG_TRACE, ("RTMPInitPCIeDevice::STA Support HW PCIe Power Saving\n"));			
			pAd->chipCap.HW_PCIE_PS_SUPPORT=TRUE;
		}
#endif /* CONFIG_STA_SUPPORT */

		/* Support advanced power save after 2892/2790. */
		/* MAC version at offset 0x1000 is 0x2872XXXX/0x2870XXXX(PCIe, USB, SDIO). */
		if ((MacCsr0&0xffff0000) != 0x28600000)
		{
#ifdef PCIE_PS_SUPPORT			
			OPSTATUS_SET_FLAG(pAd, fOP_STATUS_ADVANCE_POWER_SAVE_PCIE_DEVICE);
#endif /* PCIE_PS_SUPPORT */
			RtmpRaDevCtrlInit(pAd, RTMP_DEV_INF_PCIE);
			return;
		}
		

	}
	RtmpRaDevCtrlInit(pAd, RTMP_DEV_INF_PCI);

}


#ifdef CONFIG_STA_SUPPORT
#ifdef PCIE_PS_SUPPORT
VOID RTMPInitPCIeLinkCtrlValue(
	IN	PRTMP_ADAPTER	pAd)
{
    INT     pos;
    USHORT	reg16, data2, PCIePowerSaveLevel, Configuration;
	UINT32 MacValue;
    BOOLEAN	bFindIntel = FALSE;
	POS_COOKIE pObj;

	pObj = (POS_COOKIE) pAd->OS_Cookie;

	if (!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_ADVANCE_POWER_SAVE_PCIE_DEVICE))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("Not PCIe device.\n"));
		return;
	}

    DBGPRINT(RT_DEBUG_TRACE, ("%s.===>\n", __FUNCTION__));
	/* Init EEPROM, and save settings */
	if (!(IS_RT3090(pAd) || IS_RT3572(pAd) || IS_RT3390(pAd) ||
		IS_RT3593(pAd) || IS_RT5390(pAd) || IS_RT5392(pAd) || IS_RT5592(pAd)))
	{
		RT28xx_EEPROM_READ16(pAd, 0x22, PCIePowerSaveLevel);
		pAd->PCIePowerSaveLevel = PCIePowerSaveLevel & 0xff;
		pAd->LnkCtrlBitMask = 0;
		if ((PCIePowerSaveLevel&0xff) == 0xff)
		{
			OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_ADVANCE_POWER_SAVE_PCIE_DEVICE);
			DBGPRINT(RT_DEBUG_TRACE, ("====> PCIePowerSaveLevel = 0x%x.\n", PCIePowerSaveLevel));
			return;
		}
		else
		{
			PCIePowerSaveLevel &= 0x3;
			RT28xx_EEPROM_READ16(pAd, 0x24, data2);

			if( !(((data2&0xff00) == 0x9200) && ((data2&0x80) !=0)) )
			{
				if (PCIePowerSaveLevel > 1 ) 
					PCIePowerSaveLevel = 1;
			}

			DBGPRINT(RT_DEBUG_TRACE, ("====> Write 0x83 = 0x%x.\n", PCIePowerSaveLevel));
			AsicSendCommandToMcu(pAd, 0x83, 0xff, (UCHAR)PCIePowerSaveLevel, 0x00, FALSE);
			RT28xx_EEPROM_READ16(pAd, 0x22, PCIePowerSaveLevel);
			PCIePowerSaveLevel &= 0xff;
			PCIePowerSaveLevel = PCIePowerSaveLevel >> 6;
			switch(PCIePowerSaveLevel)
			{
					case 0:	/* Only support L0 */
						pAd->LnkCtrlBitMask = 0;
					break;
					case 1:	/* Only enable L0s */
						pAd->LnkCtrlBitMask = 1;
					break;
					case 2:	/* enable L1, L0s */
						pAd->LnkCtrlBitMask = 3;
					break;
					case 3:	/* sync with host clk and enable L1, L0s */
					pAd->LnkCtrlBitMask = 0x103;
					break;
			}
					RT28xx_EEPROM_READ16(pAd, 0x24, data2);
					if ((PCIePowerSaveLevel&0xff) != 0xff)
					{
						PCIePowerSaveLevel &= 0x3;

						if( !(((data2&0xff00) == 0x9200) && ((data2&0x80) !=0)) )
						{
							if (PCIePowerSaveLevel > 1 ) 
								PCIePowerSaveLevel = 1;
						}

						DBGPRINT(RT_DEBUG_TRACE, ("====> rt28xx Write 0x83 Command = 0x%x.\n", PCIePowerSaveLevel));
							       printk("\n\n\n%s:%d\n",__FUNCTION__,__LINE__);

						AsicSendCommandToMcu(pAd, 0x83, 0xff, (UCHAR)PCIePowerSaveLevel, 0x00, FALSE);
					}
			DBGPRINT(RT_DEBUG_TRACE, ("====> LnkCtrlBitMask = 0x%x.\n", pAd->LnkCtrlBitMask));
		}   
		}
		else if (IS_RT3090(pAd) || IS_RT3572(pAd) || IS_RT3390(pAd) ||
				IS_RT3593(pAd) || IS_RT5390(pAd) || IS_RT5392(pAd) ||
				IS_RT5592(pAd))
		{
			UCHAR	LinkCtrlSetting = 0;

			/* Check 3090E special setting chip. */
				RT28xx_EEPROM_READ16(pAd, 0x24, data2);
			if ((data2 == 0x9280) && ((pAd->MACVersion&0xffff) == 0x0211))
			{
				pAd->b3090ESpecialChip = TRUE;
				DBGPRINT_RAW(RT_DEBUG_ERROR,("Special 3090E chip \n"));
			}
			
			RTMP_IO_READ32(pAd, AUX_CTRL, &MacValue);
			/*enable WAKE_PCIE function, which forces to enable PCIE clock when mpu interrupt asserting. */
			/*Force PCIE 125MHz CLK to toggle */
			MacValue |= 0x402;
			RTMP_IO_WRITE32(pAd, AUX_CTRL, MacValue);
			DBGPRINT_RAW(RT_DEBUG_ERROR,(" AUX_CTRL = 0x%32x\n", MacValue));

			

			/* for RT30xx F and after, PCIe infterface, and for power solution 3 */
			if ((IS_VERSION_AFTER_F(pAd)) 
				&& (pAd->StaCfg.PSControl.field.rt30xxPowerMode >= 2)
				&& (pAd->StaCfg.PSControl.field.rt30xxPowerMode <= 3))
			{
				RTMP_IO_READ32(pAd, AUX_CTRL, &MacValue);
				DBGPRINT_RAW(RT_DEBUG_ERROR,(" Read AUX_CTRL = 0x%x\n", MacValue));
				/* turn on bit 12. */
				/*enable 32KHz clock mode for power saving */
				MacValue |= 0x1000;
				if (MacValue != 0xffffffff)
				{
					RTMP_IO_WRITE32(pAd, AUX_CTRL, MacValue);
					DBGPRINT_RAW(RT_DEBUG_ERROR,(" Write AUX_CTRL = 0x%x\n", MacValue));
					/* 1. if use PCIePowerSetting is 2 or 3, need to program OSC_CTRL to 0x3ff11. */
					MacValue = 0x3ff11;
					RTMP_IO_WRITE32(pAd, OSC_CTRL, MacValue);
					DBGPRINT_RAW(RT_DEBUG_ERROR,(" OSC_CTRL = 0x%x\n", MacValue));
					/* 2. Write PCI register Clk ref bit */
					RTMPrt3xSetPCIePowerLinkCtrl(pAd);
				}
				else
		{
					/* Error read Aux_Ctrl value.  Force to use solution 1 */
					DBGPRINT(RT_DEBUG_ERROR,(" Error Value in AUX_CTRL = 0x%x\n", MacValue));
					pAd->StaCfg.PSControl.field.rt30xxPowerMode = 1;
					DBGPRINT(RT_DEBUG_ERROR,(" Force to use power solution1 \n"));
				}
			}
			/* 1. read setting from inf file. */
			
			PCIePowerSaveLevel = (USHORT)pAd->StaCfg.PSControl.field.rt30xxPowerMode;
			DBGPRINT(RT_DEBUG_ERROR, ("====> rt30xx Read PowerLevelMode =  0x%x.\n", PCIePowerSaveLevel));
			/* 2. Check EnableNewPS. */
			if (pAd->StaCfg.PSControl.field.EnableNewPS == FALSE)
				PCIePowerSaveLevel = 1;

			if (IS_VERSION_BEFORE_F(pAd) && (pAd->b3090ESpecialChip == FALSE))
			{
				/* Chip Version E only allow 1, So force set 1. */
				PCIePowerSaveLevel &= 0x1;
				pAd->PCIePowerSaveLevel = (USHORT)PCIePowerSaveLevel;
				DBGPRINT(RT_DEBUG_TRACE, ("====> rt30xx E Write 0x83 Command = 0x%x.\n", PCIePowerSaveLevel));

				AsicSendCommandToMcu(pAd, 0x83, 0xff, (UCHAR)PCIePowerSaveLevel, 0x00, FALSE);
			}
			else
			{
				/* Chip Version F and after only allow 1 or 2 or 3. This might be modified after new chip version come out. */
				if (!((PCIePowerSaveLevel == 1) || (PCIePowerSaveLevel == 3)))
					PCIePowerSaveLevel = 1;
				DBGPRINT(RT_DEBUG_ERROR, ("====> rt30xx F Write 0x83 Command = 0x%x.\n", PCIePowerSaveLevel));
				pAd->PCIePowerSaveLevel = (USHORT)PCIePowerSaveLevel;
				/* for 3090F , we need to add high-byte arg for 0x83 command to indicate the link control setting in */
				/* PCI Configuration Space. Because firmware can't read PCI Configuration Space */
				if ((pAd->Rt3xxRalinkLinkCtrl & 0x2) && (pAd->Rt3xxHostLinkCtrl & 0x2))
				{
					LinkCtrlSetting = 1;
				}
				DBGPRINT(RT_DEBUG_TRACE, ("====> rt30xxF LinkCtrlSetting = 0x%x.\n", LinkCtrlSetting));
				AsicSendCommandToMcu(pAd, 0x83, 0xff, (UCHAR)PCIePowerSaveLevel, LinkCtrlSetting, FALSE);
			}
	  
		}
    
    /* Find Ralink PCIe Device's Express Capability Offset */
	pos = pci_find_capability(pObj->pci_dev, PCI_CAP_ID_EXP);

    if (pos != 0)
    {
        /* Ralink PCIe Device's Link Control Register Offset */
        pAd->RLnkCtrlOffset = pos + PCI_EXP_LNKCTL;
    	pci_read_config_word(pObj->pci_dev, pAd->RLnkCtrlOffset, &reg16);
        Configuration = le2cpu16(reg16);
        DBGPRINT(RT_DEBUG_TRACE, ("Read (Ralink PCIe Link Control Register) offset 0x%x = 0x%x\n", 
                                    pAd->RLnkCtrlOffset, Configuration));
        pAd->RLnkCtrlConfiguration = (Configuration & 0x103);
        Configuration &= 0xfefc;
        Configuration |= (0x0);
#ifdef RT2860
		if ((pObj->DeviceID == NIC2860_PCIe_DEVICE_ID) 
			||(pObj->DeviceID == NIC2790_PCIe_DEVICE_ID))
		{
			reg16 = cpu2le16(Configuration);
			pci_write_config_word(pObj->pci_dev, pAd->RLnkCtrlOffset, reg16);
			DBGPRINT(RT_DEBUG_TRACE, ("Write (Ralink PCIe Link Control Register)  offset 0x%x = 0x%x\n", 
                                    pos + PCI_EXP_LNKCTL, Configuration));
		}
#endif /* RT2860 */

        pObj->parent_pci_dev = RTMPFindHostPCIDev(pObj->pci_dev);
        if (pObj->parent_pci_dev)
        {
		USHORT  vendor_id;

		pci_read_config_word(pObj->parent_pci_dev, RTMP_OS_PCI_VENDOR_ID, &vendor_id);
		vendor_id = le2cpu16(vendor_id);
		if (vendor_id == PCIBUS_INTEL_VENDOR)
                 {
			bFindIntel = TRUE;
                        RTMP_SET_PSFLAG(pAd, fRTMP_PS_TOGGLE_L1);
                 }
		/* Find PCI-to-PCI Bridge Express Capability Offset */
		pos = pci_find_capability(pObj->parent_pci_dev, PCI_CAP_ID_EXP);

		if (pos != 0)
		{
			BOOLEAN		bChange = FALSE;
			/* PCI-to-PCI Bridge Link Control Register Offset */
			pAd->HostLnkCtrlOffset = pos + PCI_EXP_LNKCTL;
			pci_read_config_word(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, &reg16);    
			Configuration = le2cpu16(reg16);
			DBGPRINT(RT_DEBUG_TRACE, ("Read (Host PCI-to-PCI Bridge Link Control Register) offset 0x%x = 0x%x\n", 
			                            pAd->HostLnkCtrlOffset, Configuration));    
			pAd->HostLnkCtrlConfiguration = (Configuration & 0x103);
			Configuration &= 0xfefc;
			Configuration |= (0x0);
			
			switch (pObj->DeviceID)
			{
#ifdef RT2860
				case NIC2860_PCIe_DEVICE_ID:
				case NIC2790_PCIe_DEVICE_ID:
					bChange = TRUE;
					break;
#endif /* RT2860 */

				default:
					break;
			}
				
			if (bChange)
			{
				reg16 = cpu2le16(Configuration);
				pci_write_config_word(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, reg16);
				DBGPRINT(RT_DEBUG_TRACE, ("Write (Host PCI-to-PCI Bridge Link Control Register) offset 0x%x = 0x%x\n", 
						pAd->HostLnkCtrlOffset, Configuration));
			}
		}
		else
		{
			pAd->HostLnkCtrlOffset = 0;
			DBGPRINT(RT_DEBUG_ERROR, ("%s: cannot find PCI-to-PCI Bridge PCI Express Capability!\n", __FUNCTION__));
		}
        }
    }
    else
    {
        pAd->RLnkCtrlOffset = 0;
        pAd->HostLnkCtrlOffset = 0;
        DBGPRINT(RT_DEBUG_ERROR, ("%s: cannot find Ralink PCIe Device's PCI Express Capability!\n", __FUNCTION__));
    }

    if (bFindIntel == FALSE)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("Doesn't find Intel PCI host controller. \n"));
		/* Doesn't switch L0, L1, So set PCIePowerSaveLevel to 0xff */
		pAd->PCIePowerSaveLevel = 0xff;
		/* RT3090 will no co-existence with RT3593 */
		if ((pAd->RLnkCtrlOffset != 0)&&(pAd->chipCap.HW_PCIE_PS_SUPPORT==TRUE))
		{
			pci_read_config_word(pObj->pci_dev, pAd->RLnkCtrlOffset, &reg16);
			Configuration = le2cpu16(reg16);
			DBGPRINT(RT_DEBUG_TRACE, ("Read (Ralink 30xx PCIe Link Control Register) offset 0x%x = 0x%x\n", 
			                        pAd->RLnkCtrlOffset, Configuration));
			pAd->RLnkCtrlConfiguration = (Configuration & 0x103);
			Configuration &= 0xfefc;
			Configuration |= (0x0);
			reg16 = cpu2le16(Configuration);
			pci_write_config_word(pObj->pci_dev, pAd->RLnkCtrlOffset, reg16);
			DBGPRINT(RT_DEBUG_TRACE, ("Write (Ralink PCIe Link Control Register)  offset 0x%x = 0x%x\n", 
			                        pos + PCI_EXP_LNKCTL, Configuration));
		}
	}
}

/*
	========================================================================
	
	Routine Description:
		1. Write a PCI register for rt30xx power solution 3

	========================================================================
*/
VOID RTMPrt3xSetPCIePowerLinkCtrl(
	IN	PRTMP_ADAPTER	pAd)
{
	
	ULONG	HostConfiguration = 0;
	ULONG	Configuration;
/*
	ULONG	Vendor;
	ULONG	offset;
*/
	POS_COOKIE 	pObj;
	INT     pos;
    	USHORT	reg16;

	pObj = (POS_COOKIE) pAd->OS_Cookie;

	DBGPRINT(RT_DEBUG_INFO, ("RTMPrt3xSetPCIePowerLinkCtrl.===> %x\n", (UINT)pAd->StaCfg.PSControl.word));
	
	/* Check PSControl Configuration */
	if (pAd->StaCfg.PSControl.field.EnableNewPS == FALSE)
		return;
	pObj->parent_pci_dev = RTMPFindHostPCIDev(pObj->pci_dev);
        if (pObj->parent_pci_dev)
        {

		/* Find PCI-to-PCI Bridge Express Capability Offset */
		pos = pci_find_capability(pObj->parent_pci_dev, PCI_CAP_ID_EXP);

		if (pos != 0)
		{
			pAd->HostLnkCtrlOffset = pos + PCI_EXP_LNKCTL;
		}
	/* If configurared to turn on L1. */
	HostConfiguration = 0;
		if (pAd->StaCfg.PSControl.field.rt30xxForceASPMTest == 1)
		{
						DBGPRINT(RT_DEBUG_TRACE, ("Enter,PSM : Force ASPM \n"));
	
			/* Skip non-exist deice right away */
			if ((pAd->HostLnkCtrlOffset != 0))
			{
	       		 PCI_REG_READ_WORD(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, HostConfiguration);
				/* Prepare Configuration to write to Host */
				HostConfiguration |= 0x3;
	        		PCI_REG_WIRTE_WORD(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, HostConfiguration);
				pAd->Rt3xxHostLinkCtrl = HostConfiguration;
				/* Because in rt30xxForceASPMTest Mode, Force turn on L0s, L1. */
				/* Fix HostConfiguration bit0:1 = 0x3 for later use. */
				HostConfiguration = 0x3;
				DBGPRINT(RT_DEBUG_TRACE, ("PSM : Force ASPM : Host device L1/L0s Value =  0x%x\n",(UINT)HostConfiguration));
			}
		}
		else if (pAd->StaCfg.PSControl.field.rt30xxFollowHostASPM == 1)
		{

			/* Skip non-exist deice right away */
			if ((pAd->HostLnkCtrlOffset != 0))
			{
	       		 PCI_REG_READ_WORD(pObj->parent_pci_dev, pAd->HostLnkCtrlOffset, HostConfiguration);
				pAd->Rt3xxHostLinkCtrl = HostConfiguration;
				HostConfiguration &= 0x3;
				DBGPRINT(RT_DEBUG_TRACE, ("PSM : Follow Host ASPM : Host device L1/L0s Value =  0x%x\n", (UINT)HostConfiguration));
			}
		}
        }
	/* Prepare to write Ralink setting. */
	/* Find Ralink PCIe Device's Express Capability Offset */
	pos = pci_find_capability(pObj->pci_dev, PCI_CAP_ID_EXP);

    if (pos != 0)
    {
        /* Ralink PCIe Device's Link Control Register Offset */
       pAd->RLnkCtrlOffset = pos + PCI_EXP_LNKCTL;
    	pci_read_config_word(pObj->pci_dev, pAd->RLnkCtrlOffset, &reg16);
        Configuration = le2cpu16(reg16);
	DBGPRINT(RT_DEBUG_TRACE, ("Read (Ralink PCIe Link Control Register) offset 0x%x = 0x%x\n", 
			                                    pAd->RLnkCtrlOffset, (UINT)Configuration));
		Configuration |= 0x100;
		if ((pAd->StaCfg.PSControl.field.rt30xxFollowHostASPM == 1) 
			|| (pAd->StaCfg.PSControl.field.rt30xxForceASPMTest == 1))
		{
			switch(HostConfiguration)
			{
				case 0:
					Configuration &= 0xffffffc;
					break;
				case 1:
					Configuration &= 0xffffffc;
					Configuration |= 0x1;
					break;
				case 2:
					Configuration &= 0xffffffc;
					Configuration |= 0x2;
					break;
				case 3:
					Configuration |= 0x3;
					break;
			}
		}
		reg16 = cpu2le16(Configuration);
		pci_write_config_word(pObj->pci_dev, pAd->RLnkCtrlOffset, reg16);
		pAd->Rt3xxRalinkLinkCtrl = Configuration;
		DBGPRINT(RT_DEBUG_TRACE, ("PSM :Write Ralink device L1/L0s Value =  0x%x\n", (UINT)Configuration));
	}
	DBGPRINT(RT_DEBUG_INFO,("PSM :RTMPrt3xSetPCIePowerLinkCtrl <==============\n"));
	
}
#endif /* PCIE_PS_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */

#endif /* RTMP_MAC_PCI */
