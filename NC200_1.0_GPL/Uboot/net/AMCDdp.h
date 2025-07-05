/*************************************************************************************************
	Copyright (C), 2002-2015, TP-LINK TECHNOLOGIES CO., LTD.

	File name:	AMCDdp.h
	Version:	0.0.1
	Author:		Andrew Chang (or Zhang Min, the same guy)
	
	Discription:
 			A header file for "AMCDdp.c".
	
	History:
		2014-08-12: File copied and modified from NS210 to NC400 project
		2012-11-14: File created.
		
 *************************************************************************************************
	GPL declaration:
	
		This program is free software: you can redistribute it and/or modify it under the terms 
	of the GNU General Public License as published by the Free Software Foundation, either version 
	3 of the License, or any later version.

		This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
	the GNU General Public License for more details. 

		You should have received a copy of the GNU General Public License along with this program. 
	If not, see <http://www.gnu.org/licenses/>.

		For any suggestions, problems and bug reports, please contact Andrew through either E-mails
	below:
	
	1. zhangmin@tp-link.com.cn	(company mail, as long as I am an employee of TP-LINK)
	2. laplacezhang@126.com		(personal mail)

 *************************************************************************************************/

#ifndef	__AMC_DDP_H__
#define	__AMC_DDP_H__

//#define	AMCDDP_DEBUG

//#define	CFG_AMCDDP_USE_UBOOT_IP

#ifndef	CFG_AMCDDP_USE_UBOOT_IP
#define	CFG_AMCDDP_IP_ADDRESS	"10.25.56.61"
#endif


#ifndef	uint8_t
#define	uint8_t  unsigned char
#endif

#ifndef	uint16_t
#define	uint16_t	unsigned short
#endif

#ifndef	uint32_t
#define	uint32_t	unsigned int
#endif


#ifdef	AMCDDP_DEBUG
#define	AMCDDP_DB(x)	printf("AMCDDP: %d: ", __LINE__); x
#else
#define	AMCDDP_DB(x)
#endif

#define	AMCDDP_PKG_MAX_CONTENT_LEN		(1024)		// should not exceed size of NetTxPacket

typedef uint8_t AMCDdpPackageType_t;enum{
	AMCDDP_PKG_TYPE_REQ = 0,
	AMCDDP_PKG_TYPE_ACK = 1,
	AMCDDP_PKG_TYPE_INFORM = 2,
	AMCDDP_PKG_HEARTBEAT = 3
};


#if 0
typedef struct {
	uchar		ip_hl_v;	/* header length and version	*/
	uchar		ip_tos;		/* type of service		*/
	ushort		ip_len;		/* total length			*/
	ushort		ip_id;		/* identification		*/
	ushort		ip_off;		/* fragment offset field	*/
	uchar		ip_ttl;		/* time to live			*/
	uchar		ip_p;		/* protocol			*/
	ushort		ip_sum;		/* checksum			*/
	IPaddr_t	ip_src;		/* Source IP address		*/
	IPaddr_t	ip_dst;		/* Destination IP address	*/
} AMCDdpPackageHeader_st;

#define	AMC_DDP_HEADER_LEN	(sizeof(AMCDdpPackageHeader_st))
#define	AMC_DDP_PACKAGE_MAX_LEN	(sizeof(AMCDdpPackage_st))
#endif


typedef	uint8_t AMCDdpPackageOption_t; enum{
	AMCDdpPkgOpt_NoOption		= 0,

	/* Old options used in TL-NS210 */
	AMCDdpPkgOpt_Reserved_EnterDdpMode		= 3,
	AMCDdpPkgOpt_Reserved_ReqAssignIp		= 4,
	AMCDdpPkgOpt_Reserved_ExitDdpMode		= 5,
	AMCDdpPkgOpt_Reserved_FileGood			= 6,
	AMCDdpPkgOpt_Reserved_FileIllegal		= 7,
	AMCDdpPkgOpt_Reserved_FileBurnOK		= 8,
	AMCDdpPkgOpt_Reserved_FileBurnFail		= 9,

	/* New options used in NC400 */
	AMCDdpPkgOpt_SearchUtility				= 10,
	AMCDdpPkgOpt_ReadUpgradeFile			= 11,
	AMCDdpPkgOpt_ReadFileMd5Digest			= 12,
	AMCDdpPkgOpt_ReadFileLength				= 13,		// Not used in Uboot
};

/**********
 *  Packet format
 *    |--pkgType--|-pkgOption-|-----contextLenth------|		--> header
 *    |------------Additional Information-------------|
 *    |    ..........
 *                                       ..........   |		--> context   
 */
typedef struct {
	AMCDdpPackageType_t		pkgType;
	AMCDdpPackageOption_t	pkgOption;
	uint16_t	contextLenth;
	uint32_t	additionalInfo;
	uchar		context[AMCDDP_PKG_MAX_CONTENT_LEN];	/* main content */
} AMCDdpContext_st;



#define	AMCDDP_TIMEOUT_SEC	(10)
#define	AMCDDP_HEADER_SIZE	(sizeof(AMCDdpContext_st) - AMCDDP_PKG_MAX_CONTENT_LEN)
#define	AMCDDP_CLIENT_PORT	(1710)
#define	AMCDDP_SERVER_PORT	(4085)


void AMCDdpStart(void);
void *AMCDdpFileStart(void);
unsigned long AMCDdpFileLength(void);
void AMCDdpSetMd5Buffer(unsigned char *md5Buffer);



/************************************************************
 *  <<<< Request and Response format definitions >>>>
 *
 * === Search Utility ===
 *
 * -- Resuest --
 *   ( 8b) type:        AMCDDP_PKG_TYPE_REQ
 *   ( 8b) option:      AMCDdpPkgOpt_SearchUtility
 *   (16b) length:      strlen("Hello utility!")
 *   (32b) information: 0
 *   (   ) data:        "Hello utility"
 *
 * -- Response --
 *   ( 8b) type:        AMCDDP_PKG_TYPE_ACK
 *   ( 8b) option:      AMCDdpPkgOpt_SearchUtility
 *   (16b) length:      strlen("Hello, device!")
 *   (32b) information: 0
 *   (   ) data:        "Hello, device!" 
 *
 *
 *
 * === Read bin file ===
 *
 * -- Request --
 *   ( 8b) type:        AMCDDP_PKG_TYPE_REQ
 *   ( 8b) option:      AMCDdpPkgOpt_ReadUpgradeFile
 *   (16b) length:      (length of context)
 *   (32b) information: 0
 *   (   ) data:        "Request upgrade file\n"
 *                      "Uboot Date:"__DATE__"\n"
 *                      "Model:NC400\n"
 *                      "Architecture:SNX\n"
 *                      "File Offset:%d\n",
 *                      "Context Size Limit:%d",
 *       "SNX" identifies "Sonix". All key-value pairs are not necessary EXCEPT 
 *   "File Offset" and "Context Size Limit". Mostly, value of "Context Size Li-
 *   mit" is 1024. And value "File Offset" tells the file offset Uboot requires
 *   to read.
 *
 * -- Response --
 *   ( 8b) type:        AMCDDP_PKG_TYPE_ACK
 *   ( 8b) option:      AMCDdpPkgOpt_ReadUpgradeFile
 *   (16b) length:      (length of context)
 *   (32b) information: (File offset number)
 *   (   ) data:        (File section content)
 *       After receiving the requirement from Uboot, PC-ended utility sends this 
 *   response back, Which contains the required data of bin files.
 */

#endif	/* EOF */
