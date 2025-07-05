/*************************************************************************************************
	Copyright (C), 2002-2015, TP-LINK TECHNOLOGIES CO., LTD.

	File name:	AMCDdp.c
	Version:	0.0.1
	Author:		Andrew Chang (or Zhang Min, the same guy)
	
	Discription:
 			This file definds a simple protocol to make several custom configuration and communi-
 		cation on local network.
	
	History:
		2014-08-12: File copied and modified from NS210 to NC400 project
		2012-11-14: File created.
		
 *************************************************************************************************
	GPL declaration:
	
		This program is free software: you can redistribute it and/or modify it under the terms 
	of the GNU General Public License as published by the Free Software Foundation, either version 
	3 of the License, or any later version.

		This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 
	PURPOSE.  See the GNU General Public License for more details. 

		You should have received a copy of the GNU General Public License along with this program. 
	If not, see <http://www.gnu.org/licenses/>.

		For any suggestions, problems and bug reports, please contact Andrew through either 
	E-mails below:
	1. zhangmin@tp-link.com.cn	(company mail, as long as I am an employee of TP-LINK)
	2. laplacezhang@126.com		(personal mail)

 *************************************************************************************************/

#include <common.h>
#include <command.h>
#include <console.h>
#include <net.h>

#include "AMCDdp.h"
#include <configs/rt2880.h>		/* for MARCO "CFG_LOAD_ADDR" */

#ifdef	CFG_LOAD_ADDR
#define _AMCDDP_LOAD_ADDR		CFG_LOAD_ADDR
#else
#define	_AMCDDP_LOAD_ADDR		0x80100000
#endif


#define	_MD5_DIGEST_LEN	16


/**********/
/* check configuration */
#if (PKTSIZE_ALIGN <= AMCDDP_PKG_MAX_CONTENT_LEN)
#error "Error, AMCDDP_PKG_MAX_CONTENT_LEN should not greater than PKTSIZE_ALIGN too much!"
#endif


static AMCDdpPackageOption_t _currentOption = AMCDdpPkgOpt_NoOption;

static void _handleUtilitySearchRespond(AMCDdpContext_st *ddpPkg, IPaddr_t ipFrom);
static void _handleUtilityReadFileRespond(AMCDdpContext_st *ddpPkg, IPaddr_t ipFrom);
static void _handleUtilityReadFileMd5Respond(AMCDdpContext_st *ddpPkg, IPaddr_t ipFrom);
static void _ddpSend(AMCDdpPackageType_t type, AMCDdpPackageOption_t option, uint32_t extInfo, const uchar *data, unsigned int dataLen);
static uint8_t *_ddpLoadAddr = (uint8_t*)_AMCDDP_LOAD_ADDR;

static uchar _eth[6] = {0,0,0,0,0,0};		/* server's physical address */
static uchar *_md5Buffer = NULL;


/**********/
#define	__DATA_DEBUG
#ifdef	__DATA_DEBUG
static char _charFromByte(uint8_t byte)
{
	if ((byte >= '!') && (byte <= 0x7F))
	{
		return (char)byte;
	}
	else if ('\n' == byte)
	{
		return '.';
	}
	else if ('\r' == byte)
	{
		return '.';
	}
	else if (' ' == byte)
	{
		return ' ';
	}
	else
	{
		return '.';
	}
}


static void _printData(const uint8_t *data, const size_t size)
{
	size_t column, tmp;
	char lineString[64] = "";
	char linechar[24] = "";
	size_t lineLen = 0;
	uint8_t byte;

	printf ("---------------------------------------------------------------------------\n");
	printf ("Base: +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C +D +E +F    01234567 89ABCDEF\n");
	printf ("----\n");
//	printf ("---------------------------------------------------------------------------\n");
	
	for (tmp = 0; 
		(tmp + 16) <= size; 
		tmp += 16)
	{
		memset(lineString, 0, sizeof(lineString));
		memset(linechar, 0, sizeof(linechar));
	
		for (column = 0, lineLen = 0;
			column < 16;
			column ++)
		{
			byte = data[tmp + column];
			sprintf(lineString + lineLen, "%02X ", byte & 0xFF);
			
			lineLen += 3;

			if (column < 7)
			{
				linechar[column] = _charFromByte(byte);
			}
			else if (7 == column)
			{
				linechar[column] = _charFromByte(byte);
				linechar[column+1] = ' ';
				sprintf(lineString + lineLen, " ");
				lineLen += 1;
			}
			else
			{
				linechar[column+1] = _charFromByte(byte);
			}
		}

		printf ("%04X: %s   %s\n", tmp, lineString, linechar);
	}

	/* last line */
	if (tmp < size)
	{
		memset(lineString, 0, sizeof(lineString));
		memset(linechar, 0, sizeof(linechar));
	
		for (column = 0, lineLen = 0;
			column < (size - tmp);
			column ++)
		{
			byte = data[tmp + column];
			sprintf(lineString + lineLen, "%02X ", byte & 0xFF);
			lineLen += 3;

			if (column < 7)
			{
				linechar[column] = _charFromByte(byte);
			}
			else if (7 == column)
			{
				linechar[column] = _charFromByte(byte);
				linechar[column+1] = ' ';
				sprintf(lineString + lineLen, " ");
				lineLen += 1;
			}
			else
			{
				linechar[column+1] = _charFromByte(byte);
			}
		}
#if 1
		for (/* null */;
			column < 16;
			column ++)
		{
			sprintf(lineString + lineLen, "   ");
			lineLen += 3;
		
			if (7 == column)
			{
				sprintf(lineString + lineLen, " ");
				lineLen += 1;
			}
		}
#endif
		printf ("%04X: %s   %s\n", tmp, lineString, linechar);
	}
	
	printf ("---------------------------------------------------------------------------\n");
	
	/* ends */
}
#else
#define	_printData(x, y)		/* as nothing */
#endif


/**********/
#define	__PUBLIC_INTERFACES
#ifdef __PUBLIC_INTERFACES

void AMCDdpSetCmdRequest(AMCDdpCmdRequest_t req)
{
	switch (req)
	{
		/* find utility */
		case AMCCmdReq_SearchForUtility:
			_currentOption = AMCDdpPkgOpt_SearchUtility;
			break;

		/* request upgrade file */
		case AMCCmdReq_RequestUpgradeFile:
			_currentOption = AMCDdpPkgOpt_ReadUpgradeFile;
			break;

		/* request uograde file MD5 digest */
		case AMCCmdReq_RequestMd5Digest:
			_currentOption = AMCDdpPkgOpt_ReadFileMd5Digest;
			break;
			
		default:
			break;
	}
}

#endif



/**********/
#define	__NET_LOOP_CALLBACKS
#ifdef	__NET_LOOP_CALLBACKS
static void AMCDdpTimeout(void)
{
	printf("AMCDDP timeout in in operation ID %d.\n", _currentOption & 0xFF);

	/* tell NetLoop that we wants to quit in error */
	_currentOption = AMCDdpPkgOpt_NoOption;
	NetState = NETLOOP_FAIL;			/* Final fail */

	return;
}


static void AMCDdpHandler
				(uchar * pkt, unsigned dest, unsigned src, unsigned len)
{
	AMCDdpContext_st *ddpContext;			/* pointer should point to package from called */
	IPaddr_t ipFrom;
//	uchar macFrom[6];
//	static char charBuffer[64];
//	long tmp;
	char ipStrng[16];
	IP_t ipPkg;

	ddpContext = (AMCDdpContext_st*) pkt;

//	ipPkg = (IP_t*)(pkt - IP_HDR_SIZE);		/* WARNING: This is a dangerous action */
	memcpy(&ipPkg, pkt - IP_HDR_SIZE, IP_HDR_SIZE);
	ipFrom = ipPkg.ip_src;

	ip_to_string(ipFrom, ipStrng);
	//AMCDDP_DB(printf ("Get response from: %s.\n", ipStrng));

	/* check port */
	if ((AMCDDP_SERVER_PORT == src) &&
		(AMCDDP_CLIENT_PORT == dest))			/* port correct */
	{
		switch (ddpContext->pkgOption)
		{
			case AMCDdpPkgOpt_SearchUtility:
				_handleUtilitySearchRespond(ddpContext, ipFrom);
				break;

			case AMCDdpPkgOpt_ReadUpgradeFile:
				_handleUtilityReadFileRespond(ddpContext, ipFrom);
				break;

			case AMCDdpPkgOpt_ReadFileMd5Digest:
				_handleUtilityReadFileMd5Respond(ddpContext, ipFrom);
				break;
		
			default:
				printf ("Unproper option status: %d\nAMCDDP ends.\n", ddpContext->pkgOption);
				_currentOption = AMCDdpPkgOpt_NoOption;
				NetState = NETLOOP_SUCCESS;
				break;
		}
	}
	else
	{
		printf("Get unrecognized responce.\n");
	}

	//AMCDDP_DB(printf("staticAMCDdpHandler() ends\n"));
	return;
}

void AMCDdpStart()
{
	const char startMessage[] = "Hello utility!";
	char msgBuff[AMCDDP_PKG_MAX_CONTENT_LEN] = "";

	extern IPaddr_t	NetArpWaitPacketIP;
	extern IPaddr_t	NetArpWaitReplyIP;

	/* enable UDP checksum */
	//run_command("setudpsum on", 0);
#if 0
	AMCDDP_DB(printf("NetArpWaitPacketIP = 0x%08X.\n", NetArpWaitPacketIP));
	AMCDDP_DB(printf("NetArpWaitReplyIP = 0x%08X.\n", NetArpWaitReplyIP));
	AMCDDP_DB(printf("NetOurSubnetMask = 0x%08X.\n", NetOurSubnetMask));
	AMCDDP_DB(printf("NetOurGatewayIP = 0x%08X.\n", NetOurGatewayIP));
	AMCDDP_DB(printf("NetOurDNSIP = 0x%08X.\n", NetOurDNSIP));
	AMCDDP_DB(printf("NetOurIP = 0x%08X.\n", NetOurIP));
	AMCDDP_DB(printf("NetServerIP = 0x%08X.\n", NetServerIP));
	AMCDDP_DB(printf("NetEtherNullAddr = %02x:%02x:%02x:%02x:%02x:%02x\n", 
		NetEtherNullAddr[0], NetEtherNullAddr[1], NetEtherNullAddr[2], 
		NetEtherNullAddr[3], NetEtherNullAddr[4], NetEtherNullAddr[5]));
	AMCDDP_DB(printf("NetBcastAddr = %02x:%02x:%02x:%02x:%02x:%02x\n", 
		NetBcastAddr[0], NetBcastAddr[1], NetBcastAddr[2], 
		NetBcastAddr[3], NetBcastAddr[4], NetBcastAddr[5]));
#endif

	NetSetHandler(AMCDdpHandler);
	NetSetTimeout((ulong)(CFG_HZ * AMCDDP_TIMEOUT_SEC), AMCDdpTimeout);

	switch (_currentOption)
	{
		/* search and get server IP address */
		case AMCDdpPkgOpt_SearchUtility:
			_ddpSend(AMCDDP_PKG_TYPE_REQ, 
					AMCDdpPkgOpt_SearchUtility,
					0,
					startMessage, 
					strlen(startMessage));
			break;
			

		/* request for upgrade file */
		case AMCDdpPkgOpt_ReadUpgradeFile:
			memset(_eth, 0, sizeof(_eth));
			_ddpLoadAddr = (uint8_t*)_AMCDDP_LOAD_ADDR;
			sprintf(msgBuff,
					"Request upgrade file\n"
					"Uboot Date:"__DATE__"\n"
					"Model:NC400\n"
					"Architecture:SNX\n"
					"File Offset:0\n"
					"Context Size Limit:%d",
					AMCDDP_PKG_MAX_CONTENT_LEN);
			_ddpSend(AMCDDP_PKG_TYPE_REQ, 
					AMCDdpPkgOpt_ReadUpgradeFile,
					0,
					msgBuff, 
					strlen(msgBuff) + 1);
			break;

		/* request for MD5 digest of current upgrade file */
		case AMCDdpPkgOpt_ReadFileMd5Digest:
			_ddpSend(AMCDDP_PKG_TYPE_REQ, AMCDdpPkgOpt_ReadFileMd5Digest, 0, msgBuff, 0);
			break;


		/* invalid request */
		default:
			_currentOption = AMCDdpPkgOpt_SearchUtility;
			printf("Fail: AMCDdp type not set.\n");
			NetState = NETLOOP_FAIL;
			break;
	}
}


void *AMCDdpFileStart(void)
{
	return (void*)(_AMCDDP_LOAD_ADDR);
}


unsigned long AMCDdpFileLength()
{
	return (unsigned long)(_ddpLoadAddr - _AMCDDP_LOAD_ADDR);
}


void AMCDdpSetMd5Buffer(unsigned char *md5Buffer)
{
	_md5Buffer = md5Buffer;
}


#endif



/**********/
#define	__PRIVATE_OPERATIONS
#ifdef	__PRIVATE_OPERATIONS

static void _ddpSend
	(AMCDdpPackageType_t type, AMCDdpPackageOption_t option, uint32_t extInfo, const uchar *data, unsigned int dataLen)
{
	static uint8_t header[AMCDDP_HEADER_SIZE];
	AMCDdpContext_st *context;


	if (NULL != data)
	{
		/* generate header */
		context = (AMCDdpContext_st*)header;
		context->pkgType = type;
		context->pkgOption = option;
		context->contextLenth = htons(dataLen);
		context->additionalInfo = htonl(extInfo);
		context = (AMCDdpContext_st*)(NetTxPacket + NetEthHdrSize() + IP_HDR_SIZE);
		memcpy(context, header, sizeof(header));
		
		/* copy data */
		memcpy(context->context, data, dataLen);
	}
	else
	{
		return;
	}

	//AMCDDP_DB(printf ("Data to send:\n"));
	//AMCDDP_DB(_printData(context, sizeof(header) + dataLen));


	switch (option)
	{
		/****/
		case AMCDdpPkgOpt_SearchUtility:
			memcpy(_eth, &NetBcastAddr, sizeof(_eth));
			NetSendUDPPacket(_eth, 
							0, 
							AMCDDP_SERVER_PORT, 
							AMCDDP_CLIENT_PORT, 
							dataLen + AMCDDP_HEADER_SIZE);
			break;

		/****/
		case AMCDdpPkgOpt_ReadUpgradeFile:
			NetSendUDPPacket(_eth, 
							NetServerIP, 
							AMCDDP_SERVER_PORT, 
							AMCDDP_CLIENT_PORT, 
							dataLen + AMCDDP_HEADER_SIZE);
			break;

		/****/
		case AMCDdpPkgOpt_ReadFileMd5Digest:
			NetSendUDPPacket(_eth, 
							NetServerIP, 
							AMCDDP_SERVER_PORT, 
							AMCDDP_CLIENT_PORT, 
							dataLen + AMCDDP_HEADER_SIZE);
			break;

		/****/
		default:
			AMCDDP_DB(printf("Option %d incorrect, do nothing.\n", option));
			/* do nothing */
			break;
	}

	//AMCDDP_DB(printf("staticAMCStarterSend() ends\n"));
	return;
}

static void _handleUtilitySearchRespond(AMCDdpContext_st *ddpPkg, IPaddr_t ipFrom)
{
	char ipStr[16];
	const char expectedResponse[] = "Hello, device!";

	if (AMCDDP_PKG_TYPE_ACK != ddpPkg->pkgType)
	{
		ip_to_string(ipFrom, ipStr);
		AMCDDP_DB(printf ("(SEARCH) Get unknown type: %d, from %s\n", (ddpPkg->pkgType), ipStr));
	}
	else
	{
		/* set as server IP */
		if ((ntohs(ddpPkg->contextLenth) >= strlen(expectedResponse)) &&
			(0 == memcmp(ddpPkg->context, expectedResponse, strlen(expectedResponse))))
		{
			AMCDDP_DB(printf("message match.\n"));

			/* set server IP */
			ip_to_string(ipFrom, ipStr);
			setenv("serverip", ipStr);
			NetServerIP = ipFrom;

			/* print data */
			_printData(ddpPkg->context, ntohs(ddpPkg->contextLenth));
			
			/* ends */
			_currentOption = AMCDdpPkgOpt_NoOption;
			NetState = NETLOOP_SUCCESS;
		}
		else
		{
			AMCDDP_DB(printf("message not match, ignore it.\n"));
			AMCDDP_DB(_printData(ddpPkg, ntohs(ddpPkg->contextLenth) + AMCDDP_HEADER_SIZE));
		}
	}

	return;
}



#define	_CFG_PKG_PER_SHARP	8
#define	_CFG_SHARP_PER_LINE	64

static void _handleUtilityReadFileRespond(AMCDdpContext_st *ddpPkg, IPaddr_t ipFrom)
{
	char ipStr[16];
	uint32_t sectionSize;
	static uint8_t ctxBuffer[128];
	static int sharpCount;
	uint32_t tail;

	if (AMCDDP_PKG_TYPE_ACK != ddpPkg->pkgType)
	{
		ip_to_string(ipFrom, ipStr);
		AMCDDP_DB(printf ("(READ_FILE) Get unknown type: %d, from %s\n", (ddpPkg->pkgType), ipStr));
	}
	else
	{
		/* Read data to memory */
		sectionSize = (uint32_t)ntohs(ddpPkg->contextLenth);

		/* data ends */
		if (0 == sectionSize)
		{
			tail = ((uint32_t)(_ddpLoadAddr - _AMCDDP_LOAD_ADDR) & 1023) * 1000 / 512;
			tail += (tail & 0x1) ? 1 : 0;		// round off
			tail = tail >> 1;
			
			printf ("\nfile transfer ends, total size: %d Bytes (%d.%03dkB).\n", 
					_ddpLoadAddr - _AMCDDP_LOAD_ADDR,
					(uint32_t)(_ddpLoadAddr - _AMCDDP_LOAD_ADDR) >> 10,
					tail);
			sharpCount = 0;
			_currentOption = AMCDdpPkgOpt_NoOption;
			NetState = NETLOOP_SUCCESS;
		}
		else
		{
			/* reset timeout */
			NetSetTimeout((ulong)(CFG_HZ * AMCDDP_TIMEOUT_SEC), AMCDdpTimeout);

			/* read data */
			memcpy(_ddpLoadAddr, ddpPkg->context, sectionSize);
			_ddpLoadAddr += sectionSize;

			/* print read process */
			if (0 == AMCDdpFileLength())
			{
				printf ("Start receiving file.\n");
			}

 			//AMCDDP_DB(printf ("(READ_FILE) Got %d Bytes, Current size: %d Bytes\n", sectionSize, _ddpLoadAddr - _AMCDDP_LOAD_ADDR));
			//AMCDDP_DB(printf ("Receive data:\n"));
			//AMCDDP_DB(_printData(ddpPkg->context, ntohs(ddpPkg->contextLenth)));

			sharpCount++;
			if (0 == (sharpCount & ((_CFG_PKG_PER_SHARP * _CFG_SHARP_PER_LINE) - 1)))
			{
				printf ("# %8dkB\n", AMCDdpFileLength() >> 10);
			}
			else if (0 == (sharpCount & (_CFG_PKG_PER_SHARP - 1)))
			{
				puts ("#");
			}
			else
			{}

			/* Request for next section */
			sprintf(ctxBuffer,
					"File Offset:%d\n"
					"Context Size Limit:%d",
					_ddpLoadAddr - _AMCDDP_LOAD_ADDR,
					AMCDDP_PKG_MAX_CONTENT_LEN);
			_ddpSend(AMCDDP_PKG_TYPE_REQ, 
					AMCDdpPkgOpt_ReadUpgradeFile,
					0,
					ctxBuffer, 
					strlen(ctxBuffer) + 1);
		}	
	}

	return;
}


static void _handleUtilityReadFileMd5Respond(AMCDdpContext_st *ddpPkg, IPaddr_t ipFrom)
{
	if (_MD5_DIGEST_LEN != ntohs(ddpPkg->contextLenth))
	{
		printf ("Error package length \"%d\" from server.\n", ntohs(ddpPkg->contextLenth));
		NetState = NETLOOP_FAIL;
	}
	else
	{
		if (NULL == _md5Buffer)
		{
			printf ("MD5 digest read but buffer NULL.\n");
			NetState = NETLOOP_FAIL;
		}
		else
		{
			unsigned long tmp;

			AMCDDP_DB(printf ("MD5 buffer address: 0x%08x.\n", (unsigned int)_md5Buffer));
			AMCDDP_DB(printf ("Get digest response:\n"));
			AMCDDP_DB(_printData(ddpPkg, ntohs(ddpPkg->contextLenth) + AMCDDP_HEADER_SIZE));

			memcpy(_md5Buffer, ddpPkg->context, _MD5_DIGEST_LEN);
			NetState = NETLOOP_SUCCESS;
		}
	}


	_md5Buffer = NULL;
	return;
}


#endif


