/*************************************************************************************************
	Copyright (C), 2002-2015, TP-LINK TECHNOLOGIES CO., LTD.

	File name:	tpRecovery.c
	Version:	0.0.1
	Author:		Andrew Chang (or Zhang Min, the same guy)
	
	Discription:
 			This file definds a simple functionality to restore system code form Uboot.
	
	History:
		2014-08-28: File created.
		
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
#include <spi_api.h>
#include <nand_api.h>
#include <configs/rt2880.h>

#include "net.h"
#include "md5.h"


//#define _DEBUG


#ifdef	_DEBUG
#define	_DB(x)			x
#else
#define	_DB(x)
#endif


#ifndef	BOOL
#define	BOOL		long
#define	FALSE		0
#define	TRUE		(!(FALSE))
#endif



/******** data structure definitions ********/

#define SYSTEM_FIRMWARE_MAGGIC			400	


/**********/
/* data structures to define Flash formation */

#define	_FLASH_BASE	PHYS_FLASH_START

typedef struct _RCVR_FLASH_INFO {
	const char *name;
	unsigned long offset;		/* offset address */
	unsigned long size;			/* total size */
	unsigned long block;		/* erase block size */
} RcvrFlashInfo_st;


#define	_FLASH_BLOCK_SIZE		0x10000
static RcvrFlashInfo_st _flashInfo[] = {
	{
		.name 			= "Bootloader",
		.offset 		= 0x00000000,
		.size 			= CFG_BOOTLOADER_SIZE,
		.block 			= _FLASH_BLOCK_SIZE,
	},
	{
		.name 			= "Config",
		.offset 		= CFG_BOOTLOADER_SIZE,
		.size 			= CFG_CONFIG_SIZE,
		.block 			= _FLASH_BLOCK_SIZE,
	},
	{
		.name 			= "Factory",
		.offset 		= CFG_BOOTLOADER_SIZE + CFG_CONFIG_SIZE,
		.size 			= CFG_FACTORY_SIZE,
		.block 			= _FLASH_BLOCK_SIZE,
	},
	{
		.name 			= "Kernel",
		.offset 		= CFG_BOOTLOADER_SIZE + CFG_CONFIG_SIZE + CFG_FACTORY_SIZE,
		.size 			= CFG_KERN_SIZE,
		.block 			= _FLASH_BLOCK_SIZE,
	},
	{
		.name 			= "UsrLocal",
		.offset 		= CFG_BOOTLOADER_SIZE + CFG_CONFIG_SIZE + CFG_FACTORY_SIZE + CFG_KERN_SIZE,
		.size 			= (8 << 20) - (CFG_BOOTLOADER_SIZE + CFG_CONFIG_SIZE + CFG_FACTORY_SIZE + CFG_KERN_SIZE),
		.block 			= _FLASH_BLOCK_SIZE,
	}
};

#define	_COMMAND_LEN		64

/* DSP could only been burned in Linux. This is used to inform linux to restore the file */
#define	_RECOVERY_IDENTIFIER_MAGIC		0x1710ac60
#define	_RECOVERY_IDENTIFIER_OFFSET		0x1400



/**********/
/* data structure from NC400 source code */

#define CONFIG_PRODUCT_VER_OFFSET	0x1000

#define MD5_LEN				16
#define PKG_RESERVE_LEN		64
#define IMG_RESERVE_LEN		20
#define PKG_IMAGE_COUNT		3
#define MAGIC_HEX			0xFDFDAAAA
//#define RSA_SIGN_LEN	128	/* 128 * 8 = 1024 */
#define RSA_SIGN_LEN	0

#define SHA1_LEN		20

typedef struct _IMG_HEADER
{
	long 			type;
	long			offset;
	unsigned long	len;
	unsigned char	reserve[IMG_RESERVE_LEN];
}IMG_HEADER;

typedef struct _PKG_HEADER{
	unsigned int	magic;
	unsigned int	firmwareVersion;
	unsigned int	date;
	unsigned long	len;
	unsigned char 	md5[MD5_LEN];
	unsigned char	reserve[PKG_RESERVE_LEN];
	IMG_HEADER 		img[PKG_IMAGE_COUNT];
}PKG_HEADER;

#define BACKUP_SIGN_LEN 			20
#define BACKUP_FILE_LOCATION_LEN	64
#define BACKUP_FILE_NUM				20

typedef struct _BK_FILE_HEADER
{
	long offset;
	unsigned long len;
	unsigned char sign[BACKUP_SIGN_LEN];
	unsigned char location[BACKUP_FILE_LOCATION_LEN];
} BK_FILE_HEADER;


typedef struct _BK_PKG_HEADER
{
	unsigned int magic;
	unsigned long len;
	unsigned char md5[MD5_LEN];
	unsigned char sign[BACKUP_SIGN_LEN];
	BK_FILE_HEADER files[BACKUP_FILE_NUM];
}BK_PKG_HEADER;


typedef	IMG_HEADER	ImgHeader_st;
typedef	PKG_HEADER	PkgHeader_st;
typedef	BK_FILE_HEADER	PkFileHeader_st;
typedef	BK_PKG_HEADER	PkPkgHeader_st;

/********* Notes *********
 *     This is a point need to be explained. I want to access Flash
 * information. At first I desided to include "flash.h". But unex-
 * pectedly, it did not work. Turn out that "spi_flash.c" is used in
 * MTK Uboot implementation. 
 *     Here comes a major problem: all the functions and data struc-
 * tures are defined privately inside the .c file. Therefore I had to
 * define the data here to access is.
 *     Anyone has better solution, please help me improve this problem,
 * thank you!
 *                       ---- Andrew Chang, 2014-08-29, project NC400
 */
#ifndef	_MACRO_chip_info
#define	_MACRO_chip_info
struct chip_info {
	char		*name;
	u8		id;
	u32		jedec_id;
	unsigned long	sector_size;
	unsigned int	n_sectors;
	char		addr4b;
};
#endif
extern struct chip_info *spi_chip_info;



/******** private functions ********/
int _hexFromChar(const char c)
{
	if ((c >= '0') && (c <= '9'))
	{
		return (c - '0');
	}
	else if ((c >= 'a') && (c <= 'f'))
	{
		return (c - 'a' + 0xA);
	}
	else if ((c >= 'A') && (c <= 'F'))
	{
		return (c - 'A' + 0xA);
	}
	else
	{
		return -1;
	}
}


/* Input:
 *     1. data buffer to store output hex arrays
 *     2. input ASCII hex string
 *     3. output data buffer length limit.
 *     4. output data length pointer (or NULL)
 * Return:
 *     output data length or -1 if error.
 */
int _dataFromHex(unsigned char *hexData, const char *hexStr, int lenLimit, int *outputLen)
{
	int strLen;
	int strIdx, dataIdx;
	int isDataError = 0;
	int val;

	if (outputLen)
	{
		*outputLen = 0;
	}

	
	if ((NULL == hexStr) || (NULL == hexData))
	{
		printf ("Parameter error!\n");
		return -1;
	}


	strLen = strnlen(hexStr, lenLimit);
	if (strLen >= lenLimit)
	{
		printf ("Input value too long!\n");
		return -1;
	}

	/* check if data odd */
	if (1 == (strLen & 0x1))		// is odd
	{
		strIdx = 1;
		dataIdx = 1;

		val = _hexFromChar(hexStr[0]);

		if (val < 0)
		{
			isDataError = 1;
		}
		else
		{
			hexData[0] = val;
		}
	}
	else
	{
		strIdx = 0;
		dataIdx = 0;
	}

	/* convert remaining data */
	for (/* null */; 
	     (strIdx < strLen) && (0 == isDataError) && (dataIdx < lenLimit);
		 strIdx += 2, dataIdx += 1)
 	{
 		/* higher 4 bits */
		if (0 == isDataError)
		{
			val = _hexFromChar(hexStr[strIdx]);

			if (val < 0)
			{
				isDataError = 1;
			}
			else
			{
				hexData[dataIdx] = val << 4;
			}
		}

		/* lower 4 bits */
		if (0 == isDataError)
		{
			val = _hexFromChar(hexStr[strIdx + 1]);

			if (val < 0)
			{
				isDataError = 1;
			}
			else
			{
				hexData[dataIdx] += val;
			}
		}
 	}


	/********/
	/* return */
	if (outputLen)
	{
		*outputLen = dataIdx;
	}
	return isDataError? -1 : dataIdx;
}


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


static void _initFlashInfo(void)
{
	unsigned long tmp;
	unsigned long flashSize = (spi_chip_info->sector_size) * (spi_chip_info->n_sectors);


	if (NULL == spi_chip_info)
	{
		return;
	}
	
	_DB(printf ("Flash size: %ldMB.\n", flashSize >> 20));
	_DB(printf ("Sector size: %dkB.\n", (spi_chip_info->sector_size) >> 10));

	for (tmp = 0; tmp < (sizeof(_flashInfo) / sizeof(*_flashInfo)); tmp++)
	{
		_flashInfo[tmp].block = spi_chip_info->sector_size;
	}

	_flashInfo[4].size = 
		flashSize - 
		(_flashInfo[0].size + _flashInfo[1].size + _flashInfo[2].size + _flashInfo[3].size);	


	for (tmp = 0; tmp < (sizeof(_flashInfo) / sizeof(*_flashInfo)); tmp++)
	{
		printf ("%s size: 0x%08lx.\n", _flashInfo[tmp].name, _flashInfo[tmp].size);
	}
}


/****/
void _setValuesInConfigPartition(uint8_t *data, unsigned long size, unsigned long offset, uint8_t *dataBufferInRam)
{
	char command[_COMMAND_LEN];

	/* backup flash memory */
	memcpy(
		(void*)dataBufferInRam, 
		(void*)(_flashInfo[1].offset + _FLASH_BASE), 
		_flashInfo[1].size);

	/* change flash memory in RAM */
	memcpy(
		dataBufferInRam + offset, 
		data, 
		size);

	/* write data back */
	sprintf(
		command, 
		"spi write %lx %lx %lx",		// spi write <addr_to> <addr_from> <len>
		_flashInfo[1].offset,
		dataBufferInRam,
		_flashInfo[1].size);
	run_command(command, 0);

	/* ENDS */
	return;
}


/****/
void _writeKernelImage(uint8_t *data, unsigned long size)
{
	char command[_COMMAND_LEN];

	sprintf(
		command, 
		"spi write %lx %lx %lx",
		_flashInfo[3].offset,
		data,
		size);
	run_command(command, 0);

	return;
}


/****/
void _eraseAllExceptUboot()
{
	char command[_COMMAND_LEN];

	//run_command("erase linux", 0);
	
	sprintf (
		command,
		"erase %lx %lx",
		_flashInfo[1].offset,
		_flashInfo[4].offset + _flashInfo[4].size - _flashInfo[1].size - _flashInfo[0].size);
	printf (command);
	run_command(command, 0);

	return;
}


/****/
void _writeUsrLocalData(uint8_t *data, unsigned long size)
{
	char command[_COMMAND_LEN];

	sprintf(
		command, 
		"spi write %lx %lx %lx",
		_flashInfo[4].offset,
		data,
		size);
	run_command(command, 0);
	
	return;
}


/****/
BOOL _checkPackage(uint8_t *pkgBuffer, unsigned long pkgSize)
{
	BOOL ret = TRUE;
	uint8_t md5[MD5_LEN];
	unsigned long tmp;
	PkgHeader_st *pkgHeader = (PkgHeader_st*)(pkgBuffer + RSA_SIGN_LEN);

	/* check header size */
	if (sizeof(PKG_HEADER) + RSA_SIGN_LEN > pkgSize)
	{
		printf("ERROR: PKG buffer is too small!\n");
		ret = FALSE;
	}

	/* print packet information */
	if (ret)
	{
		printf("magic:%x, firmwareVersion:%u, date:%u, len:%u, reserve:%s\n",
				pkgHeader->magic, pkgHeader->firmwareVersion, pkgHeader->date, pkgHeader->len,
				pkgHeader->reserve);

		printf("offset:%u, len:%u, reserve:%s\n",
				pkgHeader->img[0].offset, pkgHeader->img[0].len, pkgHeader->img[0].reserve);
		
		printf("offset:%u, len:%u, reserve:%s\n",
				pkgHeader->img[1].offset, pkgHeader->img[1].len, pkgHeader->img[1].reserve);

		printf("offset:%u, len:%u, reserve:%s\n",
				pkgHeader->img[2].offset, pkgHeader->img[2].len, pkgHeader->img[2].reserve);
	}

	/* check magic number */
	if (ret)
	{
		if (MAGIC_HEX != pkgHeader->magic)
		{
			printf("ERROR: Invalid magic number, 0x%08x expected, but 0x%08x read.\n", MAGIC_HEX, pkgHeader->magic);
			ret = FALSE;
		}
	}

	if (ret)
	{
		if ((SYSTEM_FIRMWARE_MAGGIC != pkgHeader->firmwareVersion) &&
			(1 != pkgHeader->firmwareVersion))
		{
			printf ("ERROR: Firmware magic number invalid, %d expected, but %d read.\n", SYSTEM_FIRMWARE_MAGGIC, pkgHeader->firmwareVersion);
			ret = FALSE;
		}
	}

	/* calculate packet MD5 digest */
	if (ret)
	{
		MD5(
			(void*)(pkgBuffer + RSA_SIGN_LEN + sizeof(PkgHeader_st)), 
			(pkgHeader->len - sizeof(PkgHeader_st)), 
			md5);
	}

	/* check print header MD5 value */
	if (ret)
	{
		puts ("Image header MD5 digest: ");
		for (tmp = 0; tmp < MD5_LEN; tmp++)
		{
			printf ("%02x", pkgHeader->md5[tmp] & 0xFF);
		}
		puts ("\n");

		puts (" Calt header MD5 digest: ");
		for (tmp = 0; tmp < MD5_LEN; tmp++)
		{
			printf ("%02x", md5[tmp] & 0xFF);
		}
		puts ("\n");


		if (0 != memcmp(pkgHeader->md5, md5, MD5_LEN))
		{
			printf ("ERROR: MD5 not match!\n");
			ret = FALSE;
		}
	} 


	return ret;
}


/****/
int _upgradeSystem(uint8_t *pkgBuf, unsigned long size)
{
	unsigned char softVersion[PKG_RESERVE_LEN];
	PKG_HEADER * pkgHeader = (PKG_HEADER *)(pkgBuf + RSA_SIGN_LEN);
	unsigned long rootImageSize = pkgHeader->img[0].len;
	unsigned long fsImageSize = pkgHeader->img[1].len;
	const unsigned long rcvrIdentifier = _RECOVERY_IDENTIFIER_MAGIC;


	_eraseAllExceptUboot();
	

	/*******************************************************************
	*					Part 0 write product version
	********************************************************************/
	memset(softVersion, '\0',sizeof(softVersion));
	strncpy(softVersion, pkgHeader->reserve, sizeof(softVersion)-1);

	printf ("Now upgrade to software version: %s\n", softVersion);

	_setValuesInConfigPartition(
			softVersion, 
			sizeof(softVersion), 
			CONFIG_PRODUCT_VER_OFFSET, 
			(void*)(((unsigned long)(pkgBuf + size + 4)) &~(0x3)));

	/*******************************************************************
	*					Part 1 upgrade root_uImage
	********************************************************************/
	if ( rootImageSize > 0 )
	{			
		printf("rootImage reserve: %s\n", pkgHeader->img[0].reserve);
		printf("rootImageSize:%ld\n", rootImageSize);

		_writeKernelImage(
			pkgBuf + RSA_SIGN_LEN + pkgHeader->img[0].offset, 
			rootImageSize);
	}

	/*******************************************************************
	*					Part 2 upgrade fs_Image
	********************************************************************/
	if( fsImageSize > 0 )
	{
		printf("fs_image reserve: %s\n", pkgHeader->img[1].reserve);
		printf("fsImageSize:%ld\n", fsImageSize);

		_writeUsrLocalData(
			pkgBuf + RSA_SIGN_LEN + pkgHeader->img[1].offset, 
			fsImageSize);
	}


	/********/
	/* write identification */
	_setValuesInConfigPartition(
		&rcvrIdentifier, 
		sizeof(rcvrIdentifier),
		_RECOVERY_IDENTIFIER_OFFSET,
		AMCDdpFileStart() + AMCDdpFileLength());
	
	
	return 0;
}



#define	_DHCP_STAT_KEY		"dhcpStat"
int doAmcRcvr ( cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
//	DECLARE_GLOBAL_DATA_PTR;
//	bd_t *bd = gd->bd;
	int callStat = 0;
	IPaddr_t ipAddr;
	char ipStr[16];
	char *isDhcpOKStr = NULL;
	unsigned long fileLen = 0;
	uint8_t localMd5[MV_MD5_MAC_LEN];
	uint8_t remoteMd5[MV_MD5_MAC_LEN];
	unsigned long tmp;
	unsigned long rcvrIdentifier = _RECOVERY_IDENTIFIER_MAGIC;


	_initFlashInfo();
	isDhcpOKStr = getenv(_DHCP_STAT_KEY);

	/* check DHCP status and disable autoload of DHCP */
	if (isDhcpOKStr &&
		(0 == memcmp(isDhcpOKStr, "OK", 2)))
	{
		printf ("No DHCP required.\n");
		/* DHCP not required */
		callStat = 0;
	}
	else
	{
		setenv("autoload", "no");
		callStat = NetLoop(DHCP);
	}
	

	/* search for active utility */
	if (0 == callStat);
	{
		AMCDdpSetCmdRequest(AMCCmdReq_SearchForUtility);
		callStat = NetLoop(AMCDDP);

		if (0 == callStat)
		{
			setenv(_DHCP_STAT_KEY, "OK");
		}
		else
		{
			printf ("AMCDDP server not found, exit.\n");
		}
	}

	/* request receive MD5 */
	if (0 == callStat)
	{
		printf ("Now start read remote MD5 digest.\n");
		AMCDdpSetMd5Buffer(remoteMd5);
		AMCDdpSetCmdRequest(AMCCmdReq_RequestMd5Digest);
		callStat = NetLoop(AMCDDP);
	}


	/* request file */
	if (0 == callStat)
	{
		ip_to_string(NetServerIP, ipStr);
		printf ("Get AMCDDP server with IP: %s\n", ipStr);

		AMCDdpSetCmdRequest(AMCCmdReq_RequestUpgradeFile);
		callStat = NetLoop(AMCDDP);
	}


	/* calculate MD5 */
	if (0 == callStat)
	{
		fileLen = AMCDdpFileLength();

		MD5((unsigned char*)AMCDdpFileStart(), AMCDdpFileLength(), localMd5);

		puts (" Local File MD5 digest: ");
		for (tmp = 0; tmp < sizeof(localMd5); tmp++)
		{
			printf ("%02x", (int)(localMd5[tmp] & 0xFF));
		}
		puts ("\n");
	}

	

	/* compare MD5 result */
	if (0 == callStat)
	{
		puts ("Remote File MD5 digest: ");
		for (tmp = 0; tmp < sizeof(remoteMd5); tmp++)
		{
			printf ("%02x", (int)(remoteMd5[tmp] & 0xFF));
		}
		puts ("\n");

	
		if (0 == memcmp(remoteMd5, localMd5, MV_MD5_MAC_LEN))
		{
			printf ("File OK, congratulations!\n");
		}
		else
		{
			printf ("File incorrect!\n");
			callStat = -1;
		}
	}


	/* Analyze package */
	if (0 == callStat)
	{
		if (_checkPackage(AMCDdpFileStart(), AMCDdpFileLength()))
		{
			/* OK continue */
		}
		else
		{
			printf ("Package invalid.\n");
			callStat = -1;
		}
	}


	/* Upgrade system */
	if (0 == callStat)
	{
		printf ("Packet checked. Now start burning.\n");
		callStat = _upgradeSystem(AMCDdpFileStart(), AMCDdpFileLength());
	}
	

	/* ENDS */
	if (0 == callStat)
	{
		printf ("Congradulations! Kernal and root FS has been upgraded!\n");
	
		/* upgrade success, reset */
		printf ("System reset in  ");
		for (tmp = 3; tmp > 0; tmp --)
		{
			printf ("%c%c", 0x08, tmp + '0');
			udelay(1000000);
		}
		run_command("reset", 0);
	}
	else
	{}
	return (0 == callStat) ? 0 : -1;
}


U_BOOT_CMD(
	recover,    1,    1,    doAmcRcvr,
	"recover - recover with system firmware\n",
	"\nrecover\n"
	"    - Start recovering procedure.\n"
);


 