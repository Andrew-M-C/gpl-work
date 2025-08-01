/**********************************************************************************
	Copyright (C), 2002-2014, TP-LINK TECHNOLOGIES CO., LTD.

	File name:	md5.h
	Version:	0.0.1
	Author:		Marvell
	Modifior:	Andrew Chang (or Zhang Min, the same guy)
	
	Discription:
 		This file was originally designed by Marvell and named "mvMd5.h". In order to
 	transplant MD5 algorithm into this project, I move this file into current project.
		Any question, please refer to Marvel copyright declaration below.
	
	History:
		2014-07-31: File created.
		
 *********************************************************************************
	GPL declaration for TP-LINK:
	
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
	1. zhangmin@tp-link.com.cn		(official mail, as long as I am an employee of TP-LINK)
	2. laplacezhang@126.com		(personal mail)

 **********************************************************************************/


 
/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

This software file (the "File") is owned and distributed by Marvell 
International Ltd. and/or its affiliates ("Marvell") under the following
alternative licensing terms.  Once you have made an election to distribute the
File under one of the following license alternatives, please (i) delete this
introductory statement regarding license alternatives, (ii) delete the two
license alternatives that you have not elected to use and (iii) preserve the
Marvell copyright notice above.

********************************************************************************
Marvell Commercial License Option

If you received this File from Marvell and you have entered into a commercial
license agreement (a "Commercial License") with Marvell, the File is licensed
to you under the terms of the applicable Commercial License.

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or 
modify this File in accordance with the terms and conditions of the General 
Public License Version 2, June 1991 (the "GPL License"), a copy of which is 
available along with the File in the license.txt file or by writing to the Free 
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or 
on the worldwide web at http://www.gnu.org/licenses/gpl.txt. 

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED 
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY 
DISCLAIMED.  The GPL License provides additional details about this warranty 
disclaimer.
********************************************************************************
Marvell BSD License Option

If you received this File from Marvell, you may opt to use, redistribute and/or 
modify this File under the following licensing terms. 
Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

    *   Redistributions of source code must retain the above copyright notice,
	    this list of conditions and the following disclaimer. 

    *   Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution. 

    *   Neither the name of Marvell nor the names of its contributors may be 
        used to endorse or promote products derived from this software without 
        specific prior written permission. 
    
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*******************************************************************************/

#ifndef __mvMD5_h__
#define __mvMD5_h__

#define MV_MD5_MAC_LEN 16

#ifndef MV_U32
#define MV_U32		unsigned int
#endif

#ifndef MV_U8
#define MV_U8		unsigned char
#endif


typedef struct 
{
    MV_U32 buf[4];
    MV_U32 bits[2];
    MV_U8  in[64];

} MV_MD5_CONTEXT;
 
void mvMD5Init(MV_MD5_CONTEXT *context);
void mvMD5Update(MV_MD5_CONTEXT *context, unsigned char const *buf,
                unsigned len);
void mvMD5Final(unsigned char digest[16], MV_MD5_CONTEXT *context);

void mvMD5(unsigned char const *buf, unsigned len, unsigned char* digest);

void mvHmacMd5(unsigned char const* text, int text_len,
                  unsigned char const* key, int key_len,
                  unsigned char* digest);

void MD5(unsigned char const *buf, unsigned len, unsigned char* digest);
  

#endif /* __mvMD5_h__ */
 
