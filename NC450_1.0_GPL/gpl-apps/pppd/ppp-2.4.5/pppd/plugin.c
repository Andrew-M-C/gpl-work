/***********************************************************************
*
* plugin.c
*
* pppd plugin for kernel-mode PPPoE on Linux
*
* Copyright (C) 2001 by Roaring Penguin Software Inc., Michal Ostrowski
* and Jamal Hadi Salim.
*
* Much code and many ideas derived from pppoe plugin by Michal
* Ostrowski and Jamal Hadi Salim, which carries this copyright:
*
* Copyright 2000 Michal Ostrowski <mostrows@styx.uwaterloo.ca>,
*                Jamal Hadi Salim <hadi@cyberus.ca>
* Borrows heavily from the PPPoATM plugin by Mitchell Blank Jr.,
* which is based in part on work from Jens Axboe and Paul Mackerras.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version
* 2 of the License, or (at your option) any later version.
*
***********************************************************************/

static char const RCSID[] =
"$Id: plugin.c,v 1.17 2008/06/15 04:35:50 paulus Exp $";

#define _GNU_SOURCE 1
#include "pppoe.h"

#include "pppd.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#include "ccp.h"
/* #include "pppd/pathnames.h" */

#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <linux/if_pppox.h>

#ifndef _ROOT_PATH
#define _ROOT_PATH ""
#endif

#define _PATH_ETHOPT         _ROOT_PATH "/etc/ppp/options."

char pppd_version[] = VERSION;

/* From sys-linux.c in pppd -- MUST FIX THIS! */
extern int new_style_driver;

char *pppd_pppoe_service = NULL;
static char *acName = NULL;

/* Add by Yin Jun, 2012-03-21-10:08:34. */

#ifdef USE_FILE_TO_PASS_PPP_ARG 
extern int req_unit;

static char servicename_buf[32] = {0};
static char servername_buf[32] = {0};

/* service name is stored in /var/tmp/pppInfo_pppx, here we get the length.
 */
int service_name_len = 0;
int ac_name_len = 0;
#endif /* Ended by Yin Jun */

static char *existingSession = NULL;
static int printACNames = 0;
static char *pppoe_reqd_mac = NULL;
unsigned char pppoe_reqd_mac_addr[6];


static int PPPoEDevnameHook(char *cmd, char **argv, int doit);
static option_t Options[] = {
    { "device name", o_wild, (void *) &PPPoEDevnameHook,
      "PPPoE device name",
      OPT_DEVNAM | OPT_PRIVFIX | OPT_NOARG  | OPT_A2STRVAL | OPT_STATIC,
      devnam},
    { "rp_pppoe_service", o_string, &pppd_pppoe_service,
      "Desired PPPoE service name" },

/* Add by Yin Jun, 2012-03-21-15:39:42. */
#ifdef USE_FILE_TO_PASS_PPP_ARG
    { "servicename_len", o_int, &service_name_len,
      "Servicename length in pppinfo file." },

    { "servername_len", o_int, &ac_name_len,
      "Servername length in pppinfo file." },
#endif /* Ended by Yin Jun. */
    { "rp_pppoe_ac",      o_string, &acName,
      "Desired PPPoE access concentrator name" },
    { "rp_pppoe_sess",    o_string, &existingSession,
      "Attach to existing session (sessid:macaddr)" },
    { "rp_pppoe_verbose", o_int, &printACNames,
      "Be verbose about discovered access concentrators"},
    { "pppoe-mac", o_string, &pppoe_reqd_mac,
      "Only connect to specified MAC address" },
    { NULL }
};
int (*OldDevnameHook)(char *cmd, char **argv, int doit) = NULL;
static PPPoEConnection *conn = NULL;

/**********************************************************************
 * %FUNCTION: PPPOEInitDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 *
 * %DESCRIPTION:
 * Initializes PPPoE device.
 ***********************************************************************/
static int
PPPOEInitDevice(void)
{
    conn = malloc(sizeof(PPPoEConnection));
    if (!conn) {
	novm("PPPoE session data");
    }
    memset(conn, 0, sizeof(PPPoEConnection));
    conn->acName = acName;
    conn->serviceName = pppd_pppoe_service;
    conn->ifName = devnam;
    conn->discoverySocket = -1;
    conn->sessionSocket = -1;
    conn->useHostUniq = 1;
    conn->printACNames = printACNames;
    conn->discoveryTimeout = PADI_TIMEOUT;
    return 1;
}

/**********************************************************************
 * %FUNCTION: PPPOEConnectDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Non-negative if all goes well; -1 otherwise
 * %DESCRIPTION:
 * Connects PPPoE device.
 ***********************************************************************/
static int
PPPOEConnectDevice(void)
{
    struct sockaddr_pppox sp;

    strlcpy(ppp_devnam, devnam, sizeof(ppp_devnam));
    if (existingSession) {
	unsigned int mac[ETH_ALEN];
	int i, ses;
	if (sscanf(existingSession, "%d:%x:%x:%x:%x:%x:%x",
		   &ses, &mac[0], &mac[1], &mac[2],
		   &mac[3], &mac[4], &mac[5]) != 7) {
	    fatal("Illegal value for rp_pppoe_sess option");
	}
	conn->session = htons(ses);
	for (i=0; i<ETH_ALEN; i++) {
	    conn->peerEth[i] = (unsigned char) mac[i];
	}
    } else {
	discovery(conn);
	if (conn->discoveryState != STATE_SESSION) {
	    /*error("Unable to complete PPPoE Discovery");*/
	    return -1;
	}
    }

    /* Set PPPoE session-number for further consumption */
    ppp_session_number = ntohs(conn->session);

    /* Make the session socket */
    conn->sessionSocket = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
    if (conn->sessionSocket < 0) {
	error("Failed to create PPPoE socket: %m");
	goto errout;
    }
    sp.sa_family = AF_PPPOX;
    sp.sa_protocol = PX_PROTO_OE;
    sp.sa_addr.pppoe.sid = conn->session;
    memcpy(sp.sa_addr.pppoe.dev, conn->ifName, IFNAMSIZ);
    memcpy(sp.sa_addr.pppoe.remote, conn->peerEth, ETH_ALEN);

    /* Set remote_number for ServPoET */
    sprintf(remote_number, "%02X:%02X:%02X:%02X:%02X:%02X",
	    (unsigned) conn->peerEth[0],
	    (unsigned) conn->peerEth[1],
	    (unsigned) conn->peerEth[2],
	    (unsigned) conn->peerEth[3],
	    (unsigned) conn->peerEth[4],
	    (unsigned) conn->peerEth[5]);

    warn("Connected to %02X:%02X:%02X:%02X:%02X:%02X via interface %s",
	 (unsigned) conn->peerEth[0],
	 (unsigned) conn->peerEth[1],
	 (unsigned) conn->peerEth[2],
	 (unsigned) conn->peerEth[3],
	 (unsigned) conn->peerEth[4],
	 (unsigned) conn->peerEth[5],
	 conn->ifName);

    script_setenv("MACREMOTE", remote_number, 0);

    if (connect(conn->sessionSocket, (struct sockaddr *) &sp,
		sizeof(struct sockaddr_pppox)) < 0) {
	error("Failed to connect PPPoE socket: %d %m", errno);
	close(conn->sessionSocket);
	goto errout;
    }

    return conn->sessionSocket;

 errout:
    if (conn->discoverySocket >= 0) {
	sendPADT(conn, NULL);
	close(conn->discoverySocket);
	conn->discoverySocket = -1;
    }
    return -1;
}

static void
PPPOERecvConfig(int mru,
		u_int32_t asyncmap,
		int pcomp,
		int accomp)
{
#if 0 /* broken protocol, but no point harrassing the users I guess... */
    if (mru > MAX_PPPOE_MTU)
	warn("Couldn't increase MRU to %d", mru);
#endif
}

/**********************************************************************
 * %FUNCTION: PPPOEDisconnectDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Disconnects PPPoE device
 ***********************************************************************/
static void
PPPOEDisconnectDevice(void)
{
    struct sockaddr_pppox sp;

    sp.sa_family = AF_PPPOX;
    sp.sa_protocol = PX_PROTO_OE;
    sp.sa_addr.pppoe.sid = 0;
    memcpy(sp.sa_addr.pppoe.dev, conn->ifName, IFNAMSIZ);
    memcpy(sp.sa_addr.pppoe.remote, conn->peerEth, ETH_ALEN);
    if (connect(conn->sessionSocket, (struct sockaddr *) &sp,
		sizeof(struct sockaddr_pppox)) < 0)
	error("Failed to disconnect PPPoE socket: %d %m", errno);
    close(conn->sessionSocket);
    /* don't send PADT?? */
    if (conn->discoverySocket >= 0)
	close(conn->discoverySocket);
}

static void
PPPOEDeviceOptions(void)
{
    char buf[256];
    snprintf(buf, 256, _PATH_ETHOPT "%s", devnam);
    if (!options_from_file(buf, 0, 0, 1))
	exit(EXIT_OPTION_ERROR);

}

struct channel pppoe_channel;

/**********************************************************************
 * %FUNCTION: PPPoEDevnameHook
 * %ARGUMENTS:
 * cmd -- the command (actually, the device name
 * argv -- argument vector
 * doit -- if non-zero, set device name.  Otherwise, just check if possible
 * %RETURNS:
 * 1 if we will handle this device; 0 otherwise.
 * %DESCRIPTION:
 * Checks if name is a valid interface name; if so, returns 1.  Also
 * sets up devnam (string representation of device).
 ***********************************************************************/
static int
PPPoEDevnameHook(char *cmd, char **argv, int doit)
{
    int r = 1;
    int fd;
    struct ifreq ifr;

/* Add by Yin Jun, 2012-03-21-11:44:58. */
#ifdef USE_FILE_TO_PASS_PPP_ARG 
	FILE *pppinfo = NULL;
	char pppinfo_fname[32] = {0};
#endif

 	/* Added by Yang Caiyong, 11-Oct-10.
 	 * For notice the pppoe device name.
 	 */ 
	notice("PPPoE DevName Hook, the name is %s", cmd);
	doit = 1;
 	/* Ended by Yang Caiyong, 11-Oct-10. */

/* Add by Yin Jun, 2012-03-21-09:47:16. */
#ifdef USE_FILE_TO_PASS_PPP_ARG 
	if (service_name_len > 0 || ac_name_len > 0) {
		snprintf(pppinfo_fname, sizeof(pppinfo_fname), "%sppp%d", PPPOE_FILE_PREFIX, req_unit);

		pppinfo = fopen(pppinfo_fname, "r");
		if (pppinfo == NULL) {
			option_error("open %s failed", pppinfo_fname);
			exit(EXIT_OPTION_ERROR);
		}

		if (ac_name_len > 0) {
			if (fread(servername_buf, 1, ac_name_len, pppinfo) != ac_name_len) {
				option_error("read password error.");
				fclose(pppinfo);
				exit(EXIT_OPTION_ERROR);
			}
			acName = servername_buf;
		}

		if (service_name_len > 0) {
			if (fread(servicename_buf, 1, service_name_len, pppinfo) != service_name_len) {
				option_error("read password error.");
				fclose(pppinfo);
				exit(EXIT_OPTION_ERROR);
			}
			pppd_pppoe_service = servicename_buf;
		}

		fclose(pppinfo);
	}
#endif /* Ended by Yin Jun. */

    /*
     * Take any otherwise-unrecognized option as a possible device name,
     * and test if it is the name of a network interface with a
     * hardware address whose sa_family is ARPHRD_ETHER.
     */
    if (strlen(cmd) > 4 && !strncmp(cmd, "nic-", 4)) {
	/* Strip off "nic-" */
	cmd += 4;
    }

    /* Open a socket */
    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
	r = 0;
    }

    /* Try getting interface index */
    if (r) {
	strncpy(ifr.ifr_name, cmd, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	    r = 0;
	} else {
	    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		r = 0;
	    } else {
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		    if (doit)
			error("Interface %s not Ethernet", cmd);
		    r = 0;
		}
	    }
	}
    }

    /* Close socket */
    close(fd);
    if (r && doit) {
	strncpy(devnam, cmd, sizeof(devnam));
	if (the_channel != &pppoe_channel) {

	    the_channel = &pppoe_channel;
	    modem = 0;

	    PPPOEInitDevice();
	}
	return 1;
    }

    return r;
}

/* Added by Yang Caiyong, 08Jun12.
 * For send PADT when kill the pppd process.
 */ 
extern int isPppoe;
/* Ended by Yang Caiyong, 08Jun12. */

void sendPADTWhenKill(void)
{	
	printf("[ %s ] %d: Send PADT\n", __FUNCTION__, __LINE__);
	sendPADT(conn, NULL);
}

/**********************************************************************
 * %old FUNCTION: plugin_init
 * %now FUNCTION: pppoe_init
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Initializes hooks for pppd plugin
 * changed function name by yangcaiyong:from plugin_init() to pppoe_init(), 2011-10-10
 ***********************************************************************/
void
pppoe_init(void)
{
    if (!ppp_available() && !new_style_driver) {
	fatal("Linux kernel does not support PPPoE -- are you running 2.4.x?");
    }

    add_options(Options);

	info("pppoe_init() success");

	isPppoe = 1;
}

void pppoe_check_options(void)
{
    unsigned int mac[6];
    int i;

    if (pppoe_reqd_mac != NULL) {
	if (sscanf(pppoe_reqd_mac, "%x:%x:%x:%x:%x:%x",
		   &mac[0], &mac[1], &mac[2], &mac[3],
		   &mac[4], &mac[5]) != 6) {
	    option_error("cannot parse pppoe-mac option value");
	    exit(EXIT_OPTION_ERROR);
	}
	for (i = 0; i < 6; ++i)
	    conn->req_peer_mac[i] = mac[i];
	conn->req_peer = 1;
    }

    lcp_allowoptions[0].neg_accompression = 0;
    lcp_wantoptions[0].neg_accompression = 0;

    lcp_allowoptions[0].neg_asyncmap = 0;
    lcp_wantoptions[0].neg_asyncmap = 0;

    lcp_allowoptions[0].neg_pcompression = 0;
    lcp_wantoptions[0].neg_pcompression = 0;

    if (lcp_allowoptions[0].mru > MAX_PPPOE_MTU)
	lcp_allowoptions[0].mru = MAX_PPPOE_MTU;
    if (lcp_wantoptions[0].mru > MAX_PPPOE_MTU)
	lcp_wantoptions[0].mru = MAX_PPPOE_MTU;

    ccp_allowoptions[0].deflate = 0;
    ccp_wantoptions[0].deflate = 0;

    ipcp_allowoptions[0].neg_vj = 0;
    ipcp_wantoptions[0].neg_vj = 0;

    ccp_allowoptions[0].bsd_compress = 0;
    ccp_wantoptions[0].bsd_compress = 0;
}

struct channel pppoe_channel = {
    .options = Options,
    .process_extra_options = &PPPOEDeviceOptions,
    .check_options = pppoe_check_options,
    .connect = &PPPOEConnectDevice,
    .disconnect = &PPPOEDisconnectDevice,
    .establish_ppp = &generic_establish_ppp,
    .disestablish_ppp = &generic_disestablish_ppp,
    .send_config = NULL,
    .recv_config = &PPPOERecvConfig,
    .close = NULL,
    .cleanup = NULL
};
