/*
	Cgi/template routines for the /whitelist url
*/

#include <string.h>
#include <stdlib.h>

#include <osapi.h>
#include "user_interface.h"
#include "mem.h"
#include "httpd.h"
#include "cgi.h"
#include "io.h"
#include "espmissingincludes.h"
#include "auth.h"
#include "cgiwhitelist.h"
#include <ip_addr.h>
#include <netif/etharp.h>

#define MAC_TO_STR(buffer, mac)																\
		do {																				\
			os_sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",	mac->addr[0], mac->addr[1],	\
																mac->addr[2], mac->addr[3],	\
																mac->addr[4], mac->addr[5]);\
		}while(0)

enum
{
	MSG_SUCCESS = 0,
	MSG_NOT_ALLOWED,
	MSG_INVALID_MAC,
	MSG_MAC_EXISTS,
	MSG_LIST_FULL
};

enum
{
	STYLE_HIDDEN = 0,
	STYLE_SUCCESS,
	STYLE_FAIL
};

const char*	msgStyleStrList[]	=	{"hide", "success", "fail"};
const int	MsgStyleList[]		= 	{STYLE_SUCCESS, STYLE_FAIL, STYLE_FAIL, STYLE_FAIL, STYLE_FAIL};
const char* MsgList[]			= 	{"Success !",
									"Error: Not allowed operation",
									"Error: Invalid MAC address",
									"Error: MAC address already exists",
									"Error: Whitelist is full"};

int ICACHE_FLASH_ATTR isValidHex(char * str)
{
	int i = 0;
	int len = strlen(str);

	for(i = 0 ; i < len; i++)
	{
		if( (str[i] >= '0') && (str[i] <= '9') )
			continue;
		else if( (str[i] >= 'A') && (str[i] <= 'F') )
			continue;
		else
			return 0;
	}

	return 1;
}

//Cgi to parse whitelist delete request
int ICACHE_FLASH_ATTR cgiWhitelistDel(HttpdConnData *connData) {
	int len, Idx;
	int retStatus = MSG_NOT_ALLOWED;
	char buff[1024];

	if (connData->conn==NULL) {
		//Connection aborted. Clean up.
		return HTTPD_CGI_DONE;
	}

	len=httpdFindArg(connData->postBuff, "id", buff, sizeof(buff));
	if (len > 0) {
			Idx = atoi(buff);
			if(authWhitelistCount() == 1)
				retStatus = MSG_NOT_ALLOWED;
			else if((Idx >= 0) && (Idx < WHITELIST_MAX))
			{
				authWhitelistRemoveMac(Idx);
				retStatus = MSG_SUCCESS;
			}
			else
				retStatus = MSG_NOT_ALLOWED;
	}

	os_sprintf(buff, "/whitelist.tpl?msgid=%d", retStatus);
	httpdRedirect(connData, buff);

	return HTTPD_CGI_DONE;
}

//Cgi to parse whitelist page requests
//TODO: re-write this function
int ICACHE_FLASH_ATTR cgiWhitelistAdd(HttpdConnData *connData) {
	char buff[1024];
	char tmp[3] = {0};
	int len, i = 0, c = 0;
	int retStatus = MSG_INVALID_MAC;
	struct eth_addr eth_ret;

	if (connData->conn==NULL) {
		//Connection aborted. Clean up.
		return HTTPD_CGI_DONE;
	}

	len=httpdFindArg(connData->postBuff, "macaddr", buff, sizeof(buff));
	if( (len == 17) || (len == 12) )
	{
		retStatus = MSG_SUCCESS;

		for(i = 0; i < len; i++)
		{
			if( (buff[i] == ':') || (buff[i] == '-') )
				continue;

			tmp[0] = buff[i++];
			tmp[1] = buff[i];

			if(isValidHex(tmp))
				eth_ret.addr[c++] = (unsigned char)strtol(tmp, NULL, 16);
			else
			{
				retStatus = MSG_INVALID_MAC;
				break;
			}
		}
	}

	if(retStatus == MSG_SUCCESS)
	{
		if(!IS_VALID_MAC(eth_ret))
			retStatus = MSG_INVALID_MAC;
		else if(authIsMacAllowed(&eth_ret))
			retStatus = MSG_MAC_EXISTS;
		else if(!authWhitelistAddMac(&eth_ret))
			retStatus = MSG_LIST_FULL;
	}

	os_sprintf(buff, "/whitelist.tpl?msgid=%d", retStatus);
	httpdRedirect(connData, buff);

	return HTTPD_CGI_DONE;
}

//Template code for the whitelist
void ICACHE_FLASH_ATTR tplWhitelist(HttpdConnData *connData, char *token, void **arg) {
	char buff[128];
	char macstr[64];
	int	 Idx, count, len;
	struct eth_addr * eth_ret;
	ip_addr_t *ip_ret;

	if (token==NULL) return;

	if (os_strcmp(token, "MAC")==0) {
		etharp_find_addr(ip_current_netif(), &current_iphdr_src, &eth_ret, &ip_ret);
		MAC_TO_STR(buff, eth_ret);
	}
	else if (os_strcmp(token, "IP")==0) {
		os_strcpy(buff, ipaddr_ntoa(&current_iphdr_src));
	}
	else if (os_strcmp(token, "maxdevices")==0) {
		os_sprintf(buff, "%d", WHITELIST_MAX);
	}
	else if (os_strcmp(token, "repeater")==0) {
		eth_ret = authGetWhitelist();
		count = 0;
		for(Idx = 0; Idx < WHITELIST_MAX; Idx++)
		{
			if(IS_VALID_MAC(eth_ret[Idx]))
			{
				MAC_TO_STR(macstr, ((struct eth_addr *)&eth_ret[Idx]));
				os_sprintf(buff, "<tr>"
								 "<td>%d</td>"
								 "<td>%s</td>"
								 "<td>"
								 "<button type=\"submit\" name=\"id\" value=\"%d\">Delete</button>"
								 "</td>"
								 "</tr>", count, macstr, Idx);

				espconn_sent(connData->conn, (uint8 *)buff, os_strlen(buff));
				count = count + 1;
			}
		}

		return;
	}
	else if (os_strcmp(token, "STATUS_STYLE")==0) {
		len = httpdFindArg(connData->getArgs, "msgid", buff, sizeof(buff));
		if(len > 0)
		{
				Idx = atoi(buff);
				if( !((Idx >= 0) && (Idx < 5)) )
					Idx = 1;

				os_strcpy(buff, msgStyleStrList[MsgStyleList[Idx]]);
				os_printf("%s", buff);
		}
		else
			os_strcpy(buff, msgStyleStrList[STYLE_HIDDEN]);
	}
	else if (os_strcmp(token, "STATUS_MSG")==0) {
		len = httpdFindArg(connData->getArgs, "msgid", buff, sizeof(buff));
		if(len > 0)
		{
			Idx = atoi(buff);
			if( !((Idx >= 0) && (Idx < 5)) )
				Idx = 1;

			os_strcpy(buff, MsgList[Idx]);
			os_printf("%s", buff);
		}
		else
			buff[0] = NULL;
	}

	espconn_sent(connData->conn, (uint8 *)buff, os_strlen(buff));
}


