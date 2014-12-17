/*
	Connector to let httpd be able to control authorization and web access
*/

#include "espmissingincludes.h"
#include <string.h>
#include <osapi.h>
#include "c_types.h"
#include "user_interface.h"
#include "espconn.h"
#include "mem.h"

#include "httpd.h"
#include "httpdespfs.h"
#include "espfs.h"
#include "auth.h"

// ARP Stuff
#include <netif/etharp.h>

typedef struct
{
	struct eth_addr macWhiteList[WHITELIST_MAX];
	unsigned char authStatus;
} AuthConfig;

static AuthConfig authConfig;

struct eth_addr * ICACHE_FLASH_ATTR authGetWhitelist(){
	return authConfig.macWhiteList;
}

int ICACHE_FLASH_ATTR authWhitelistCount(){
	int count = 0;
	int i;

	for(i = 0; i < WHITELIST_MAX; i++)
	{
		if(IS_VALID_MAC(authConfig.macWhiteList[i]))
			count++;
	}

	return count;
}

int ICACHE_FLASH_ATTR authWhitelistRemoveMac(int macIdx){
	if( (macIdx >= 0) && (macIdx < WHITELIST_MAX) )
	{
		os_memset(&authConfig.macWhiteList[macIdx], 0, sizeof(struct eth_addr));
		return 1;
	}

	return 0;
}

int ICACHE_FLASH_ATTR authWhitelistAddMac(struct eth_addr * mac){
	int i = 0;

	//TODO: write better way to eliminate spoofing to zero .. is 00..00 allowed any way ?
	//if(!IS_VALID_MAC((*mac)))
    //	return 0;

	for(i = 0; i < WHITELIST_MAX; i++)
	{
		// Empty Space
		if(!IS_VALID_MAC(authConfig.macWhiteList[i]))
		{
			os_memcpy(&authConfig.macWhiteList[i], mac, sizeof(struct eth_addr));
			return 1;
		}
	}

	return 0;
}

int ICACHE_FLASH_ATTR authIsMacAllowed(struct eth_addr * mac) {
	int i;

	//TODO: write better way to eliminate spoofing to zero .. is 00..00 allowed any way ?
	if(!IS_VALID_MAC((*mac)))
		return 0;

	for(i = 0; i < WHITELIST_MAX; i++)
	{
		if(!os_memcmp(&authConfig.macWhiteList[i], mac, sizeof(struct eth_addr)))
			return 1;
	}

	return 0;
}

int ICACHE_FLASH_ATTR authInit(){
	struct eth_addr mac;

	// Zero memory
	os_memset(&authConfig, 0, sizeof(AuthConfig));

	// Enable authentication
	authConfig.authStatus = AUTH_ENABLED;

	// Add Laptop Mac Address
	mac.addr[0] = 0x61;		mac.addr[1] = 0x63;			mac.addr[2] = 0x64;
	mac.addr[3] = 0x62;		mac.addr[4] = 0x63;			mac.addr[5] = 0x64;
	authWhitelistAddMac(&mac);

	// Remove the on in the middle
	authWhitelistRemoveMac(1);

	return 1;
}

int ICACHE_FLASH_ATTR authCgiHook(HttpdConnData *conn) {
	struct eth_addr *eth_ret;
	ip_addr_t *ip_ret;

	if(AUTH_ENABLED == authConfig.authStatus)
	{
		// fetch source mac address
		etharp_find_addr(ip_current_netif(), &current_iphdr_src, &eth_ret, &ip_ret);

		// Check if the MAC address is not allowed
		if(!authIsMacAllowed(eth_ret))
		{
			conn->url = "/401.tpl";
			conn->cgi = cgiEspFsHook;
		}
	}

	return conn->cgi(conn);
}


