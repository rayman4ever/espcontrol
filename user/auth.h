#ifndef AUTH_H
#define AUTH_H

#include <netif/etharp.h>
#include "httpd.h"

#define	WHITELIST_MAX	10

#define IS_VALID_MAC(mac)	((mac.addr[0] | mac.addr[1] | mac.addr[2] |		\
							  mac.addr[3] | mac.addr[4] | mac.addr[5]) != 0)

enum
{
	AUTH_DISABLED = 0,
	AUTH_ENABLED
};

typedef struct
{
	struct eth_addr macWhiteList[WHITELIST_MAX];
	unsigned char authStatus;
} AuthConfig;

AuthConfig * ICACHE_FLASH_ATTR authGetConfig();
int ICACHE_FLASH_ATTR authWhitelistCount();
int ICACHE_FLASH_ATTR authWhitelistRemoveMac(int macIdx);
int ICACHE_FLASH_ATTR authWhitelistAddMac(struct eth_addr * mac);
int ICACHE_FLASH_ATTR authIsMacAllowed(struct eth_addr * mac);
int ICACHE_FLASH_ATTR authInit();
int ICACHE_FLASH_ATTR authCgiHook(HttpdConnData *conn);

#endif
