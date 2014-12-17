#ifndef AUTH_H
#define AUTH_H

#include "httpd.h"

#define	WHITELIST_MAX	10

enum
{
	AUTH_DISABLED = 0,
	AUTH_ENABLED
};

#define IS_VALID_MAC(mac)	((mac.addr[0] | mac.addr[1] | mac.addr[2] |		\
							  mac.addr[3] | mac.addr[4] | mac.addr[5]) != 0)

struct eth_addr* ICACHE_FLASH_ATTR authGetWhitelist();
int ICACHE_FLASH_ATTR authWhitelistCount();
int ICACHE_FLASH_ATTR authWhitelistRemoveMac(int macIdx);
int ICACHE_FLASH_ATTR authWhitelistAddMac(struct eth_addr * mac);
int ICACHE_FLASH_ATTR authIsMacAllowed(struct eth_addr * mac);
int ICACHE_FLASH_ATTR authInit();
int ICACHE_FLASH_ATTR authCgiHook(HttpdConnData *conn);

#endif
