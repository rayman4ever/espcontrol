#ifndef CGIWHITELIST_H
#define CGIWHITELIST_H

#include "httpd.h"

int ICACHE_FLASH_ATTR cgiWhitelistUpdate(HttpdConnData *connData);
int ICACHE_FLASH_ATTR cgiWhitelistAdd(HttpdConnData *connData);
int ICACHE_FLASH_ATTR cgiWhitelistDel(HttpdConnData *connData);
void ICACHE_FLASH_ATTR tplWhitelist(HttpdConnData *connData, char *token, void **arg);

#endif
