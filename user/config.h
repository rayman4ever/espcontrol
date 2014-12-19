#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include "auth.h"

#define CONFIG_MAGIC	0x4546494c
#define CONFIG_VERSION	1

typedef struct {
	uint32_t magic;
	uint32_t version;
	AuthConfig authConfig;
} config_t;

void config_save();
void config_init_default();
config_t* config_init();
config_t* config_get();

#endif

