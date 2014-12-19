/*
	Configuration management
*/

#include "espmissingincludes.h"
#include <string.h>
#include <osapi.h>
#include "c_types.h"
#include "user_interface.h"
#include "espconn.h"
#include "mem.h"

#include "config.h"

#define CONFIG_SECTOR 0x3F
#define CONFIG_ADDR (SPI_FLASH_SEC_SIZE * CONFIG_SECTOR)

static config_t s_config;
static int s_config_loaded = 0;

void ICACHE_FLASH_ATTR config_read(config_t* config)
{
    spi_flash_read((uint32)CONFIG_ADDR, (uint32*) config, sizeof(config_t));
}

void ICACHE_FLASH_ATTR config_write(config_t* config)
{
    ETS_UART_INTR_DISABLE();
    spi_flash_erase_sector(CONFIG_SECTOR);
    spi_flash_write(CONFIG_ADDR, (uint32*) config, sizeof(config_t));
    ETS_UART_INTR_ENABLE();
}

config_t* ICACHE_FLASH_ATTR config_get()
{
    if (!s_config_loaded)
    {
        config_read(&s_config);
        s_config_loaded = 1;
    }
    return &s_config;
}

void ICACHE_FLASH_ATTR config_save()
{
    config_write(&s_config);
    config_t tmp;
    config_read(&tmp);
    if (memcmp(&tmp, &s_config, sizeof(config_t)) != 0)
    {
        os_printf("config verify failed");
    }
}

config_t* ICACHE_FLASH_ATTR config_init()
{
    config_t* config = config_get();
    if (config->magic != CONFIG_MAGIC || config->version != CONFIG_VERSION)
    {
    	os_printf("initializing config");
        config_init_default();
    }
    return config;
}

void ICACHE_FLASH_ATTR config_init_default()
{
    config_t* config = config_get();
    config->magic = CONFIG_MAGIC;
    config->version = CONFIG_VERSION;

    // Initialize the Authorized list
    memset(&(config->authConfig), 0, sizeof(AuthConfig));

    // Store the configuration
    config_save();

    // Reset to WIFI AP Mode
}

