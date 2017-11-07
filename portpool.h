#ifndef _PORTPOOL_H_
#define _PORTPOOL_H_
#include <stdint.h>

typedef struct port_pool_s {
	int _nat_count;
	unsigned short _nat_port;
	uint32_t _nat_port_bitmap[65536 / 32];
} port_pool_t;

uint16_t alloc_nat_port(port_pool_t *pool);
uint16_t use_nat_port(port_pool_t *pool, uint16_t port);
uint16_t free_nat_port(port_pool_t *pool, uint16_t port);

#endif
