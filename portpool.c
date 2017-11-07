#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "portpool.h"

uint16_t use_nat_port(port_pool_t *pool, uint16_t port)
{
	int index = (port / 32);
	int offset = (port % 32);

	uint32_t old = pool->_nat_port_bitmap[index];
	pool->_nat_port_bitmap[index] |= (1 << offset);
	assert(old != pool->_nat_port_bitmap[index]);
	pool->_nat_count++;

	return htons(port + 1024);
}

#define USER_PORT_COUNT (65536 - 1024)

uint16_t alloc_nat_port(port_pool_t *pool)
{
	uint32_t bitmap;
	int index, offset, bound;

	pool->_nat_port_bitmap[0] = 0xffffffff;
	if (pool->_nat_count >= USER_PORT_COUNT) {
		return 0;
	}

	pool->_nat_port += (rand() % 17);
	pool->_nat_port %= USER_PORT_COUNT;

	bound = (pool->_nat_port >> 5);
	bitmap = pool->_nat_port_bitmap[bound];

	for (offset = (pool->_nat_port % 32); offset < 32; offset++) {
		if (bitmap & (1 << offset)) {
			pool->_nat_port++;
		} else {
			return pool->_nat_port;
		}
	}

	for (index = bound + 1; index < (USER_PORT_COUNT / 32); index++) {
		if (pool->_nat_port_bitmap[index] != 0xffffffff) {
			bitmap = pool->_nat_port_bitmap[index];
			offset = 0;
			goto found;
		}
	}

	for (index = 0; index < bound; index++) {
		if (pool->_nat_port_bitmap[index] != 0xffffffff) {
			bitmap = pool->_nat_port_bitmap[index];
			offset = 0;
			goto found;
		}
	}

	pool->_nat_port = bound * 32;
	for (offset = 0; offset < (pool->_nat_port % 32); offset++) {
		if (bitmap & (1 << offset)) {
			pool->_nat_port++;
		} else {
			return pool->_nat_port;
		}
	}

	return 0;

found:
	pool->_nat_port = index * 32;
	for (offset = 0; offset < 32; offset++) {
		if (bitmap & (1 << offset)) {
			pool->_nat_port++;
		} else {
			return pool->_nat_port;
		}
	}

	return pool->_nat_port;
}

uint16_t free_nat_port(port_pool_t *pool, uint16_t port)
{
	int index, offset;

	port = htons(port) - 1024;
	index = (port / 32);
	offset = (port % 32);

	pool->_nat_port_bitmap[index] &= ~(1 << offset);
	pool->_nat_count--;

	return 0;
}

