#include <stdio.h>
#include <assert.h>
#include <string.h>

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else

#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <router.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

static int _route_size = 0;
static struct route_item _route_table[26];
static struct route_item *_route_get(in_addr_t prefix, in_addr_t _submask);

static int binary_search(const struct route_item table[], int start, int end, in_addr_t khey)
{
	int mid;

	while (start < end) {
		mid = start + (end - start) / 2;
		if (table[mid].prefix < khey) {
			start = mid + 1;
		} else if (table[mid].prefix > khey) {
			end = mid;
		} else {
			return mid;
		}
	}

	return start;
}

static int route_add(in_addr_t prefix, in_addr_t submask, in_addr_t nexthop)
{
	int index;
	in_addr_t premask = 0;
	struct route_item *fib, *table = _route_table;

	assert(_route_size < ARRAY_SIZE(_route_table));
	index = binary_search(_route_table, 0, _route_size, prefix);

	fib = _route_get(prefix, 0xffffffff);
	if (fib != NULL && fib->submask < submask) premask = fib->submask;

	fib = &table[index];
	if (index < _route_size && fib->prefix == prefix) {
		while (index < _route_size) {
			fib = &table[index];
			if (fib->prefix != prefix) {
				break;
			} else if (fib->submask == submask) {
				return 0;
			} else if (fib->submask < submask) {
				premask = fib->submask;
				index++;
			} else {
				break;
			}
		}

		while (index > 0) {
			fib = &table[index -1];
			if (fib->prefix != prefix) {
				break;
			} else if (fib->submask == submask) {
				return 0;
			} else if (fib->submask > submask) {
				index--;
			} else {
				break;
			}
		}
	}

	memmove(&table[index + 1], &table[index], (_route_size - index) * sizeof(table[0]));
	table[index].submask = submask;
	table[index].nexthop = nexthop;
	table[index].premask = premask;
	table[index].prefix = prefix;
	_route_size++;

	for (index++; index < _route_size; index++) {
		fib = &table[index];
		if (fib->submask < submask) {
			break;
		} else if ((fib->prefix & submask) != prefix) {
			break;
		} else if (fib->premask < submask) {
			fib->premask = submask;
		}
	}

	return 0;
}

void route_restore(const char *route)
{
	int length = 0;
	char sprefix[16] = {};
	const char *ptr = NULL;

	for (ptr = route - 1; ptr; ptr = strchr(ptr +1, ' ')) {
		if (2 == sscanf(ptr +1, "%[0-9.]/%d", sprefix, &length)) {
			in_addr_t prefix = inet_addr(sprefix);
			route_add(htonl(prefix), ~0 << (32 - length), INADDR_LOOPBACK);
		}
	}

	return;
}

static struct route_item *_route_get(in_addr_t prefix, in_addr_t _submask)
{
	int index;
	in_addr_t submask;
	struct route_item *fib, *table = _route_table;

	index = binary_search(table, 0, _route_size, prefix & _submask);
	if (index < _route_size &&
			(table[index].prefix == (prefix & table[index].submask))) {
		while (index + 1 < _route_size) {
			if (table[index +1].prefix
					!= (prefix & table[index +1].submask)) {
				break;
			}
			index++;
		}
		return &_route_table[index];
	}

	if (index-- == 0) {
		return NULL;
	}

	fib = &table[index];
	submask = fib->submask;
	if ((submask & prefix) == fib->prefix) {
		return fib;
	} else if (fib->premask) {
		assert(fib->premask < _submask);
		return _route_get(prefix, fib->prefix);
	}

	return NULL;
}

const struct route_item *route_get(struct in_addr target)
{
#if 0
	printf("\n-------------------------\n");
	for (int i = 0; i < _route_size; i++) {
		struct route_item *item = &_route_table[i];
		printf("%d %08x %08x %08x %08x\n", i, item->prefix, item->submask, item->premask, item->nexthop);
	}
	printf("-------------------------\n");
#endif

	return _route_get(htonl(target.s_addr), ~0);
}

int route_cmd(const char *route)
{
	int length = 0;
	char sprefix[16] = {};
	char sgateway[16] = {};

	if (3 == sscanf(route, "%16[0-9.]/%d@%16s", sprefix, &length, sgateway)) {
		in_addr_t prefix = inet_addr(sprefix);
		in_addr_t gateway = inet_addr(sgateway);
		route_add(htonl(prefix), ~0 << (32 - length), htonl(gateway));
		return 0;
	}

	return -1;
}

