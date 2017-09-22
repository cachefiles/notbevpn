#ifndef _ROUTER_H_
#define _ROUTER_H_
#ifdef WIN32
#define in_addr_t unsigned
#endif

struct route_item {
	in_addr_t prefix;
	in_addr_t submask;
	in_addr_t premask;
	in_addr_t nexthop;
};

void route_restore(const char *route);

int route_cmd(const char *route);
const struct route_item *route_get(struct in_addr target);

#endif

