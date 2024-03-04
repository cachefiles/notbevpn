#ifndef  _NAT_H
#define  _NAT_H

int nat_create(int a, int b);
int nat_delete(int a, int b);
int nat_map(void *p, const void *q);

#define NAT64_SRC 1
#define NAT64_DST 1
#define NAT64_PREFIX_UPDATE nat64_prefix_update
int nat64_prefix_set(const char *prefix);
int nat64_prefix_update(void *addr, int type);

#endif
