#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <config.h>

#include "natimpl.h"

typedef unsigned int u32;

struct nat_key_t {
	u32 key;
	u32 revert;
};

#define N (65536 << 1)
static int _nat_cnt = 0;
static struct nat_key_t _nat_keys[N];

int nat_create(int a, int b)
{
	struct nat_key_t *kp;

	int low = 0, middle;
	int high = _nat_cnt - 1;

	if (a == b) {
		/* invalid */
		return -1;
	}

	while (low <= high) {
		middle = (high + low) / 2;
		kp = _nat_keys + middle;

		if (kp->key == a) {
			kp->revert = a ^ b;
			break;
		} else if (kp->key > a) {
			high = middle - 1;
			continue;
		} else {
			low = middle + 1;
			continue;
		}
	}

	if (low >= high && _nat_cnt + 1 < N) {
		assert (low  <= _nat_cnt);
		kp = _nat_keys + low;
		memmove(kp + 1, kp, (_nat_cnt - low) * sizeof(*kp));
		kp->revert = a ^ b;
		kp->key = a;
		_nat_cnt++;
	}

	low = 0;
	high = _nat_cnt - 1;
	while (low <= high) {
		middle = (high + low) / 2;
		kp = _nat_keys + middle;

		if (kp->key == b) {
			kp->revert = a ^ b;
			break;
		} else if (kp->key > b) {
			high = middle - 1;
			continue;
		} else {
			low = middle + 1;
			continue;
		}
	}

	if (low >= high && _nat_cnt < N) {
		assert (low  <= _nat_cnt);
		kp = _nat_keys + low;
		memmove(kp + 1, kp, (_nat_cnt - low) * sizeof(*kp));
		kp->revert = a ^ b;
		kp->key = b;
		_nat_cnt++;
	}

	return 0;
}

int nat_map(void *p,  const void *q)
{
	struct nat_key_t *kp;

	u32 *pt = (u32 *)p;
	const u32 *qt = (const u32 *)q;

	*pt = *qt;

	int low = 0, middle;
	int high = _nat_cnt -1;

	while (low <= high) {
		middle = (high + low) / 2;
		kp = _nat_keys + middle;

		if (kp->key == *pt) {
			*pt ^= kp->revert;
			return 0;
		} else if (kp->key > *pt) {
			high = middle - 1;
			continue;
		} else {
			low = middle + 1;
			continue;
		}
	}

	return 1;
}

int nat_delete(int a, int b)
{
	struct nat_key_t *kp;

	int low = 0, middle;
	int high = _nat_cnt -1;

	if (a == b) {
		/* invalid */
		return -1;
	}

	while (low <= high) {
		middle = (high + low) / 2;
		kp = _nat_keys + middle;

		if (kp->key == a) {
			memmove(kp, kp + 1, (_nat_cnt - middle) * sizeof(*kp));
			_nat_cnt--;
			break;
		} else if (kp->key > a) {
			high = middle - 1;
			continue;
		} else {
			low = middle + 1;
			continue;
		}
	}

	low = 0;
	high = _nat_cnt -1;
	while (low < high) {
		middle = (high + low) / 2;
		kp = _nat_keys + middle;

		if (kp->key == b) {
			memmove(kp, kp + 1, (_nat_cnt - middle) * sizeof(*kp));
			_nat_cnt--;
			break;
		} else if (kp->key > b) {
			high = middle - 1;
			continue;
		} else {
			low = middle + 1;
			continue;
		}
	}

	return 0;
}

static int _nat64_on = 0;
static uint8_t _nat64_patten[16] = {0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static uint8_t _v4mapped_patten[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0};

int nat64_prefix_set(const char *prefix)
{
        inet_pton(AF_INET6, prefix, &_nat64_patten);
	_nat64_on = !!memcmp(_v4mapped_patten, _nat64_patten, 16);
        return 0;
}

int nat64_prefix_update(void *addr, int type)
{
	if (_nat64_on == 0) {
		/* do nothing since nat64 is off */
	} else if (memcmp(_nat64_patten, addr, 12) == 0 && type == NAT64_DST) {
		memcpy(addr, _v4mapped_patten, 12);
	} else if (memcmp(_v4mapped_patten, addr, 12) == 0 && type == NAT64_SRC) {
		memcpy(addr, _nat64_patten, 12);
	}

        return 0;
}
