#include <sys/types.h>
#include <base_link.h>

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	int i;
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	for (i = 0; i < len; i++) {
		*fdst++ = (*fsrc++ ^ d0);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	return 0;
}

int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	int i;
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	for (i = 0; i < len; i++) {
		*fdst++ = (*fsrc++ ^ d0);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	return 0;
}

