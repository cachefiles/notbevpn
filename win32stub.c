#ifdef WIN32
#include <string.h>

int dn_comp(unsigned char *exp_dn, unsigned char *comp_dn,
		int length, unsigned char **dnptrs, unsigned char **lastdnptr)
{
	return -1;
}

int dn_expand(unsigned char *msg, unsigned char *eomorig,
		unsigned char *comp_dn, char *exp_dn,
		int length)
{
	return -1;
}

char *strcasestr(const char *haystack, const char *needle)
{
	return strstr(haystack, needle);
}

#endif
