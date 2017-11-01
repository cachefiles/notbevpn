#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>

#ifdef __linux__
#define __BSD_VISIBLE 1
#define	__packed	__attribute__((__packed__))
#define	__aligned(x)	__attribute__((__aligned__(x)))
#include <bsd/queue.h>
#include <bsdinet/ip.h>
#include <bsdinet/ip6.h>
#include <bsdinet/tcp.h>
#endif

#ifndef __BSD_VISIBLE
#include <sys/queue.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#endif

#include <bsdinet/tcpup.h>

#define TCPIP_MAXOLEN TCP_MAXOLEN
#define min(a, b) ((a) < (b)? (a): (b))

/*
 * Parse TCP options and place in tcpupopt.
 */
int tcpip_dooptions(struct tcpupopt *to, u_char *cp, int cnt)
{
	static char _null_[] = {0};
	int opt, optlen, oldcnt = cnt;
	to->to_flags = 0;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		switch (opt) {
			case TCPOPT_MAXSEG:
				if (optlen != TCPOLEN_MAXSEG)
					continue;
				to->to_flags |= TOF_MSS;
				memcpy(&to->to_mss, cp + 2, sizeof(to->to_mss));
				to->to_mss = ntohs(to->to_mss);
				break;

			case TCPOPT_WINDOW:
				if (optlen != TCPOLEN_WINDOW)
					continue;
				to->to_flags |= TOF_SCALE;
				to->to_wscale = (cp[2] < 14? cp[2]: 14);
				break;

			case TCPOPT_TIMESTAMP:
				if (optlen != TCPOLEN_TIMESTAMP)
					continue;
				to->to_flags |= TOF_TS;
				memcpy(&to->to_tsval, cp + 2, sizeof(to->to_tsval));
				to->to_tsval = ntohl(to->to_tsval);
				memcpy(&to->to_tsecr, cp + 6, sizeof(to->to_tsecr));
				to->to_tsecr = ntohl(to->to_tsecr);
				break;
			case TCPOPT_SACK_PERMITTED:
				if (optlen != TCPOLEN_SACK_PERMITTED)
					continue;
				to->to_flags |= TOF_SACKPERM;
				break;
			case TCPOPT_SACK:
				if (optlen <= 2 || (optlen - 2) % TCPOLEN_SACK != 0)
					continue;
				to->to_flags |= TOF_SACK;
				to->to_nsacks = (optlen - 2) / TCPOLEN_SACK;
				to->to_sacks = cp + 2;
				break; 
			default:
				continue;
		}              
	}                      

	return oldcnt;         
}              

/*
 * Insert TCP options according to the supplied parameters to the place
 * optp in a consistent way. Can handle unaligned destinations.
 *
 * The order of the option processing is crucial for optimal packing and
 * alignment for the scarce option space.
 *
 * The optimal order for a SYN/SYN-ACK segment is:
 * MSS (4) + NOP (1) + Window scale (3) + SACK permitted (2) +
 * Timestamp (10) + Signature (18) = 38 bytes out of a maximum of 40.
 *
 * The SACK options should be last. SACK blocks consume 8*n+2 bytes.
 * So a full size SACK blocks option is 34 bytes (with 4 SACK blocks).
 * At minimum we need 10 bytes (to generate 1 SACK block). If both
 * TCP Timestamps (12 bytes) and TCP Signatures (18 bytes) are present,
 * we only have 10 bytes for SACK options (40 - (12 + 18)).
 */
int tcpip_addoptions(struct tcpupopt *to, u_char *optp)
{      
	u_int mask, optlen = 0;

	for (mask = 1; mask < TOF_MAXOPT; mask <<= 1) {
		if ((to->to_flags & mask) != mask)
			continue;
		if (optlen == TCPIP_MAXOLEN)
			break;
		switch (to->to_flags & mask) {
			case TOF_MSS:
				while (optlen % 4) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCPIP_MAXOLEN - optlen < TCPOLEN_MAXSEG)
					continue;
				optlen += TCPOLEN_MAXSEG;
				*optp++ = TCPOPT_MAXSEG;
				*optp++ = TCPOLEN_MAXSEG;
				to->to_mss = htons(to->to_mss);
				memcpy(optp, &to->to_mss, sizeof(to->to_mss));
				optp += sizeof(to->to_mss);
				break;
			case TOF_SCALE:
				while (!optlen || optlen % 2 != 1) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCPIP_MAXOLEN - optlen < TCPOLEN_WINDOW)
					continue;
				optlen += TCPOLEN_WINDOW;
				*optp++ = TCPOPT_WINDOW;
				*optp++ = TCPOLEN_WINDOW;
				*optp++ = to->to_wscale;
				break;
			case TOF_SACK:
				{
					int sackblks = 0;
					struct sackblk *sack = (struct sackblk *)to->to_sacks;
					tcp_seq sack_seq;

					while (!optlen || optlen % 4 != 2) {
						optlen += TCPOLEN_NOP;
						*optp++ = TCPOPT_NOP;
					}
					if (TCPIP_MAXOLEN - optlen < TCPOLEN_SACKHDR + TCPOLEN_SACK)
						continue;
					optlen += TCPOLEN_SACKHDR;
					*optp++ = TCPOPT_SACK;
					sackblks = min(to->to_nsacks,
							(TCPIP_MAXOLEN - optlen) / TCPOLEN_SACK);
					*optp++ = TCPOLEN_SACKHDR + sackblks * TCPOLEN_SACK;
					while (sackblks--) {
						sack_seq = (sack->start);
						memcpy(optp, &sack_seq, sizeof(sack_seq));
						optp += sizeof(sack_seq);
						sack_seq = (sack->end);
						memcpy(optp, &sack_seq, sizeof(sack_seq));
						optp += sizeof(sack_seq);
						optlen += TCPOLEN_SACK;
						sack++;
					}
					break;
				}
			case TOF_TS:
				while (!optlen || optlen % 4 != 2) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}      
				if (TCPIP_MAXOLEN - optlen < TCPOLEN_TIMESTAMP)
					continue;
				optlen += TCPOLEN_TIMESTAMP;
				*optp++ = TCPOPT_TIMESTAMP;
				*optp++ = TCPOLEN_TIMESTAMP;
				to->to_tsval = htonl(to->to_tsval);
				to->to_tsecr = htonl(to->to_tsecr);
				memcpy(optp, &to->to_tsval, sizeof(to->to_tsval));
				optp += sizeof(to->to_tsval);
				memcpy(optp, &to->to_tsecr, sizeof(to->to_tsecr));
				optp += sizeof(to->to_tsecr);
				break;

			case TOF_SACKPERM:
				while (optlen % 2) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}      
				if (TCPIP_MAXOLEN - optlen < TCPOLEN_SACK_PERMITTED)
					continue;
				optlen += TCPOLEN_SACK_PERMITTED;
				*optp++ = TCPOPT_SACK_PERMITTED;
				*optp++ = TCPOLEN_SACK_PERMITTED;
				break;

			case TOF_DESTINATION:
				break;

			default:
				/* (0, "unknown TCP option type"); */
				assert(0);
				break;
		}
	}

	/* Terminate and pad TCP options to a 4 byte boundary. */
	if (optlen % 4) {

		optlen += TCPOLEN_EOL;  
		*optp++ = TCPOPT_EOL;  
	}  
	/*  
	 * According to RFC 793 (STD0007):  
	 * "The content of the header beyond the End-of-Option option  
	 * must be header padding (i.e., zero)."  
	 * and later: "The padding is composed of zeros."  
	 */  
	while (optlen % 4) {  
		optlen += TCPOLEN_PAD;  
		*optp++ = TCPOPT_PAD;  
	}  

	return (optlen);  
}  

#define TCPUP_MAXOLEN 64

/*
 * Parse TCP options and place in tcpupopt.
 */
int tcpup_dooptions(struct tcpupopt *to, u_char *cp, int cnt)
{
	static char _null_[] = {0};
	int opt, optlen, oldcnt = cnt;
	to->to_flags = 0;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		switch (opt) {
			case TCPOPT_MAXSEG:
				if (optlen != TCPOLEN_MAXSEG)
					continue;
				to->to_flags |= TOF_MSS;
				bcopy((char *)cp + 2,
						(char *)&to->to_mss, sizeof(to->to_mss));
				to->to_mss = ntohs(to->to_mss);
				break;
			case TCPOPT_TIMESTAMP:
				if (optlen != TCPOLEN_TIMESTAMP)
					continue;
				to->to_flags |= TOF_TS;
				memcpy(&to->to_tsval, cp + 2, sizeof(to->to_tsval));
				to->to_tsval = ntohl(to->to_tsval);
				memcpy(&to->to_tsecr, cp + 6, sizeof(to->to_tsecr));
				to->to_tsecr = ntohl(to->to_tsecr);
				break;
#if 0
			case TCPOPT_WINDOW:
				if (optlen != TCPOLEN_WINDOW)
					continue;
				to->to_flags |= TOF_SCALE;
				to->to_wscale = (cp[2] < 14? cp[2]: 14);
				break;
			case TCPOPT_SACK_PERMITTED:
				if (optlen != TCPOLEN_SACK_PERMITTED)
					continue;
				to->to_flags |= TOF_SACKPERM;
				break;
#endif
			case TCPOPT_DESTINATION:
				to->to_flags |= TOF_DESTINATION;
				to->to_dsaddr = cp + 2;
				to->to_dslen = optlen - 2;
				assert(optlen >= 2);
				break;

			case TCPOPT_SACK:
				if (optlen <= 2 || (optlen - 2) % TCPOLEN_SACK != 0)
					continue;
				to->to_flags |= TOF_SACK;
				to->to_nsacks = (optlen - 2) / TCPOLEN_SACK;
				to->to_sacks = cp + 2;
				break;
			default:
				continue;
		}
	}

	return sizeof(struct tcpuphdr) + oldcnt;
}

int tcpup_addoptions(struct tcpupopt *to, u_char *optp)
{
	u_int mask, optlen = 0;

	for (mask = 1; mask < TOF_MAXOPT; mask <<= 1) {
		if ((to->to_flags & mask) != mask)
			continue;
		if (optlen == TCPUP_MAXOLEN)
			break;
		switch (to->to_flags & mask) {
			case TOF_MSS:
				while (optlen % 4) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCPUP_MAXOLEN - optlen < TCPOLEN_MAXSEG)
					continue;
				optlen += TCPOLEN_MAXSEG;
				*optp++ = TCPOPT_MAXSEG;
				*optp++ = TCPOLEN_MAXSEG;
				to->to_mss = htons(to->to_mss);
				memcpy(optp, &to->to_mss, sizeof(to->to_mss));
				optp += sizeof(to->to_mss);
				break;
			case TOF_SCALE:
				while (!optlen || optlen % 2 != 1) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCPUP_MAXOLEN - optlen < TCPOLEN_WINDOW)
					continue;
				optlen += TCPOLEN_WINDOW;
				*optp++ = TCPOPT_WINDOW;
				*optp++ = TCPOLEN_WINDOW;
				*optp++ = to->to_wscale;
				break;
			case TOF_SACK:
				{
					int sackblks = 0;
					struct sackblk *sack = (struct sackblk *)to->to_sacks;
					tcp_seq sack_seq;

					while (!optlen || optlen % 4 != 2) {
						optlen += TCPOLEN_NOP;
						*optp++ = TCPOPT_NOP;
					}
					if (TCPUP_MAXOLEN - optlen < TCPOLEN_SACKHDR + TCPOLEN_SACK)
						continue;
					optlen += TCPOLEN_SACKHDR;
					*optp++ = TCPOPT_SACK;
					sackblks = min(to->to_nsacks,
							(TCPUP_MAXOLEN - optlen) / TCPOLEN_SACK);
					*optp++ = TCPOLEN_SACKHDR + sackblks * TCPOLEN_SACK;
					while (sackblks--) {
						sack_seq = (sack->start);
						memcpy(optp, &sack_seq, sizeof(sack_seq));
						optp += sizeof(sack_seq);
						sack_seq = (sack->end);
						memcpy(optp, &sack_seq, sizeof(sack_seq));
						optp += sizeof(sack_seq);
						optlen += TCPOLEN_SACK;
						sack++;
					}
					break;
				}
			case TOF_TS:
				while (!optlen || optlen % 4 != 2) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCPUP_MAXOLEN - optlen < TCPOLEN_TIMESTAMP)
					continue;
				optlen += TCPOLEN_TIMESTAMP;
				*optp++ = TCPOPT_TIMESTAMP;
				*optp++ = TCPOLEN_TIMESTAMP;
				to->to_tsval = htonl(to->to_tsval);
				to->to_tsecr = htonl(to->to_tsecr);
				memcpy(optp, &to->to_tsval, sizeof(to->to_tsval));
				optp += sizeof(to->to_tsval);
				memcpy(optp, &to->to_tsecr, sizeof(to->to_tsecr));
				optp += sizeof(to->to_tsecr);
				break;
			case TOF_SACKPERM:
				break;
			case TOF_DESTINATION:
				while (!optlen || optlen % 2 != 1) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCPUP_MAXOLEN - optlen < TCPOLEN_DESTINATION + to->to_dslen)
					continue;
				optlen += (to->to_dslen + TCPOLEN_DESTINATION);
				*optp++ = TCPOPT_DESTINATION;
				*optp++ = (to->to_dslen + TCPOLEN_DESTINATION);
				memcpy(optp, to->to_dsaddr, to->to_dslen);
				optp += to->to_dslen;
				break;

			default:
				/* (0, "unknown TCP option type"); */
				assert(0);
				break;
		}
	}

	/* Terminate and pad TCP options to a 4 byte boundary. */
	if (optlen % 4) {
		optlen += TCPOLEN_EOL;
		*optp++ = TCPOPT_EOL;
	}
	/*
	 * According to RFC 793 (STD0007):
	 * "The content of the header beyond the End-of-Option option
	 * must be header padding (i.e., zero)."
	 * and later: "The padding is composed of zeros."
	 */
	while (optlen % 4) {
		optlen += TCPOLEN_PAD;
		*optp++ = TCPOPT_PAD;
	}

	return (optlen);
}

unsigned tcpip_checksum(unsigned cksum,  const void *buf, size_t len, int finish)
{
	unsigned short *digit = (unsigned short *)buf;

	while (len > 1) {
		cksum += (*digit++);
		len -= 2;
	}

	if (len > 0 && finish) {
		unsigned short t0 = ntohs(*digit) & ~0xff;
		cksum += htons(t0);
	}

	return cksum;
}

int ip_checksum(void *buf, size_t len)
{
    unsigned short *digit;
    unsigned long cksum = 0;
    unsigned short cksum1 = 0;

    digit = (unsigned short *)buf;
    while (len > 1) {
        cksum += (*digit++);
        len -= 2;
    }

    if (len > 0) {
        cksum += *(unsigned char *)digit;
    }

    cksum1 = (cksum >> 16);
    while (cksum1 > 0) {
        cksum  = cksum1 + (cksum & 0xffff);
        cksum1 = (cksum >> 16);
    }

    cksum1 = (~cksum);
    return cksum1;
}

int tcp_checksum(unsigned cksum, void *buf, size_t len)
{
    unsigned short cksum1 = 0;
    cksum += htons(6 + len);
    cksum = tcpip_checksum(cksum, buf, len, 1);

    cksum1 = (cksum >> 16);
    while (cksum1 > 0) {
        cksum  = cksum1 + (cksum & 0xffff);
        cksum1 = (cksum >> 16);
    }

    return (~cksum) & 0xffff;
}

int udp_checksum(unsigned cksum, void *buf, size_t len)
{
    unsigned short cksum1 = 0;
    cksum += htons(IPPROTO_UDP + len);
    cksum = tcpip_checksum(cksum, buf, len, 1);

    cksum1 = (cksum >> 16);
    while (cksum1 > 0) {
        cksum  = cksum1 + (cksum & 0xffff);
        cksum1 = (cksum >> 16);
    }

    return (~cksum) & 0xffff;
}

