#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <assert.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "dnsproto.h"

#ifdef __ANDROID__ 
#define dn_comp __dn_comp  
#endif

#define NTOH_PTR_SET(x, y, z) { z _t; memcpy(&_t, y, sizeof(_t)); switch (sizeof(_t)) { case 4: _t = htonl(_t); break; case 2: _t = htons(_t); break; default: break; } memcpy(x, &_t, sizeof(_t)); }

union dns_res_value {
	uint32_t u32;
	uint16_t u16;
	char *str;
	void *ptr;
};

struct dns_rsc_fixed {
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t len;
} __attribute__ ((packed));

static int get_rsc_fixed(struct dns_resource *res, struct dns_rsc_fixed *pf, const void *s, size_t len)
{
	*pf = *(const struct dns_rsc_fixed *)s;

	assert(len == sizeof(*pf));
	res->type = pf->type = ntohs(pf->type);
	res->klass = pf->klass = ntohs(pf->klass);
	res->ttl = pf->ttl = ntohl(pf->ttl);
	res->len = pf->len = ntohs(pf->len);

	return 0;
}

static const char * rsrc_verify_signature[256] = {
	[NSTYPE_A] = NSSIG_A,
	[NSTYPE_NS] = NSSIG_NS,
	[NSTYPE_CNAME] = NSSIG_CNAME,
	[NSTYPE_SOA] = NSSIG_SOA,
	[NSTYPE_PTR] = NSSIG_PTR,
	[NSTYPE_MX] = NSSIG_MX,
	[NSTYPE_AAAA] = NSSIG_AAAA,
	[NSTYPE_SRV] = NSSIG_SRV,
	[NSTYPE_OPT] = NSSIG_OPT,
};

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

const char *add_domain(struct dns_parser *parser, const char *dn)
{
	int i;
	int l;
	int n = parser->strcnt;

	for (i = 0; i < parser->strcnt; i++) {
		if (strcmp(parser->strptr[i], dn) == 0) {
			return parser->strptr[i];
		}
	}

	if (parser->strcnt >= ARRAY_SIZE(parser->strptr)) {
		fprintf(stderr, "str index is full\n");
		return NULL;
	}

	if (parser->lastptr == NULL) {
		assert (parser->strcnt == 0);
		parser->lastptr = parser->strtab;
	}

	l = strlen(dn);
	if (parser->lastptr + l + 1
			>= parser->strtab + sizeof(parser->strtab)) {
		fprintf(stderr, "str buf is full\n");
		return NULL;
	}

	parser->strcnt++;
	memcpy(parser->lastptr, dn, l + 1);
	parser->strptr[n] = parser->lastptr;
	parser->lastptr += (l + 1);
	return parser->strptr[n];
}

const uint8_t * rsc_verify_handle(struct dns_resource *res, struct dns_parser *parse, const uint8_t *buf, const uint8_t *frame, size_t msglen)
{
	int len;
	char dn[256];
	const char *dnp = NULL;
	const uint8_t *dopt = buf;

	if (res->type < 256 && rsrc_verify_signature[res->type]) {
		uint8_t *valptr = res->value;
		uint8_t *vallimit = res->value + sizeof(res->value);
		const char *signature = rsrc_verify_signature[res->type];

		while (*signature && dopt < &frame[msglen]) {
			void *btr = valptr;
			switch (*signature++) {
				case 'B':
					valptr += sizeof(dopt);
					assert(valptr < vallimit);
					memcpy(btr, &dopt, sizeof(dopt));
					dopt += res->len;
					break;

				case 'u':
					valptr += 4;
					assert(valptr < vallimit);
					NTOH_PTR_SET(btr, dopt, uint32_t);
					dopt += 4;
					break;

				case 'A':
					valptr += 4;
					assert(valptr < vallimit);
					memcpy(btr, dopt, sizeof(uint32_t));
					dopt += 4;
					break;

				case 'q':
					valptr += 2;
					assert(valptr < vallimit);
					NTOH_PTR_SET(btr, dopt, uint16_t);
					dopt += 2;
					break;

				case 's':
					valptr += sizeof(char *);
					assert(valptr < vallimit);
					len = dn_expand(frame, &frame[msglen], dopt, dn, sizeof(dn));
					if (len > 0 && (dnp = add_domain(parse, dn))) {
						memcpy(btr, &dnp, sizeof(dnp));
						dopt += len;
						break;
					}

				default:
					return &frame[msglen];
			}
		}

		if (dopt == buf + res->len) {
			return buf;
		}
	}

	return &frame[msglen];
}

#define GET_SHORT(v, p) v = ntohs(*(uint16_t *)p)

struct dns_parser * dns_parse(struct dns_parser *parser, const uint8_t *frame, size_t len)
{
	const struct dns_header *phead = (const struct dns_header *)frame;
	const uint8_t *limit = NULL;
	const uint8_t *dotp = NULL;

	char dn[256];
	int complen = 0;
	int num = 0;

	int16_t nstype, nsclass;
	struct dns_rsc_fixed f0;
	struct dns_question *nsq;
	struct dns_resource *res;
	memset(parser, 0, sizeof(*parser));

	parser->head.ident = phead->ident;
	parser->head.flags = ntohs(phead->flags);
	parser->head.question = ntohs(phead->question);
	parser->head.answer   = ntohs(phead->answer);
	parser->head.author   = ntohs(phead->author);
	parser->head.addon    = ntohs(phead->addon);

	dotp = (const uint8_t *)(phead + 1);
	limit = (const uint8_t *)(frame + len);

	if (parser->head.question >= MAX_RECORD_COUNT ||
			parser->head.answer >= MAX_RECORD_COUNT ||
			parser->head.author >= MAX_RECORD_COUNT ||
			parser->head.addon >= MAX_RECORD_COUNT) {
		fprintf(stderr, "H: %d/%d/%d/%d\n",
				parser->head.question, parser->head.answer,
				parser->head.author, parser->head.addon); 
		return NULL;
	}
		
	for (num = 0; dotp < limit && num < parser->head.question; num ++)  {
		nsq = &parser->question[num];
		complen = dn_expand(frame, limit, dotp, dn, sizeof(dn));
		if (complen <= 0) {
			return NULL;
		}

		dotp += complen;
		nsq->domain = add_domain(parser, dn);
		if (nsq->domain == NULL) {
			return NULL;
		}

		GET_SHORT(nsq->type, dotp);
		dotp += sizeof(nstype);

		GET_SHORT(nsq->klass, dotp);
		dotp += sizeof(nsclass);
	}

	for (num = 0; dotp < limit && num < parser->head.answer; num ++)  {
		res = &parser->answer[num];

		complen = dn_expand(frame, limit, dotp, dn, sizeof(dn));
		if (complen <= 0) {
			return NULL;
		}

		dotp += complen;
		res->domain = add_domain(parser, dn);
		if (res->domain == NULL) {
			return NULL;
		}

		get_rsc_fixed(res, &f0, dotp, sizeof(f0));
		dotp += sizeof(f0);

		dotp = rsc_verify_handle(res, parser, dotp, frame, len);
		dotp += f0.len;
	}

	for (num = 0; dotp < limit && num < parser->head.author; num ++)  {
		res = &parser->author[num];

		complen = dn_expand(frame, limit, dotp, dn, sizeof(dn));
		if (complen <= 0) {
			return NULL;
		}

		dotp += complen;
		res->domain = add_domain(parser, dn);
		if (res->domain == NULL) {
			return NULL;
		}

		get_rsc_fixed(res, &f0, dotp, sizeof(f0));
		dotp += sizeof(f0);

		dotp = rsc_verify_handle(res, parser, dotp, frame, len);
		dotp += f0.len;
	}

	for (num = 0; dotp < limit && num < parser->head.addon; num ++)  {
		res = &parser->addon[num];

		complen = dn_expand(frame, limit, dotp, dn, sizeof(dn));
		if (complen <= 0) {
			return NULL;
		}

		dotp += complen;
		res->domain = add_domain(parser, dn);
		if (res->domain == NULL) {
			return NULL;
		}

		get_rsc_fixed(res, &f0, dotp, sizeof(f0));
		dotp += sizeof(f0);

		dotp = rsc_verify_handle(res, parser, dotp, frame, len);
		dotp += f0.len;
	}

	if (dotp > limit) {
		return NULL;
	}

	return parser;
}

uint8_t * dn_put_domain(uint8_t *buf, uint8_t *limit, const char *domain, uint8_t **ptr, size_t count)
{
	int ret;

	if (buf < limit) {
		ret = dn_comp(domain, buf, limit - buf, ptr, ptr + count);
		if (ret > 0) {
			return buf + ret;
		}
	}

	return limit;
}

uint8_t * dn_put_short(uint8_t *buf, uint8_t *limit, uint16_t val)
{
	if (buf + sizeof(val) < limit) {
		val = htons(val);
		memcpy(buf, &val, sizeof(val));
		return buf + sizeof(val);
	}

	return limit;
}

uint8_t * dn_put_long(uint8_t *buf, uint8_t *limit, uint32_t val)
{
	if (buf + sizeof(val) < limit) {
		val = htonl(val);
		memcpy(buf, &val, sizeof(val));
		return buf + sizeof(val);
	}

	return limit;
}

uint8_t * dn_put_resource(uint8_t *dotp, uint8_t *limit, const struct dns_resource *res, struct dns_parser *parse)
{
	int ret;
	uint8_t *mark = NULL;

	if (res->type < 256 && rsrc_verify_signature[res->type]) {
		const uint8_t *right_val = res->value;
		const char *signature = rsrc_verify_signature[res->type];

		ret = dn_comp(res->domain, dotp, limit - dotp, parse->comptr, parse->comptr + MAX_RECORD_COUNT);
		if (ret <= 0 || dotp + ret >= limit) {
			return limit;
		}

		dotp += ret;
		dotp = dn_put_short(dotp, limit, res->type);
		dotp = dn_put_short(dotp, limit, res->klass);
		dotp = dn_put_long(dotp, limit, res->ttl);

		mark = dotp;
		dotp = dn_put_short(dotp, limit, res->len);

		while (*signature && dotp < limit) {
			union dns_res_value * drvp = (union dns_res_value *)right_val;
			switch (*signature++) {
				case 'B':
					memcpy(dotp, drvp->ptr, res->len);
					right_val += sizeof(void *);
					dotp += res->len;
					break;

				case 'u':
					NTOH_PTR_SET(dotp, &drvp->u32, uint32_t);
					right_val += 4;
					dotp += 4;
					break;

				case 'A':
					memcpy(dotp, &drvp->u32, sizeof(uint32_t));
					right_val += 4;
					dotp += 4;
					break;

				case 'q':
					NTOH_PTR_SET(dotp, &drvp->u16, uint16_t);
					right_val += 2;
					dotp += 2;
					break;

				case 's':
					ret = dn_comp(drvp->str, dotp, limit - dotp, parse->comptr, parse->comptr + MAX_RECORD_COUNT);
					if (ret > 0 && dotp + ret + 4 < limit) {
						right_val += sizeof(void *);
						dotp += ret;
						break;
					}

				default:
					return limit;
			}
		}

		if (dotp < limit && mark + res->len + 2 != dotp) {
			dn_put_short(mark, limit, dotp - mark - 2);
		}

		return dotp;
	}

	return limit;
}

int dns_build(struct dns_parser *parser, uint8_t *frame, size_t len)
{
	struct dns_header *phead = (struct dns_header *)frame;
	uint8_t *dotp = NULL;
	int num = 0;

	struct dns_resource *res;
	struct dns_question *nsq;

	uint8_t *limit  = &frame[len];

	phead->ident = parser->head.ident;
	phead->flags = htons(parser->head.flags);
	phead->question = htons(parser->head.question);
	phead->answer = htons(parser->head.answer);
	phead->author = htons(parser->head.author);
	phead->addon = htons(parser->head.addon);

	dotp = (uint8_t *)(phead + 1);
	memset(parser->comptr, 0, sizeof(parser->comptr));
	parser->comptr[0] = frame;

	assert(parser->head.question < MAX_RECORD_COUNT);
	for (num = 0; dotp < limit && num < parser->head.question; num ++)  {
		nsq = &parser->question[num];
		dotp = dn_put_domain(dotp, limit, nsq->domain, parser->comptr, MAX_RECORD_COUNT);
		dotp = dn_put_short(dotp, limit, nsq->type);
		dotp = dn_put_short(dotp, limit, nsq->klass);
	}

	assert(parser->head.answer < MAX_RECORD_COUNT);
	for (num = 0; dotp < limit && num < parser->head.answer; num ++)  {
		res = &parser->answer[num];
		dotp = dn_put_resource(dotp, limit, res, parser);
	}

	assert(parser->head.author < MAX_RECORD_COUNT);
	for (num = 0; dotp < limit && num < parser->head.author; num ++)  {
		res = &parser->author[num];
		dotp = dn_put_resource(dotp, limit, res, parser);
	}

	assert(parser->head.addon < MAX_RECORD_COUNT);
	for (num = 0; dotp < limit && num < parser->head.addon; num ++)  {
		res = &parser->addon[num];
		dotp = dn_put_resource(dotp, limit, res, parser);
	}

	if (dotp >= limit) {
		return -1;
	}

	return dotp - frame;

}
