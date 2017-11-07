#include <time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

#include <config.h>
#include <base_link.h>
#include <conversation.h>

static unsigned _last_conversation_key = 0;
static void ** _last_conversation_ptr = NULL;

int set_conversation(unsigned key, void **udataptr)
{
	_last_conversation_key = key;
	_last_conversation_ptr = udataptr;
	return 0;
}

void * get_conversation(void)
{
	return _last_conversation_ptr;
}

unsigned get_conversation_key(void)
{
	return _last_conversation_key;
}

void * set_conversation_udata(void *udata)
{
	void * old = NULL;

	if (_last_conversation_ptr) {
		old = *_last_conversation_ptr;
		*_last_conversation_ptr = udata;
		return old;
	}

	return 0;
}

void * get_conversation_udata(void)
{
	if (_last_conversation_ptr) {
		return *_last_conversation_ptr;
	}

	return 0;
}

#define MAX_CONVERSATION 100
struct conversation_context {
	time_t last_active;
	unsigned conversation;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} u;
};

static struct conversation_context _conversation_source[MAX_CONVERSATION];

struct sockaddr * pull_conversation(struct sockaddr *dest, size_t len)
{
	struct conversation_context *c;

	c = (struct conversation_context *)get_conversation_udata();
	if (c == NULL || c < _conversation_source
			|| c >= _conversation_source + MAX_CONVERSATION) {
		return dest;
	}

	if (c->last_active + 30 <= time(NULL)) {
		LOG_DEBUG("source is delete");
	}

	return SOT(&c->u);
}

#define CLIENTID(id) (htonl(id) & 0xffff)

static struct sockaddr * alloc_new_conversation(struct sockaddr *dest, size_t len)
{
	int i;
	time_t now;
	struct conversation_context *c;
	struct conversation_context *idle = NULL;

	time(&now);
	for (i = 0; i < MAX_CONVERSATION; i++) {
		c = &_conversation_source[i];
		if (c->conversation == CLIENTID(_last_conversation_key)) {
			LOG_DEBUG("reuse old client id: %x %x\n", c->conversation, htonl(_last_conversation_key));
			goto found;
		} else if (c->last_active + 300 < now) {
			idle = c;
		}
	}

	if (idle != NULL) {
		c = idle;
		c->conversation = CLIENTID(_last_conversation_key);
		LOG_DEBUG("create new client id: %x %x\n", c->conversation, htonl(_last_conversation_key));
		goto found;
	}

	LOG_DEBUG("client table is full: %x\n",  _last_conversation_key);
	return dest;

found:
	assert (len < sizeof(c->u));
	c->last_active = time(NULL);
	memcpy(&c->u, dest, len);
	set_conversation_udata(c);
	return SOT(&c->u);
}

struct sockaddr * push_conversation(struct sockaddr *dest, size_t len)
{
	struct conversation_context *c;

	if (get_conversation() == NULL) {
		return dest;
	}

	c = (struct conversation_context *)get_conversation_udata();
	if (c == NULL || c < _conversation_source
			|| c >= _conversation_source + MAX_CONVERSATION) {
		return alloc_new_conversation(dest, len);
	}

	if (c->conversation != CLIENTID(_last_conversation_key)) {
		return dest;
	}
	
	assert (len < sizeof(c->u));
	c->last_active = time(NULL);
	memcpy(&c->u, dest, len);
	return dest;
}

