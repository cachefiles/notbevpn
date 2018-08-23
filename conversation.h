#ifndef _CONVERSATION_H_
#define _CONVERSATION_H_

int set_conversation(unsigned key, void **udataptr);
void * get_conversation(void);

unsigned get_conversation_key(void);

void * set_conversation_udata(void *udata);
void * get_conversation_udata(void);

struct sockaddr;
struct sockaddr * pull_conversation(u_long dest);
struct sockaddr * push_conversation(struct sockaddr *dest, size_t len);

void set_default_gate(struct sockaddr *hop, size_t len);

#endif
