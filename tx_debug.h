#ifndef _TX_DEBUG_H_
#define _TX_DEBUG_H_

int log_tag_putlog(const char *tag, const char *fmt, ...);

#ifdef __ANDROID__
#define log_error(fmt, args...) 
#define log_verbose(fmt, args...) 
#else
#define log_error(fmt, args...) log_tag_putlog("E", fmt, ##args)
#define log_verbose(fmt, args...) log_tag_putlog("V", fmt, ##args)
#endif

#endif
