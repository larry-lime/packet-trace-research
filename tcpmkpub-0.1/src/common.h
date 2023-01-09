#ifndef common_h
#define common_h

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "config.h"

/* _GNU_SOURCE disables __FAVOR_BSD in features.h on Linux :-( */
#undef _GNU_SOURCE
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifndef __FAVOR_BSD
#error "__FAVOR_BSD not defined!"
#endif

#include <string>
using namespace std;

namespace tcpmkpub {

extern int debug;
extern double network_time;
extern const char *input_filename;
extern bool alert_off, note_off;
extern FILE *log_fp;

class Exception
{
public:
	Exception(const char *fmt, ...)
		{
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
		if ( debug )
			abort();
		}

	const char *msg() const { return msgbuf; }

protected:
	char msgbuf[1024];
};

static inline in_addr_t to_addr(const char *s)
	{
	in_addr_t a[4];
	if ( sscanf(s, "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3]) != 4 )
		throw Exception("cannot parse IP addr: %s", s);

	return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
	}

static inline string addr_to_string(const in_addr_t ip)
	{
	static char tmp[128];
	snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d",
		ip >> 24,
		(ip >> 16) & 0xff,
		(ip >> 8) & 0xff,
		ip & 0xff);
	return string(tmp);
	}

static inline int print_ip(FILE *fp, in_addr_t ip)
	{
	return fprintf(fp, "%d.%d.%d.%d",
		ip >> 24,
		(ip >> 16) & 0xff,
		(ip >> 8) & 0xff,
		ip & 0xff);
	}

static inline void internal_error(const char *fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	abort();
	}

#define ASSERT(x)	\
	{ 		\
	if ( ! (x) )  	\
		{ 	\
		internal_error("ASSERT failed at %s:%s: %s\n", \
			__FILE__, __LINE__, #x); \
		} 	\
	}

static inline void Alert(const char *msg, ...)
	{
	if ( alert_off )
		return;

	fprintf(log_fp, "Alert! %.6f %s: ", 
		network_time, 
		input_filename ? input_filename : "<no input>");
	va_list ap;
	va_start(ap, msg);
	vfprintf(log_fp, msg, ap);
	va_end(ap);
	fprintf(log_fp, "\n");
	}

static inline void DebugMsg(const char *msg, ...)
	{
	if ( ! debug )
		return;
	fprintf(log_fp, "Debug: ");
	va_list ap;
	va_start(ap, msg);
	vfprintf(log_fp, msg, ap);
	va_end(ap);
	fprintf(log_fp, "\n");
	}

static inline void Note(const char *msg, ...)
	{
	if ( note_off )
		return;
	fprintf(log_fp, "Note: ");
	va_list ap;
	va_start(ap, msg);
	vfprintf(log_fp, msg, ap);
	va_end(ap);
	fprintf(log_fp, "\n");
	}

enum ExportType {
	FOR_ALL,
	PER_TRACE,
	PER_PACKET,
};

static inline void Export(ExportType type, const char *tag, const char *msg, ...)
	{
	if ( note_off )
		return;
	fprintf(log_fp, "Export: ");
	switch ( type )
		{
		case FOR_ALL:
			fprintf(log_fp, "(for all) ");
			break;

		case PER_TRACE:
			fprintf(log_fp, "(for trace %s) ", 
				input_filename ? input_filename : "<no input>");
			break;

		case PER_PACKET:
			fprintf(log_fp, "(for packet %s %.6f) ", 
				input_filename ? input_filename : "<no input>",
				network_time);
			break;
		}

	fprintf(log_fp, "[%s] ", tag);

	va_list ap;
	va_start(ap, msg);
	vfprintf(log_fp, msg, ap);
	va_end(ap);
	fprintf(log_fp, "\n");
	}

static inline unsigned long reverse_byte_order(unsigned long x)
	{
	return ((x & 0xffUL) << 24) | ((x & 0xff00UL) << 8) | 
		((x & 0xff0000UL) >> 8) | ((x & 0xff000000UL) >> 24);
	}

}  // namespace tcpmkpub

#endif /* common_h */
