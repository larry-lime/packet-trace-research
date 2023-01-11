#ifndef const_checker_h
#define const_checker_h

#include <sys/param.h>
#include "common.h"
#include "DataProcessor.h"

namespace tcpmkpub {

class ConstCheckException : public Exception
{
public:
	ConstCheckException(const char *data_name)
		: Exception("constant check failure at %s",
			data_name) 
		{}
};

enum ConstCheckAction { CORRECT, BREAK };

template<class T>
class ConstChecker : public DataProcessor
{
public:
	ConstChecker(const T &v, ConstCheckAction o = BREAK) 
		: size(sizeof(T)), val(v), otherwise(o) {}

	void operator()(const char *data_name, 
			const u_char* start, int caplen,
			int &offset_in, int len, int &offset_out, 
			InputPacket *pkt_in, OutputPacket *pkt_out) const
		{
		if ( len >= 0 && len != (int) size )
			internal_error("size mismatch for ConstChecker %d != %d", 
				len, size);

		const T *p = (const T *) (start + offset_in);

		if ( ! ( *p == val ) )
			{
			Alert("const checker failed at %s", data_name);
			switch ( otherwise )
				{
				case CORRECT:
					p = &val;
					break;
				case BREAK:
					throw ConstCheckException(data_name);
					break;
				}
			}

		pkt_out->dump((const u_char *)(p), size, offset_out);
		offset_in += size;
		offset_out += size;
		}

protected:
	size_t size;
	T val;
	ConstCheckAction otherwise;
};

static inline ConstChecker<u_char> const_n8(const u_char v, ConstCheckAction o)
	{
	return ConstChecker<u_char>(v, o);
	}

static inline ConstChecker<u_short> const_n16(const u_short v, ConstCheckAction o)
	{
	return ConstChecker<u_short>(htons(v), o);
	}

static inline ConstChecker<u_long> const_n32(const u_long v, ConstCheckAction o)
	{
	return ConstChecker<u_long>(htonl(v), o);
	}

class RangeCheckException : public Exception
{
public:
	RangeCheckException(const char *data_name)
		: Exception("range check failure at %s",
			data_name) 
		{}
};

template<class T>
class RangeChecker : public DataProcessor
{
public:
	RangeChecker(const T &lo, const T &hi)
		: size(sizeof(T)), lower(lo), upper(hi) {}

	void operator()(const char *data_name, 
			const u_char* start, int caplen,
			int &offset_in, int len, int &offset_out, 
			InputPacket *pkt_in, OutputPacket *pkt_out) const
		{
		if ( len >= 0 && len != (int) size )
			internal_error("size mismatch for ConstChecker %d != %d", 
				len, size);

		const T *p = (const T *) (start + offset_in);

		if ( ! ( lower <= *p && *p <= upper ) )
			{
			Alert("range checker failed at %s", data_name);
			throw RangeCheckException(data_name);
			}

		pkt_out->dump((const u_char *)(p), size, offset_out);
		offset_in += size;
		offset_out += size;
		}

protected:
	size_t size;
	T lower, upper;
};

struct net_short
{
	u_short v;
	net_short(u_short x) { v = htons(x); }
};

struct net_long
{
	u_long v;
	net_long(u_long x) { v = htonl(x); }
};

static inline bool operator<=(net_short a, net_short b) 
	{ return ntohs(a.v) <= ntohs(b.v); }

static inline bool operator==(net_short a, net_short b) 
	{ return ntohs(a.v) == ntohs(b.v); }

static inline bool operator<=(net_long a, net_long b) 
	{ return ntohl(a.v) <= ntohl(b.v); }

static inline bool operator==(net_long a, net_long b) 
	{ return ntohl(a.v) == ntohl(b.v); }

static inline RangeChecker<u_char> range_n8(const u_char lo, const u_char hi)
	{
	return RangeChecker<u_char>(lo, hi);
	}

static inline RangeChecker<net_short> range_n16(const u_short lo, const u_short hi)
	{
	return RangeChecker<net_short>(net_short(lo), net_short(hi));
	}

static inline RangeChecker<net_long> range_n32(const u_long lo, const u_long hi)
	{
	return RangeChecker<net_long>(net_long(lo), net_long(hi));
	}

}  // namespace tcpmkpub

#endif /* range_checker_h */
