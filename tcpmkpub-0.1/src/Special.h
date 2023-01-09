#ifndef special_h
#define special_h

#include <string>
#include <cstring>
#include <map>
using namespace std;

#include "Packet.h"
#include "FieldType.h"
#include "DataProcessor.h"

namespace tcpmkpub {

class SpecialCase {
public:
	virtual ~SpecialCase() {}
	virtual bool operator()(DATA_PROCESSOR_ARGS) const = 0;
};

typedef pair<FieldType, double> FieldTimestamp;
extern map<FieldTimestamp, const SpecialCase *> special_cases;
extern void init_special_cases();

static inline bool check_special_case(FieldType field, DATA_PROCESSOR_ARGS)
	{
	// DebugMsg("%.6f check special case: field = %d, offset = %d", 
	//          pkt_in->Timestamp(), field, offset_in);
	bool wildcard_timestamp = false;
	FieldTimestamp ind(field, pkt_in->Timestamp());
	map<FieldTimestamp, const SpecialCase *>::const_iterator it;
	it = special_cases.find(ind);
	if ( it == special_cases.end() )
		{
		ind = FieldTimestamp(field, 0);
		it = special_cases.find(ind);
		if ( it == special_cases.end() )
			return false;
		wildcard_timestamp = true;
		}

	if ( (*it->second)(data_name, start, caplen, 
			offset_in, len, offset_out,
			pkt_in, pkt_out) )
		{
		Note("special case processed at %s %.6f field %d", 
		     input_filename, pkt_in->Timestamp(), field);
		return true;
		}
	else
		{
		if ( ! wildcard_timestamp )
			Alert("special case checking failed at field %d", field);
		return false;
		}
	}

class SpecialCaseString : public SpecialCase 
{
public:
	SpecialCaseString(string s)
		: str(s) {}

	bool operator()(DATA_PROCESSOR_ARGS) const
		{
		if ( ! check(start, offset_in, len, caplen) )
			return false;
		len = str.length();
		pkt_out->dump(start + offset_in, len, offset_out);
		offset_in += len;
		offset_out += len;
		return true;
		}

protected:
	bool check(const u_char *start, 
			int offset_in, int len, int caplen) const
		{
		if ( len == VARLEN || len >= (int) str.length() )
			len = str.length();
		else 
			{
			Alert("SpecialCaseString insufficient data: %d < %d",
				len, str.length());
			return false;
			}

		if ( offset_in + len > caplen )
			{
			Alert("SpecialCaseString out of bound: %d + %d > %d",
				offset_in, len, caplen);
			return false;
			}

		if ( memcmp(start + offset_in, str.c_str(), len) != 0 )
			{
			Alert("SpecialCaseString content mismatch");
			return false;
			}
		else
			return true;
		}

	string str;
};

class SpecialCaseIPAddr : public SpecialCase 
{
public:
	SpecialCaseIPAddr(string s)
		{
		in_addr_t a = to_addr(s.c_str());
		for ( int i = 3; i >= 0; --i )
			{
			ip[i] = a & 0xff;
			a = a >> 8;
			}
		}

	bool operator()(DATA_PROCESSOR_ARGS) const
		{
		if ( len != sizeof(ip) || offset_in + len > caplen )
			return false;
		if ( memcmp(start + offset_in, ip, sizeof(ip)) != 0 )
			return false;
		pkt_out->dump(ip, sizeof(ip), offset_out);
		offset_in += len;
		offset_out += len;
		return true;
		}

protected:
	unsigned char ip[4];
};

}  // namespace tcpmkpub

#endif /* special_h */
