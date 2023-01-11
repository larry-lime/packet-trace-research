#ifndef data_processor_inl_h
#define data_processor_inl_h

#include "DataProcessor.h"
#include "TCPMkPub.h"

namespace tcpmkpub {

static inline DATA_PROCESSOR(Copy)
	{
	if ( len == VARLEN )
		throw Exception("unknown data length for %s", data_name);
	
	if ( offset_in + len > caplen )
		len = caplen - offset_in;

	pkt_out->dump(start + offset_in, len, offset_out);

	offset_in += len;
	offset_out += len;
	}

static inline DATA_PROCESSOR(Zero)
	{
	if ( len == VARLEN )
		throw Exception("unknown data length for %s", data_name);
	
	if ( offset_in + len > caplen )
		len = caplen - offset_in;

	pkt_out->dump((u_char) 0, len, offset_out);

	offset_in += len;
	offset_out += len;
	}

static inline DATA_PROCESSOR(Skip)
	{
	if ( len == VARLEN )
		throw Exception("unknown data length for %s", data_name);
	
	if ( offset_in + len > caplen )
		len = caplen - offset_in;

	offset_in += len;
	}

#define	KEEP		Copy
#define	ZERO		Zero
#define	SKIP		Skip

#define ZERO_IT \
	 Zero(data_name, start, caplen, \
		offset_in, len, offset_out, pkt_in, pkt_out)
#define COPY_IT \
	 Copy(data_name, start, caplen, \
		offset_in, len, offset_out, pkt_in, pkt_out)
#define SKIP_IT \
	 Skip(data_name, start, caplen, \
		offset_in, len, offset_out, pkt_in, pkt_out)
#define YOU_NAME_IT(xyz) \
	 xyz(data_name, start, caplen, \
		offset_in, len, offset_out, pkt_in, pkt_out)

static inline int check_data_length(InputPacket *pkt, const char *name, 
		int offset_in, int data_len, int caplen)
	{
	if ( offset_in + data_len > caplen ) 
		{
		if ( data_len != RESTLEN )
			{
			pkt->CheckTruncation(name, 
			                     offset_in, data_len, caplen, 
			                     true);
			}
		data_len = caplen - offset_in; 
		}
	return data_len;
	}

static inline int check_case_length(InputPacket *pkt, const char *case_name, 
		int offset_in, int case_width, int len, int caplen)
	{
	int case_len;

	if ( case_width == VARLEN )
		case_len = len; 
	else
		{
		case_len = case_width;

		// Alert on case length mismatch if case_width is fixed and 
		// len is not truncated by caplen.
		if ( case_width != len && case_width != RESTLEN && 
		     offset_in + len < caplen )
			{
			Alert("case lengeth mismatch for %s in %s: %d != %d",
				case_name, pkt->FlowID().c_str(), 
				case_width, len);	
			}
		}
	
	case_len = check_data_length(
			pkt, case_name, 
			offset_in, case_len, caplen);

	// fprintf(stderr, "%s: case_len = %d, case_width = %d, len = %d, offset_in = %d, caplen = %d\n",
	// 	case_name, case_len, case_width, len, offset_in, caplen);

	return case_len;
	}

}  // namespace tcpmkpub

#endif /* data_processor_inl_h */
