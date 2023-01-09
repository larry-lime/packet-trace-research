#ifndef data_processor_h
#define data_processor_h

#include "common.h"
#include "Packet.h"

namespace tcpmkpub {

const int VARLEN		= -1;
const int RESTLEN		= 1000000000L;

class InputPacket;
class OutputPacket;

#define DATA_PROCESSOR_ARGS \
		const char *data_name, 				\
		const u_char* start, int caplen,		\
		int &offset_in, int len, int &offset_out, 	\
		InputPacket *pkt_in, OutputPacket *pkt_out

#define DATA_PROCESSOR(func_name) void func_name(DATA_PROCESSOR_ARGS)
typedef void DataProcessorFunc(DATA_PROCESSOR_ARGS);

class DataProcessor
{
public:
	virtual DATA_PROCESSOR(operator()) const = 0;
};

}  // namespace tcpmkpub

#endif /* data_processor_h */
