#ifndef scanner_h
#define scanner_h

namespace tcpmkpub {

class InputPacket;

enum ScannerID 
{
	NO_SCANNER 	= 0,
	ARP_SCANNER,
	IP_SCANNER,
	NUM_SCANNER_ID,
};

// Give address addr with its corresponding packet and field name to the scan
// detector as a potential scanned address.
void detect_scanner(in_addr_t addr, InputPacket *pkt_in, const char *data_name);

// Returns the scanner ID if the field "data_name" represents address
// of a host being scanned; returns NO_SCANNER (0) otherwise.
ScannerID check_scanner(InputPacket *pkt_in, const char *data_name);

string scanner_to_string(ScannerID scanner);

}  // namespace tcpmkpub

#endif /* scanner_h */
