#include <map>
#include <string>
using namespace std;

#include "RPerm.h"
#include "EtherAddr.h"
#include "DataProcessor.h"
#include "Scanner.h"
#include "Anon.h"

namespace tcpmkpub {

struct Mac
{
	u_char mac[6];
	ScannerID scanner;

	Mac()			
		{ 
		memset(mac, 0, sizeof(mac)); 
		scanner = NO_SCANNER;
		}

	Mac(const u_char m[6], ScannerID s)	
		{ 
		memcpy(mac, m, sizeof(mac)); 
		scanner = s;
		}

	Mac(const Mac &x) 	
		{ 
		memcpy(mac, x.mac, sizeof(mac)); 
		scanner = x.scanner;
		}

	u_long vid() const 
		{
		return (mac[0] << 16) | (mac[1] << 8) | mac[2];
		}

	u_long hid() const 
		{
		return (mac[3] << 16) | (mac[4] << 8) | mac[5];
		}

	Mac& operator=(const Mac &x)
		{ 
		memcpy(mac, x.mac, sizeof(mac)); 
		scanner = x.scanner;
		return *this;
		}

	bool operator==(const Mac &x) const
		{ 
		return memcmp(mac, x.mac, sizeof(mac)) == 0 &&
			scanner == x.scanner; 
		}

	bool operator<(const Mac &x) const
		{
		if ( scanner != x.scanner )
			return scanner < x.scanner;
		for ( int i = 0; i < (int) sizeof(mac); ++i )
			if ( mac[i] != x.mac[i] )
				return mac[i] < x.mac[i];
		return false;
		}

	string to_string() const
		{
		static char buf[32];
		snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x (%s)", 
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
			scanner_to_string(scanner).c_str()); 
		return string(buf);
		}
};

class AMac
{
public:
	AMac(HashKey key);
	~AMac();
	void anonymize(const Mac& input, Mac& output);

protected:
	void do_anonymize(const Mac& input, Mac& output);
	void map_mac_bits(const u_char input[3], u_char output[3],
		size_t seed_size, const u_char *seed, 
		bool keep_all_zero, 
		bool preserve_multicast_bit);
	HashKey key;
	map<Mac, Mac> mac_map;
};

AMac::AMac(HashKey arg_key)
	{
	copy_hashkey(const_cast<u_char *>(key), arg_key);
	}

AMac::~AMac()
	{
	}

void AMac::map_mac_bits(const u_char input[3], u_char output[3],
		size_t seed_size, const u_char *seed, 
		bool keep_all_zero, 
		bool preserve_multicast_bit)
	{
	static const u_char all_zero[3] = {0, 0, 0};
	static const u_char all_one[3] = {0xff, 0xff, 0xff};

	if ( ( memcmp(all_zero, input, 3) == 0 && keep_all_zero ) ||
	     memcmp(all_one, input, 3) == 0 )
		{
		memcpy(output, input, 3);
		return;
		}

	u_char tmp[3];
	tmp[2] = input[0];
	tmp[1] = input[1];
	tmp[0] = input[2];

	int num_bits = preserve_multicast_bit ? 23 : 24;
	u_char multicast_bit = input[0] & 1;

	for (;;)
		{
		prp_md5(HASH_TYPE_ETHER_MAC, key, 
			seed_size, seed,
			num_bits, tmp, output);

		memcpy(tmp, output, 3);

		// No matter whether to keep_all_zero, one cannot
		// be mapped to all_zero
		if ( memcmp(all_zero, output, 3) != 0 &&
		     memcmp(all_one, output, 3) != 0 )
			break;
		}

	output[2] = tmp[0];
	output[1] = tmp[1];
	output[0] = tmp[2];
	if ( preserve_multicast_bit )
		output[0] |= multicast_bit;
	}

void AMac::do_anonymize(const Mac& input, Mac& output)
	{
	static const u_char all_0[] = {0, 0, 0, 0, 0, 0};
	static const u_char all_1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	static const Mac all_zero(all_0, NO_SCANNER);
	static const Mac all_one(all_1, NO_SCANNER);

	if ( input == all_zero || input == all_one )
		{
		output = input;
		return;
		}

	// Map the first three bytes (vendor ID)
	u_long scanner = htonl(input.scanner);
	map_mac_bits(input.mac, output.mac, 
		sizeof(scanner), (const u_char *) &scanner, false, true);

	// Then the first three bytes are used as seed in computing the
	// permutation for the later three bytes
	struct {
		u_long vid;
		u_long scanner;
	} seed = { 
		htonl(input.vid()), 
		scanner,
		};
	map_mac_bits(input.mac + 3, output.mac + 3, 
		sizeof(seed), (const u_char *) &seed, true, false);

	output.scanner = input.scanner;
	}

void AMac::anonymize(const Mac& input, Mac& output)
	{
	map<Mac, Mac>::const_iterator it = mac_map.find(input);
	if ( it != mac_map.end() )
		{
		output = it->second;
		return;
		}

	do_anonymize(input, output);

	mac_map[input] = output;
	Note("%.6f %s: MAC address mapping: %s -> %s",
		network_time, input_filename, 
		input.to_string().c_str(), 
		output.to_string().c_str()); 
	}

// Ethernet MAC address anonymizer
AMac *amac = 0;

void init_mac_addr_anonymization(HashKey key)
	{
	if ( ! amac )
		amac = new AMac(key);
	}

DATA_PROCESSOR(anonymize_ethernet_addr)
	{
	if ( ! amac )
		{
		ZERO_IT;
		return;
		}
		
	Mac input, output;
	for ( int i = 0; i < (int) sizeof(Mac); ++i )
		input.mac[i] = (i < len) ? start[offset_in + i] : 0;
	input.scanner = check_scanner(pkt_in, data_name);

	amac->anonymize(input, output);

	pkt_out->dump(output.mac, len, offset_out);
	offset_in += len;
	offset_out += len;
	}

}  // namespace tcpmkpub
