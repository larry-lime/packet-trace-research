#ifndef tcpmkpub_h
#define tcpmkpub_h

// Defines the interface to TCPMkPub as a library.
namespace tcpmkpub {

// 1. Flags

// We skip preprocessing for speculative anonymization
extern bool FLAGS_speculative_anonymization;

extern bool FLAGS_alert_on_packet_truncation;
extern bool FLAGS_alert_on_non_IP_pkts;
extern bool FLAGS_alert_on_trailing_bytes;
extern bool FLAGS_export_no_UDP_checksum;

// 2. Global variables
extern int debug;
extern bool in_preprocessing;

extern FILE *log_fp;
extern const char *input_filename;
extern char pcap_errbuf[];

// The timestamp of current packet
extern double network_time;
// Alert and Note are turned off during preprocessing
extern bool alert_off;
extern bool note_off;

// 3. Functions

// Initialize the anonymizers, including (1) generating topology from 
// topology.anon; ...
void init(const char *keyinfo);

// Wrap up anonymization: generate meta-data and clean up allocations 
void finish();

// Anonymize the traces from input_files, and write output to 
// regular_dump_filename and scanner_dump_filename for regular and
// scanning traffic, respectively. 
// 
// If FLAGS_file_by_file_output is true, the output file name will be 
// <input file name>.anon
// 
void anonymize_traces(int num_input_files, 
		const char * const input_files[],
		char *pcap_filter,
		bool file_by_file_output,
		const char *regular_dump_filename,
		const char *scanner_dump_filename);

void generate_key(const char *key_file_digest, u_char *key);

}  // namespace tcpmkpub

#endif  // tcpmkpub_h
