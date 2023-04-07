#include <fcntl.h>
#include <pcap.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

#include "Anon.h"
#include "Ethernet.h"
#include "IP.h"
#include "IPAddr.h"
#include "Hash.h"
#include "Packet.h"
#include "RPerm.h"
#include "Scanner.h"
#include "Topology.h"

namespace tcpmkpub {

bool FLAGS_speculative_anonymization = false;
bool FLAGS_alert_on_packet_truncation = false;
bool FLAGS_alert_on_non_IP_pkts = false;
bool FLAGS_alert_on_trailing_bytes = false;
bool FLAGS_export_no_UDP_checksum = false;

int debug = 0;
bool in_preprocessing = true;

FILE *log_fp = stderr;
const char *exec_filename;
const char *input_filename = 0;
char pcap_errbuf[PCAP_ERRBUF_SIZE];

// The timestamp of current packet
double network_time = 0;
// Alert and Note are turned off during preprocessing
bool alert_off = false;
bool note_off = false;

namespace {

int parse_hex(char ch)
	{
	if ( ch >= '0' && ch <= '9' )
		return ch - '0';
	else if ( ch >= 'a' && ch <= 'f' )
		return 10 + (ch - 'a');
	else
		throw tcpmkpub::Exception("invalid hexadecimal digit '%c'", ch);
	}

}  // private namespace

void generate_key(const char *key_file_digest, u_char *key)
	{
	const int key_digest_size = 32;
	// Extract the key digest
	int len = strlen(key_file_digest);
	if ( len < key_digest_size )
		{
		throw Exception("key \"%s\" does not contain an md5 digest\n", 
			key_file_digest);
		}

	const char *key_digest = key_file_digest + len - key_digest_size;

	// Extract the key file name
	char *key_file;
	if ( len == key_digest_size )
		key_file = strdup(".tcpmkpub-key");
	else
		{
		key_file = strdup(key_file_digest);
		if ( key_file[len - key_digest_size - 1] != ':' )
			{
			throw Exception("key \"%s\" does not contain a key "
				"file name followed by a ':'\n",
				key_file_digest);
			}
		key_file[len - key_digest_size - 1] = '\0';
		}

	// Read from the key file
	int in_h = open(key_file, O_RDONLY);
	if ( in_h == -1 )
		throw Exception("Error: opening key file \"%s\"", key_file);

	char key_ascii[2 * sizeof(HashKey)];
	int r = read(in_h, key_ascii, sizeof(key_ascii));
	if ( r != sizeof(key_ascii) )
		{
		if ( r == -1 )
			throw Exception("Error: read from \"%s\"", key_file);
		else
			throw Exception("Error: cannot read %d bytes from \"%s\"", 
				sizeof(key_ascii), key_file);
		}
	close(in_h);
	free(key_file);

	// Verify the digest
	HashDigest digest;
	hash_md5(sizeof(key_ascii), (const u_char *) key_ascii, digest);
	char *digest_ascii = ascii_hex(sizeof(digest), digest);

	// Check the lower <key_digest_size> digits
	if ( strcmp(digest_ascii + 32 - key_digest_size, key_digest) != 0 )
		{
		throw Exception("Error: digest verification failed: %s != %s\n",
			digest_ascii, key_digest);
		}

	delete [] digest_ascii;

	Export(FOR_ALL, "key MD5 digest", "%s", key_digest);

	// Parse the key
	for ( unsigned int i = 0; i < sizeof(HashKey); ++i )
		{
		int d0 = parse_hex(key_ascii[i * 2]);
		int d1 = parse_hex(key_ascii[i * 2 + 1]);

		key[i] = (u_char) (d0 * 16 + d1);
		}
	}

void init(const char *keyinfo)
	{
	HashKey tcpmkpub_key;
	generate_key(keyinfo, tcpmkpub_key);

	// verify_prp(tcpmkpub_key);
	init_ip_addr_anonymization(tcpmkpub_key, init_topology());
	init_mac_addr_anonymization(tcpmkpub_key);
	init_special_cases();
	}

void finish()
	{
	finish_ip_addr_anonymization();
	}

bool anonymize_packet(InputPacket *pkt_in, OutputPacket *pkt_out, int pkt_dlt)
	{
	network_time = pkt_in->Timestamp();

	DebugMsg("processing packet %.6f", network_time);

	int offset_in = 0;
	int offset_out = 0;

	switch ( pkt_dlt )
		{
		case DLT_EN10MB:
			anonymize_ethernet_pkt("Ethernet Packet",
				pkt_in->Pkt(), pkt_in->Len(),
				offset_in, pkt_in->Len(), offset_out,
				pkt_in, pkt_out);
			break;

		default:
			Alert("cannot handle datalink type %d\n", pkt_dlt);
			return false;
		}

	// Note: it's possible that trailing cruft will be added
	// to fill out frames to their minimum size.
	if ( offset_in < (int) pkt_in->Len() && FLAGS_alert_on_trailing_bytes )
		{
		Alert("trailing bytes unprocessed: packet %d bytes, processed %d bytes", 
			pkt_in->Len(), offset_in);
		}

	return true;
	}

void dump_packet(pcap_dumper_t* dump_d, 
		const struct pcap_pkthdr &hdr, OutputPacket *pkt_out)
	{
	struct pcap_pkthdr new_hdr = hdr;
	new_hdr.len = hdr.len;
	new_hdr.caplen = pkt_out->Len();
	// DebugMsg("output packet len = %d, pkt = %p", new_hdr.caplen, pkt_out->Pkt());
	pcap_dump((u_char*)dump_d, &new_hdr, (u_char *)pkt_out->Pkt());
	}

pcap_t *prepare_input(const char *pkt_filename,
		char *pcap_filter, 
		int *pkt_dlt)
	{
	pcap_t *pkt_d = 0;
	DebugMsg("TRACE: %s", pkt_filename);

	struct bpf_program bpf_prog;

	if ( ! ( pkt_d = pcap_open_offline(pkt_filename, pcap_errbuf) ) )
		{
		Alert("can't open file %s\n", pkt_filename);
		return 0;
		}

	// Install the BPF filter
	if ( pcap_filter )
		{
		if ( pcap_compile(pkt_d, &bpf_prog, pcap_filter, 1, 0xffffff00) )     
			{
			pcap_perror(pkt_d, "pcap_compile");
			pcap_close(pkt_d);
			return 0;
			}
		else if ( pcap_setfilter(pkt_d, &bpf_prog) )  
			{
			pcap_perror(pkt_d, "pcap_setfilter");
			pcap_close(pkt_d);
			return 0;
			}
		}

	if ( pkt_dlt )
		*pkt_dlt = pcap_datalink(pkt_d);

	// Set the global variable "input_filename"
	input_filename = pkt_filename;

	return pkt_d;
	}

pcap_dumper_t *prepare_output(const char *dump_filename, pcap_t * pkt_d)
	{
	// open a pcap_dumper
	pcap_dumper_t *dump_d;
	if ( ! ( dump_d = pcap_dump_open(pkt_d, dump_filename) ) )
       		{
       		Alert("can't open file %s\n", dump_filename);
		return 0;
       		}
	return dump_d;
	}

// Go through trace pkt_d, call anonymize_packet() on each packet, and dump the
// resulting packet to either dump_regular_d or dump_scanner_d. The output 
// packet is dumped to dump_scanner_d if dump_scanner_d is not 0, and if the 
// packet is determined to be part of scanning traffic. When both 
// dump_regular_d and dump_scanner_d are 0 (during preprocessing phase), 
// packets still go through anonymize_packet(), but dumping will be skipped.
// 
int go_through_trace(pcap_t * pkt_d, 
		int pkt_dlt,
		pcap_dumper_t *dump_regular, 
		pcap_dumper_t *dump_scanner)
	{
	int output_packet_count = 0;
 	struct pcap_pkthdr hdr;
	const u_char* pkt;
	OutputPacket pkt_out(68);

	// Initialize global variable network_time
	network_time = 0;

	while ( (pkt = pcap_next(pkt_d, &hdr)) )
		{
		InputPacket pkt_in(hdr, pkt);

		pkt_in.CheckTruncation("pcap packet", 0, hdr.len, hdr.caplen, 
		                       FLAGS_alert_on_packet_truncation);

		pkt_out.reset();

		try 
			{
			anonymize_packet(&pkt_in, &pkt_out, pkt_dlt);

			pcap_dumper_t *d;

			// Dump scan packets to a separate file
			if ( dump_scanner && pkt_in.is_scan() )
				d = dump_scanner;
			else
				d = dump_regular;

			if ( d )
				{
				dump_packet(d, hdr, &pkt_out);
				++output_packet_count;
				}
			}
		catch (const Exception &e)
			{
			fprintf(stderr, "Error: %.6f %s\n", network_time, e.msg());
			}
		}

	network_time = 0;

	return output_packet_count;
	}

int count_packets(const char *file_name)
	{
	pcap_t *pkt_d;
	if ( ! ( pkt_d = prepare_input(file_name, "", 0) ) )
		return -1;

	int packet_count = 0;
	pcap_pkthdr hdr;
	while ( pcap_next(pkt_d, &hdr) )
		++packet_count;
	return packet_count;
	}

void anonymize_traces(int num_input_files, 
		const char * const input_files[],
		char *pcap_filter,
		bool file_by_file_output,
		const char *regular_dump_filename,
		const char *scanner_dump_filename)
	{
	pcap_t *pkt_d;	
	pcap_dumper_t *dump_regular = 0, *dump_scanner = 0;
	int trace_i = 0;
	int pkt_dlt;

	// Preprocessing the traces if we are not in speculative mode and not 
	// reading from a standard input
	if ( ! FLAGS_speculative_anonymization && num_input_files > 0 )
		{
		in_preprocessing = true;
		for ( trace_i = 0; trace_i < num_input_files; ++trace_i )
			{
			if ( ! ( pkt_d = prepare_input(input_files[trace_i], 
					pcap_filter, &pkt_dlt) ) )
				continue;

			alert_off = note_off = true;
			go_through_trace(pkt_d, pkt_dlt, 0, 0);
			alert_off = note_off = false;

			pcap_close(pkt_d);
			}
		in_preprocessing = false;
		}

	if ( ! FLAGS_speculative_anonymization )
		DebugMsg("The 2nd pass starts...");

	in_preprocessing = false;

	// Go through traces 
	trace_i = 0;
	do 
		{
		string regular_output_file_str, scanner_output_file_str;

		// Open input files
		const char *pkt_filename = 
			num_input_files == 0 ? "-" : input_files[trace_i];

		int num_input_packets, num_output_packets;
		if ( num_input_files == 0 )
			num_input_packets = -1;
		else
			num_input_packets = count_packets(pkt_filename);

		if ( ! ( pkt_d = prepare_input(pkt_filename, 
		                               pcap_filter, 
		                               &pkt_dlt) ) )
			goto end_of_trace;

		// Generate the output file name(s) for file-by-file output
		if ( file_by_file_output )
			{
			regular_output_file_str = string(pkt_filename) + ".anon";
			regular_dump_filename = regular_output_file_str.c_str();
			dump_regular = 0;

			scanner_output_file_str = string(pkt_filename) + ".anon-scanners";
			scanner_dump_filename = scanner_output_file_str.c_str();
			dump_scanner = 0;
			}

		// Open output files
		if ( ! dump_regular )
			{
			if ( ! ( dump_regular = prepare_output(regular_dump_filename, pkt_d) ) )
				goto end_of_trace;
			}

		if ( ! dump_scanner && scanner_dump_filename )
			{
			if ( ! ( dump_scanner = prepare_output(scanner_dump_filename, pkt_d) ) )
				goto end_of_trace;
			}

		// Go through the trace
		num_output_packets = 
			go_through_trace(pkt_d, pkt_dlt, 
			                 dump_regular, dump_scanner);

		if ( num_input_packets >= 0 )
			{
			Export(PER_TRACE, "removed packets", 
				"%d (total input packets: %d)", 
				num_input_packets - num_output_packets, 
				num_input_packets);
			}

		end_of_trace:
			{
			if ( pkt_d )
				{
				pcap_close(pkt_d);
				pkt_d = 0;
				}

			if ( file_by_file_output )
				{
				if ( dump_regular )
					{
					pcap_dump_close(dump_regular);
					dump_regular = 0;
					}
				if ( dump_scanner )
					{
					pcap_dump_close(dump_scanner);
					dump_scanner = 0;
					}
				}
			}
		}
	while ( ++trace_i < num_input_files );

	if ( dump_regular )
		{
		pcap_dump_close(dump_regular);
		dump_regular = 0;
		}

	if ( dump_scanner )
		{
		pcap_dump_close(dump_scanner);
		dump_scanner = 0;
		}
	}

}  // namespace tcpmkpub

