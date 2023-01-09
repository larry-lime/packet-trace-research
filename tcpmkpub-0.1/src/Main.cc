#include <err.h>
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"
#include "Hash.h"
#include "TCPMkPub.h"

const char *exec_filename;

void usage(const char *exe)
	{
	fprintf(stderr, "Usage: %s [-DSTW] [-f <pcap filter>] [-k <key>] [-K] [-w <output file>] [-s <output scanner file>] <input files...>\n", exe);

	fprintf(stderr, "Options:\n\n");

	fprintf(stderr, "-D\n");
	fprintf(stderr, "Debug mode.\n\n");

	fprintf(stderr, "-S\n");
	fprintf(stderr, "Speculative mode. Ordinarily the traces will be read twice, with the first pass to collect data for generating IP address mapping. In speculative mode, the input will only be read once, and there is a (small) chance that mapping conflicts occur. The speculative mode is useful for reading traces from the standard input.\n\n");

	fprintf(stderr, "-W\n");
	fprintf(stderr, "File-by-file output mode. Each output file name is the input file name plus \".anon\" for regular packets, and \".anon-scanners\" for packets involving scanners.\n\n");

	fprintf(stderr, "-T\n");
	fprintf(stderr, "Note IP truncation and (and do not suppress the corresponding warnings)\n\n");

	fprintf(stderr, "-f <pcap filter>\n");
	fprintf(stderr, "Apply the filter on input traces. This overrides the filter defined in the policy file \"filter.anon\".\n\n");

	fprintf(stderr, "-k [<key file>:]<key digest>\n");
	fprintf(stderr, "Use <key file> (by default \".tcpmkpub-key\") as input to generate the anonymization key. The md5 digest of the key file must match the key digest to insure that the key file is not stealthily substituted. The key digest (given in the output of tcpmkpub_keygen) is a 32-byte long string representing the 128-bit digest in hexadecimal digits (as in the output of command 'md5').\n");
	fprintf(stderr, "For example:\n");
	fprintf(stderr, "-k 64eff15984a7ab2c4f710843ff010346\n");
	fprintf(stderr, "or\n");
	fprintf(stderr, "-k mykey:64eff15984a7ab2c4f710843ff010346\n\n");
	fprintf(stderr, "-K\n");
	fprintf(stderr, "-Generate a key and write to .tcpmkpub-key");

	fprintf(stderr, "-w <file>\n");
	fprintf(stderr, "Write the output trace to <file>. By default it writes the standard output\n\n");

	fprintf(stderr, "-s <file>\n");
	fprintf(stderr, "Write the output trace involving scanners to <file>. If '-s' is specified, the regular output trace (-w) will not include packets involving scanners.\n\n");
	}

int main(int argc, char *argv[])
	{
	exec_filename = argv[0];

	const char *keyinfo = 0;
	char *pcap_filter = 0;

	bool file_by_file_output = false;
	const char *regular_dump_filename = 0;
	const char *scanner_dump_filename = 0;

	setlinebuf(stderr);

#define PCAP_FILTER(f)	pcap_filter = (char*) f;
#include "local-policy/filter.anon"
#undef PCAP_FILTER

	int ch;
	while ( (ch = getopt(argc, argv, "DSTWf:k:s:w:")) != -1 )
		{
		switch (ch)
			{
			case 'D':
				tcpmkpub::debug = 1;
				break;
			case 'S':
				tcpmkpub::FLAGS_speculative_anonymization = true;
				break;
			case 'T':
				// Note packet truncation (when
				// packets are not supposed to be
				// truncated)
				tcpmkpub::FLAGS_alert_on_packet_truncation = true;
				break;
			case 'W':
				file_by_file_output = true;
				break;
			case 'f':
				if ( pcap_filter )
					{
					tcpmkpub::Alert("overriding policy filter "
					      "\"%s\" with \"%s\"", 
				              pcap_filter, optarg);
					}
				pcap_filter = optarg;
				break;
			case 'k':
				keyinfo = optarg;
				break;
			case 'w':
				regular_dump_filename = optarg;
				break;
			case 's':
				scanner_dump_filename = optarg;
				break;
			case '?':
				usage(exec_filename);
				exit(1);
			}
		}

	argc -= optind;
	argv += optind;

	// Make sure the options are complete and make sense ...
	if ( ! keyinfo )
		{
		fprintf(stderr, 
			"Error: a key must be specified with '-k'\n");
		usage(exec_filename);
		exit(1);
		}

	if ( argc == 0 && ! tcpmkpub::FLAGS_speculative_anonymization )
		{
		fprintf(stderr, 
			"Error: cannot anonymize trace from stdin unless "
			"speculative anonymization is specified "
			"(with -S)\n");
		usage(exec_filename);
		exit(1);
		}

	if ( file_by_file_output && 
	     ( regular_dump_filename || scanner_dump_filename ) )
		{
		fprintf(stderr, 
		     "Error: cannot enable file-by-file output mode (-W) "
		     "and specify output file (-w %s) at the same time", 
		     regular_dump_filename);
		usage(exec_filename);
		exit(1);
		}	

	if ( ! file_by_file_output && 
	     ! regular_dump_filename &&
	     isatty(1) )
		{
		fprintf(stderr,
			"Error: cannot dump output to a terminal\n");
		usage(exec_filename);
		exit(1);
		}

	if ( ! regular_dump_filename )
		regular_dump_filename = "-";

	// Generate the key and anonymize the traces
	try 
		{
		tcpmkpub::init(keyinfo);
		tcpmkpub::anonymize_traces(argc, 
			argv, 
			pcap_filter,
			file_by_file_output,
			regular_dump_filename, 
			scanner_dump_filename); 
		tcpmkpub::finish();
		}
	catch (const tcpmkpub::Exception &e)
		{
		fprintf(stderr, "Error: %s\n", e.msg());
		exit(1);
		}

	tcpmkpub::DebugMsg("%s finishes\n", exec_filename);
	return 0;
	}
