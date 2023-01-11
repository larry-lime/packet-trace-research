#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>

#include "Hash.h"

namespace tcpmkpub {

void generate_key(const char *out)
	{
	const char * const in = "/dev/random";
	const int random_input_size = 256;

	// Read from input 
	int in_h = open(in, O_RDONLY);
	if ( in_h == -1 )
		err(1, "Error: opening input file \"%s\"", in);

	u_char *buf = new u_char[random_input_size];
	bool dot_printed = false;
	for ( int read_len = 0, num_trials = 0; read_len < random_input_size; )
		{
		int r = read(in_h, 
			buf + read_len, random_input_size - read_len);
		if ( r == -1 )
			err(1, "Error: read from \"%s\"", in);
		else if ( r == 0 )
			{
			if ( num_trials > 100 )
				{
				if ( dot_printed )
					fprintf(stderr, "\n");
				errx(1, "Error: cannot read any byte from \"%s\""
					" after %d bytes", in, read_len);
				}
			if ( num_trials % 100 == 0 )
				{
				fprintf(stderr, ".");
				dot_printed = true;
				}
			usleep(10000);
			++num_trials;
			}
		else
			num_trials = 0;
		read_len += r;
		}

	if ( dot_printed )
		fprintf(stderr, "\n");
	close(in_h);

	HashKey key, key_digest;
	hash_md5(random_input_size, buf, key);
	char* key_ascii = ascii_hex(sizeof(key), key);
	hash_md5(strlen(key_ascii), (const u_char *) key_ascii, key_digest);

	// Create the output file
	// fprintf(stderr, "Output file: \"%s\"\n", out);
	int out_h = open(out, 
		O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 
		S_IRUSR);
	if ( out_h == -1 )
		err(1, "Error: creating output file \"%s\"", out);
	FILE *out_fp = fdopen(out_h, "w");
	if ( ! out_fp )
		err(1, "Error: fdopen");

	// Print the output
	fprintf(out_fp, "%s", key_ascii);
	delete [] key_ascii;
	fclose(out_fp); 	// this closes out_h as well

	// Print the digest
	fprintf(stdout, "%s:", out);
	print_hex(stdout, sizeof(key_digest) - 8, key_digest + 8);
	fprintf(stdout, "\n");
	}

}  // namespace tcpmkpub

void usage(const char *exe)
	{
	fprintf(stderr, "Usage: %s [-o <output>]\n", exe);
	}

int main(int argc, char *argv[])
	{
	const char *out = ".tcpmkpub-key";

	int ch;
	while ( (ch = getopt(argc, argv, "o:")) != -1 )
		{
		switch(ch) 
			{
			case 'o':
				out = optarg;	
				break;
			case '?':
				usage(argv[0]);
				exit(1);
			}
		}

	tcpmkpub::generate_key(out);

	return 0;
	}
