#ifndef hash_h
#define hash_h

#include <sys/types.h>
#include <string.h>

#include "common.h"
#include "md5.h"

namespace tcpmkpub {

typedef u_char HashKey[16];
typedef u_char HashDigest[16];

static inline void copy_hashkey(u_char dest[16], HashKey source)
	{
	memcpy((void*) dest, source, sizeof(HashKey));
	}

static inline void print_hex(FILE *fp, size_t size, const u_char *data)
	{
	for ( int i = 0; i < (int) size; ++i )
		fprintf(fp, "%02x", data[i]);
	}

static inline char *ascii_hex(size_t size, const u_char *data)
	{
	int out_size = size * 2 + 1;
	char *out = new char[out_size];
	char *sp = out;
	for ( int i = 0; i < (int) size; ++i )
		sp += snprintf(sp, out + out_size - sp, "%02x", data[i]);
	return out;
	}

static inline void hash_md5(size_t size, const u_char *bytes, HashDigest digest)
	{
	md5_state_s h;
	md5_init(&h);
	md5_append(&h, bytes, size);
	md5_finish(&h, digest);
	}

// "Type separation"
enum HashType {
	HASH_TYPE_KEYGEN,
	HASH_TYPE_A50,
	HASH_TYPE_A49_SEPARATIST,
	HASH_TYPE_RPERM,
	HASH_TYPE_PRP,
	HASH_TYPE_AINTRASUBNET,
	HASH_TYPE_AINTERSUBNET,
	HASH_TYPE_ETHER_MAC,
	HASH_TYPE_MAC_VID,
	HASH_TYPE_MAC_HID,
};

static inline void hmac_md5(HashType type, const HashKey key,
		size_t size, const u_char *bytes, HashDigest digest)
	{
	md5_state_s h;
	u_char k_ipad[64];
	u_char k_opad[64];

	bzero(k_ipad, sizeof(k_ipad));
	bcopy(key, k_ipad, sizeof(key));
	bzero(k_opad, sizeof(k_opad));
	bcopy(key, k_opad, sizeof(key));
	for ( int i = 0; i < 64; i++ ) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	md5_init(&h);
	md5_append(&h, k_ipad, sizeof(k_ipad));
	md5_append(&h, bytes, size);
	md5_finish(&h, digest);

	digest[0] ^= (type & 0xff);
	digest[1] ^= ((type >> 8) & 0xff);

	md5_init(&h);
	md5_append(&h, k_opad, sizeof(k_opad));
	md5_append(&h, digest, sizeof(digest));
	md5_finish(&h, digest);

	if ( type == -1 )
		{
		fprintf(stderr, "hash type = %d", type);
		fprintf(stderr, ", len = %u, data = ", (unsigned int) size);
		print_hex(stderr, size, bytes);
		fprintf(stderr, ", mac = ");
		print_hex(stderr, sizeof(digest), digest);
		fprintf(stderr, "\n");
		}
	}

static inline int digest_mod_n(const HashDigest digest, int n)
	{
	if ( n > 0x10000000L )
		throw Exception("n (%d) is too big for digest_mod_n", n);

	// Now we compute r = digest % n
	// Note that this is not perfectly uniform, but I
	// suppose 2^128 is big enough that it's almost
	// uniform (assuming MD5 output is uniform).
	int r = 0;
	for ( int i = 0; i < 16; ++i )
		r = ( r * 256 + digest[i] ) % n;
	return r;
	}

}  // namespace tcpmkpub

#endif /* hash_h */
