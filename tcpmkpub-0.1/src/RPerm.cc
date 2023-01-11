#include "common.h"
#include "RPerm.h"
#include "Anon.h"

#include <map>
using namespace std;

namespace tcpmkpub {

RPerm::RPerm(int arg_n, HashKey key, size_t seed_size, const u_char *seed)
	{
	n = arg_n;

	perm = new int[n];
	for ( int k = 0; k < n; ++k )
		perm[k] = k;

	struct { int k; u_char seed[16]; } hash_data;
	hash_md5(seed_size, seed, hash_data.seed);

	for ( int k = n; k > 0; --k )
		{
		hash_data.k = htonl(k);
		u_char digest[16];
		hmac_md5(HASH_TYPE_RPERM, key, 
			sizeof(hash_data), (const u_char *) &hash_data, 
			digest);

		int r = digest_mod_n(digest, k);
		int x = perm[k-1];
		perm[k-1] = perm[r];
		perm[r] = x;
		}
	}

static u_char first_n_bit_mask(int n)
	{
	if ( n == 0 )
		return 0;
	if ( n > 8 )
		return 0xff;
	return ~((1 << (8 - n)) - 1);
	}

struct Bits
{
	u_char* bits;
	int begin, end;
	int num_bytes;
	u_char begin_mask, end_mask;
	
	Bits(int begin, int end, const u_char *data)
		{
		int begin_byte = begin / 8;
		int end_byte = (end + 7) / 8;
		num_bytes = end_byte - begin_byte;
		bits = new u_char[num_bytes];
		for ( int i = 0; i < num_bytes; ++i )
			bits[i] = data[begin_byte + i];
		begin_mask = (begin % 8) ? ~first_n_bit_mask(begin % 8) : 0xff;
		end_mask = (end % 8) ? first_n_bit_mask(end % 8) : 0xff;
		bits[0] &= begin_mask;
		bits[num_bytes - 1] &= end_mask;
		}

	void xor_hash(const Bits &x, HashKey key)
		{
		if ( num_bytes > (int) sizeof(HashDigest) )
			throw Exception("too many bytes (%d) for xor_hash", 
				num_bytes);

		HashDigest digest;
		hmac_md5(HASH_TYPE_PRP, key, x.num_bytes, x.bits, digest);
		for ( int i = 0; i < num_bytes; ++i )
			bits[i] ^= digest[i];
		bits[0] &= begin_mask;
		bits[num_bytes - 1] &= end_mask;
		}
};

// Pseudo-random permutation
// Based on [Luby and Rackoff]:
// "Pseudo-random permutation generators and cryptographic composition"
// http://portal.acm.org/citation.cfm?id=12167
// 
void prp_md5(HashType type, HashKey key,
		size_t seed_size, const u_char *seed, 
		size_t num_bits, const u_char *input, u_char *output)
	{
	struct { int k; u_char seed[16]; } hash_data;
	hash_md5(seed_size, seed, hash_data.seed);

	int Lbits = num_bits / 2;

	Bits L(0, Lbits, input);
	Bits R(Lbits, num_bits, input);

	const int num_rounds = 4;
	for ( int k = 0; k < num_rounds; ++k )
		{
		// Generate pseudo-random key2
		hash_data.k = htonl(k);
		u_char key2[16];
		hmac_md5(type, key, 
			sizeof(hash_data), (const u_char *) &hash_data, 
			key2);

		if ( k % 2 )
			L.xor_hash(R, key2);
		else
			R.xor_hash(L, key2);
		}

	// Merge L and R to output
	int output_i = 0;
	for ( int i = 0; i < L.num_bytes; ++i, ++output_i )
		output[output_i] = L.bits[i];
	if ( Lbits % 8 )
		--output_i;
	for ( int i = 0; i < R.num_bytes; ++i, ++output_i )
		output[output_i] = R.bits[i];
	if ( Lbits % 8 )
		output[L.num_bytes - 1] |= L.bits[L.num_bytes - 1];
	if ( num_bits % 8 )
		output[output_i - 1] &= R.end_mask;
	}

static inline void to_bits(int num_bits, u_long k, u_char x[])
	{
	if ( num_bits % 8 )
		k = k << (8 - num_bits % 8);

	int num_bytes = (num_bits + 7) / 8;
	for ( int i = num_bytes - 1; i >= 0; --i )
		{
		x[i] = k & 0xff;
		k = k >> 8;
		}
	}

static inline u_long from_bits(int num_bits, u_char x[])
	{
	u_long k = 0;
	int num_bytes = (num_bits + 7) / 8;
	for ( int i = 0; i < num_bytes; ++i )
		k = (k << 8) | x[i];
	if ( num_bits % 8 )
		k = k >> (8 - num_bits % 8);
	return k;
	}

u_long prp_md5(HashType type, HashKey key,
		size_t seed_size, const u_char *seed, 
		size_t num_bits, u_long input)
	{
	u_char x[4], y[4];
	to_bits(num_bits, input, x);
	prp_md5(type, key, 
		seed_size, seed,
		num_bits, x, y);
	return from_bits(num_bits, y);
	}

u_long prp_md5_n(HashType type, HashKey key,
		size_t seed_size, const u_char *seed, 
		u_long n, u_long input)
	{
	if ( input >= n )
		throw Exception("input (%u) out of range [0, %u)",
			input, n);

	int num_bits;
	u_long k;
	for ( num_bits = 1, k = 2; num_bits < 32; ++num_bits, k = k << 1 )
		if ( k >= n )
			break;
		
	for (;;)
		{
		u_long output = prp_md5(type, key, 
			seed_size, seed, 
			num_bits, input);
		if ( output < n )
			return output;
		input = output;
		}
	}

void verify_prp(HashKey key, u_long N)
	{
	map<u_long, u_long> inverse;
	u_char seed[] = {1, 2, 3, 4, 5};

	for ( u_long s = 0; s < N; ++s )
		{
		u_long k = prp_md5_n(HASH_TYPE_PRP, key, 
			sizeof(seed), seed, N, s);
		
		// now the mapping is s->k
		if ( inverse.find(k) != inverse.end() )
			throw Exception("conflict in PRP: %u, %u -> %u",
				inverse[k], s, k);
		
		inverse[k] = s;
		Note("PRP (over %u): %u -> %u", N, s, k);
		}
	}

void verify_prp(HashKey key)
	{
	verify_prp(key, 1 << 2);
	verify_prp(key, 1 << 8);
	// verify_prp(key, 1 << 16);
	verify_prp(key, 1 << 11);
	verify_prp(key, 101);
	}

}  // namespace tcpmkpub
