#ifndef RPerm_h
#define RPerm_h

#include "Hash.h"

namespace tcpmkpub {

// Pseudo-random permutation of 0..n-1. The pseudo-randomness comes
// from the provided key and seed, thus from the same key we always
// get the same permutation. Note: the memory requirement is O(n),
// so please do not use it with a large n.

class RPerm
{
public:
	RPerm(int n, HashKey key, size_t seed_size, const u_char *seed);
	~RPerm()
		{
		delete [] perm;
		}

	int operator[](int k) const
		{
		if ( k >= 0 && k < n )
			return perm[k];
		else
			return -1;
		}

protected:
	int n;
	int *perm;
};

void prp_md5(HashType type, HashKey key,
		size_t seed_size, const u_char *seed, 
		size_t num_bits, const u_char *input, u_char *output);

u_long prp_md5(HashType type, HashKey key,
		size_t seed_size, const u_char *seed, 
		size_t num_bits, u_long input);

u_long prp_md5_n(HashType type, HashKey key,
		size_t seed_size, const u_char *seed, 
		u_long n, u_long input);

void verify_prp(HashKey key);

}  // namespace tcpmkpub

#endif /* RPerm_h */
