#ifndef prefix_h
#define prefix_h

#include <sys/types.h>
#include <netinet/in.h>
#include <string>
#include <vector>

using namespace std;

#include "common.h"
#include "Hash.h"

namespace tcpmkpub {

// #define first_n_bit_mask(n)	(~(0xFFFFFFFFUL >> (n)))
static inline in_addr_t first_n_bit_mask(int n)
	{
	return (n >= 32 ? 0xFFFFFFFFUL : ~(0xFFFFFFFFUL >> n));
	}

class Prefix
{
public:
	Prefix(in_addr_t ip = 0, int prefix_length = 32);
	Prefix(const char *s);
	Prefix(const char *prefix, const char *mask);
	Prefix(const Prefix &prefix)
		{
		addr_ = prefix.addr();
		len_ = prefix.len();
		mask_ = prefix.mask();
		}

	in_addr_t addr() const 	{ return addr_; }
	in_addr_t mask() const 	{ return mask_; }
	in_addr_t len() const 	{ return len_; }

	bool includes(in_addr_t a) const 
		{
		return (a & mask()) == addr();
		}

	bool includes(const Prefix &prefix) const
		{
		return len() <= prefix.len() && includes(prefix.addr());
		}

	bool operator==(const Prefix &prefix) const
		{
		return addr() == prefix.addr() && len() == prefix.len();
		}

	bool operator<(const Prefix &prefix) const
		{
		if ( addr() != prefix.addr() )
			return addr() < prefix.addr();
		else
			return len() < prefix.len();
		}

	string to_string() const
		{
		static char tmp[128];
		in_addr_t ip = addr();
		snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d/%d",
			ip >> 24,
			(ip >> 16) & 0xff,
			(ip >> 8) & 0xff,
			ip & 0xff, 
			len());
		return string(tmp);
		}

protected:
	in_addr_t addr_, mask_;
	int len_;
};

#if 0
static inline string prefix_to_string(const Prefix &prefix)
	{
	static char tmp[128];
	in_addr_t ip = prefix.addr();
	snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d/%d",
		ip >> 24,
		(ip >> 16) & 0xff,
		(ip >> 8) & 0xff,
		ip & 0xff, 
		prefix.len());
	return string(tmp);
	}
#endif

// from tcpdpriv
static inline int bi_ffs(in_addr_t value)
	{
	int add = 0;
	static int bvals[] = { 0, 4, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1 };

	if ( (value & 0xFFFF0000) == 0 )
		{
		if ( value == 0 )
			// zero input ==> zero output.
			return 0;

		add += 16;
		}

	else
		value >>= 16;

	if ( (value & 0xFF00) == 0 )
		add += 8;
	else
		value >>= 8;

	if ( (value & 0xF0) == 0 )
		add += 4;
	else
		value >>= 4;

	return add + bvals[value & 0xf];
	}

static inline void sort_prefixes_by_len(const vector<Prefix> &a, vector<Prefix> &b)
	{
	vector<Prefix> prefix_by_len[33];
	for ( unsigned int i = 0; i < a.size(); ++i )
		prefix_by_len[a[i].len()].push_back(a[i]);
	b.clear();
	for ( unsigned int i = 0; i <= 32; ++i )
		for ( unsigned int j = 0; j < prefix_by_len[i].size(); ++j )
			b.push_back(prefix_by_len[i][j]);
	}

static inline void hash_prefix(HashType ty, HashKey key, const Prefix &prefix, 
		u_char digest[])
	{
	struct { in_addr_t addr; int len; } hash_seed =
		{ htonl(prefix.addr()), htonl(prefix.len()) };

	hmac_md5(ty, key, 
		sizeof(hash_seed), (const u_char *) &hash_seed, digest);
	}

static inline int hash_prefix(HashType ty, HashKey key, const Prefix &prefix,
		 int n)
	{
	u_char digest[16];
	hash_prefix(ty, key, prefix, digest);
	return digest_mod_n(digest, n);
	}

}  // namespace tcpmkpub

#endif /* prefix_h */
