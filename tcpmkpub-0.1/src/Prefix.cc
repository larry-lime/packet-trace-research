#include "Prefix.h"

namespace tcpmkpub {

Prefix::Prefix(const char *s)
	{
	in_addr_t a[4];
	int len;
	if ( sscanf(s, "%u.%u.%u.%u/%d", &a[0], &a[1], &a[2], &a[3], &len) != 5 )
		throw Exception("cannot parse prefix: %s", s);

	in_addr_t ip = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
	len_ = len;
	mask_ = first_n_bit_mask(len_);
	addr_ = ip & mask_;
	}

Prefix::Prefix(const char *prefix, const char *mask)
	{
	addr_ = to_addr(prefix);
	mask_ = to_addr(mask);

	in_addr_t k = mask_;
	for ( len_ = 32; len_ > 0; --len_ )
		{
		if ( k & 1 )
			break;
		k >>= 1;
		}
	
	if ( ( len_ == 32 && k != 0xffffffffUL ) || 
	     ( len_ < 32 && k + 1 != (in_addr_t) (1 << len_) ) )
		throw Exception("illegal prefix mask: %s (%04x)", 
			mask, mask_);

	addr_ &= mask_;
	}

Prefix::Prefix(in_addr_t ip, int prefix_length)
	{
	len_ = prefix_length;
	mask_ = first_n_bit_mask(len_);
	addr_ = ip & mask_;
	// fprintf(stderr, "ip = %u, len = %d, mask = %x\n", ip, prefix_length, mask_);
	// fprintf(stderr, "prefix: %s\n", prefix_to_string(*this).c_str());
	}

}  // namespace tcpmkpub
