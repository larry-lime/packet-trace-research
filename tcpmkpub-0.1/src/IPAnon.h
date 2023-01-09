#ifndef ipanon_h
#define ipanon_h

namespace tcpmkpub {

class IPAnonymizer
{
public:
	virtual in_addr_t anonymize(in_addr_t) = 0;
};

}  // namespace tcpmkpub

#endif /* ipanon_h */
