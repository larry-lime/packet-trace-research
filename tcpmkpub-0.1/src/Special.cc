#include "Special.h"

namespace tcpmkpub {

map<FieldTimestamp, const SpecialCase *> special_cases;

void init_special_cases()
	{
#define DEFINE_SPECIAL_CASE(fieldtype, timestamp, special_case) \
	special_cases[FieldTimestamp(fieldtype, timestamp)] = &(special_case);

#	include "local-policy/special.anon"

#undef DEFINE_SPECIAL_CASE
	}

}  // namespace tcpmkpub
