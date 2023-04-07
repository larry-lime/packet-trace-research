/****************************************************************************
 * 
 * tcpurify - encodings.c
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#include <inttypes.h>
#include "tcpurify.h"
#include "encode_none.h"
#include "encode_nullify.h"
#include "encode_table.h"

struct EncodingFunctions encoding_table[] = {
  { "none", encode_none_init, encode_none, encode_none, encode_none_cleanup },
  { "nullify", encode_nullify_init, encode_nullify, NULL, encode_nullify_cleanup },
  { "table", encode_table_init, encode_table, encode_table, encode_table_cleanup },
  { NULL, NULL, NULL, NULL, NULL }
};
