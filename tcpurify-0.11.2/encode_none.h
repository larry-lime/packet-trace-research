/****************************************************************************
 * 
 * tcpurify - encode_none.h
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#ifndef ENCODE_NONE_H
#define ENCODE_NONE_H

#include <inttypes.h>

int encode_none_init (int argc, char *argv[]);
void encode_none (uint32_t *ip);
void encode_none_cleanup ();

#endif /* ENCODE_NONE_H */
