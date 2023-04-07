/****************************************************************************
 * 
 * tcpurify - encode_nullify.h
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#ifndef ENCODE_NULLIFY_H
#define ENCODE_NULLIFY_H

#include <inttypes.h>

int encode_nullify_init (int argc, char *argv[]);
void encode_nullify (uint32_t *ip);
void encode_nullify_cleanup ();

#endif /* ENCODE_NULLIFY_H */
