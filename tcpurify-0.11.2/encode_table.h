/****************************************************************************
 * 
 * tcpurify - encode_table.h
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#ifndef ENCODE_TABLE_H
#define ENCODE_TABLE_H

#include <inttypes.h>

int encode_table_init (int argc, char *argv[]);
void encode_table (uint32_t *ip);
void encode_table_cleanup ();

#endif /* ENCODE_TABLE_H */
