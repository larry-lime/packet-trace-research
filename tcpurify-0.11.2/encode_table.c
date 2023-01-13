/****************************************************************************
 * 
 * tcpurify - encode_table.c
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "tcpurify.h"
#include "encode_table.h"

#define NETWORKS 16		/* The max network triplets allowed	*/

struct Network {
  uint32_t subnet;		/* i.e. 192.168.1.0			*/
  uint32_t netmask;		/* netmask for the transformed subnet	*/
  uint32_t xformmask;		/* bits to randomize			*/
  uint32_t *table;		/* random mapping table			*/
};

static uint32_t squish (uint32_t x, uint32_t mask);
static uint32_t unsquish (uint32_t x, uint32_t mask);
static uint32_t *table_compress (uint32_t *table, uint32_t mask);
static uint32_t *table_expand (uint32_t *compressed, uint32_t mask);
static int table_create (struct Network *network);
static int table_write (FILE *fp, const struct Network *network);
static int table_read (FILE *fp, struct Network *network, int reverse);
static int mask_bits (uint32_t mask);
static void swap (uint32_t *table, uint32_t x, uint32_t y);
static void shuffle (uint32_t *table, uint32_t size);

struct Network networks[NETWORKS];

int encode_table_init (int argc, char *argv[])
{
  int i, nets = 0;
  char *eq;
  char *mapfile = NULL;
  char subnet[16], tmpfname[32];
  struct in_addr subnet_addr;
  uint32_t netmask, xformmask;
  FILE *fp;
  
  for(i = 0; i < NETWORKS; i++) {
    networks[i].subnet = 0x0;
  }

  for (i = 0; i < argc && nets <= NETWORKS; i++) {
    if ((eq = strchr (argv[i], '=')) != NULL) {
      *eq = '\0';
      eq++;
      if (strcmp (argv[i], "mapfile") == 0) {
        mapfile = eq;
        continue;
      } else {
        fprintf (stderr, "Unknown encoding option '%s'\n", argv[i]);
        return (1);
      }
    }
    
    if (sscanf (argv[i], "%15[0-9.]/%x/%x", subnet, 
                &netmask, &xformmask) != 3) {
      fprintf (stderr, "Invalid triplet %s\n", argv[i]);;
      continue;
    }
    if (inet_pton (AF_INET, subnet, &subnet_addr) < 0) {
      fprintf (stderr, "Invalid address %s: %s\n",
	       subnet, strerror (errno));
      continue;
    }
    networks[nets].netmask = netmask;
    networks[nets].xformmask = xformmask;
    memcpy (&networks[nets].subnet, &subnet_addr, sizeof(subnet_addr));
    if (!table_create (&networks[nets])) {
      networks[nets].subnet = 0;
      fprintf (stderr, "Invalid triplet %s\n", argv[i]);
      continue;
    }
    nets++;
  }

  /* If you need to increase this constant, it's in tcpurify.h */
  if (nets > NETWORKS) {
    fprintf (stderr, "tcpurify: No more than %d transformation triplets can be specified\n",
             NETWORKS);
    return (1);			/* Exit...  Maybe we should go on with the
				 * first NETWORKS connections? */
  }
  
  if (!nets && !config.reverse && !mapfile) {
    fprintf (stderr, "No mappings specified ... if this is really what you want, please use the\n");
    fprintf (stderr, "'none' encoding\n");
    return (1);
  }
  
  if (nets && config.reverse) {
    fprintf (stderr, "-r cannot be used with a mapping specification\n");
    return (1);
  }
  
  if (config.reverse && !mapfile) {
    fprintf (stderr, "A mapfile must be specified to reverse encodings\n");
    return (1);
  }
  
  if (nets) {
    int fd;
    if (!mapfile) {
      sprintf(tmpfname, "/tmp/tcpurify-map-XXXXXX");
      if ((fd = mkstemp(tmpfname)) == -1) {
        fprintf (stderr, "Could not open map file %s: %s\n",
                 tmpfname, strerror (errno));
        return 1;
      }
    } else {
      if ((fd = open (mapfile, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
        fprintf (stderr, "Could not open map file %s: %s\n",
                 mapfile, strerror(errno));
        return 1;
      }
      if ((fp = fdopen (fd, "w")) == NULL) {
        fprintf (stderr, "Could not reopen map file: %s\n", strerror (errno));
        return 1;
      }
    }
      
    /* Ensure that the mapping file is readable only by us before
     * continuing */
    if (chmod (mapfile, S_IRUSR | S_IWUSR)) {
	fprintf (stderr, "Error chmoding %s: %s\n", mapfile, strerror(errno));
	unlink (mapfile);	/* I don't care if this succeeds */
	return (1);		/* Consider this fatal and exit */
    }
    if (config.debug) {
	fprintf (stderr, "Mapping file is %s\n", mapfile);
    }
    fprintf (fp, "%d\n", nets);
    for (; nets > 0; nets--) {
	if (!table_write (fp, &networks[nets - 1])) {
	  break;
	}
    }
    if(ferror (fp)) {
	fprintf (stderr, "Error writing to %s.\n", mapfile);
    }
    fclose (fp);
  } else {
    if ((fp = fopen (mapfile, "r")) == NULL) {
      fprintf (stderr, "Could not open mapping file %s: %s\n",
               mapfile, strerror (errno));
      return (1);
    }
    
    fscanf (fp, "%d", &i);
    for (; i > 0; i--) {
      if (!table_read (fp, &networks[i - 1], config.reverse)) {
	break;
      }
    }
    if (ferror (fp)) {
      fprintf (stderr, "Error reading mapping file %s: %s\n",
               mapfile, strerror (errno));
      return (1);
    }
    fclose (fp);
  }
}

void encode_table (uint32_t *ip) 
{
  int i;
  
  /* Squint real hard and it makes sense, I promise */
  for (i = 0; networks[i].subnet != 0; i++) {
    if (((*ip & networks[i].netmask) ^ networks[i].subnet) == 0) {
      *ip = ((*ip & ~networks[i].xformmask)
	     | (networks[i].table[ntohl(*ip & networks[i].xformmask)]));
    }
  }
}

void encode_table_cleanup ()
{
}

/*
 * Assuming that mask is a 32-bit mask of the "significant" digits in an
 * integer x (i.e. only the bits you will care about in x are 1's), this
 * squishes x into the rightmost n bits needed to represent x uniquely 
 */
static uint32_t squish (uint32_t x, uint32_t mask)
{
  uint32_t i, j, y;
  
  j = y = 0;
  
  for (i = 0; i < 32; i++) {
    if (mask & 0x1) {
      y = y | ((x & mask & 0x1) << j);
      j++;
    }
    x = x >> 1;
    mask = mask >> 1;
  }
  
  return (y);
}

/*
 * See squish and think the opposite.  Obviously.
 */
static uint32_t unsquish (uint32_t x, uint32_t mask)
{
  uint32_t i, y;
  
  y = 0;
  
  for (i = 0; i < 32; i++) {
    if (mask & 0x1) {
      y = y | ((x & mask & 0x1) << i);
      x = x >> 1;
    }
    mask = mask >> 1;
  }
  
  return (y);
}

/*
 * Read the description of squish before, and then think about this function.
 * :-)  This takes a table of integers in which you only care about the
 * entries that are unique under the mask 'mask' and reduces it to the
 * minimum possible size.
 */
static uint32_t *table_compress (uint32_t *table, uint32_t mask) 
{
  uint32_t *compressed, i, size_comp, size;
  
  size_comp = squish (mask, mask) + 1;
  size = (0x1 << mask_bits(mask)) + 1;
  
  compressed = (uint32_t *)malloc (size_comp * sizeof(uint32_t));
  
  for (i = 0; i < size_comp; i++) {
    compressed[i] = table[unsquish (i, mask)];
  }
  
  return (compressed);
}

/*
 * Read unsquish, then read table_compress and think backwards.
 */
static uint32_t *table_expand (uint32_t *compressed, uint32_t mask) 
{
  uint32_t *table, i, size_comp, size;
  
  size_comp = squish (mask, mask) + 1;
  size = 0x1 << (mask_bits (mask) + 1);
  
  table = (uint32_t *)malloc (size * sizeof(uint32_t));
  
  for(i = 0; i < size_comp; i++) {
    table[unsquish (i, mask)] = compressed[i];
  }
  
  return (table);
}

/*
 * This takes a properly filled-out Network structure and creates a random
 * table in network->table for address translation.
 */
static int table_create (struct Network *network)
{
  uint32_t i, size, *temptable;
  
  if (mask_bits (network->xformmask) > 20 
     || mask_bits (network->xformmask) == 0) {
    return(0);			/* This is just too large; ARBITRARY LIMIT */
  }
  
  network->netmask = htonl (network->netmask);
  
  size = squish (network->xformmask, network->xformmask) + 1;
  size = 2 * (0x1 << mask_bits (network->xformmask));
  
  temptable = (uint32_t *)malloc (size * sizeof(uint32_t));
  for(i = 0; i < size; i++) {
    temptable[i] = htonl (unsquish (i, network->xformmask));
  }
  shuffle (temptable, size);
  network->table = table_expand (temptable, network->xformmask);
  free (temptable);
  
  network->xformmask = htonl (network->xformmask);
  
  return (1);
}

/*
 * table_write compresses a table appropriately and then writes it to stdout
 * with the necessary information from its Network structure to read it back
 * in with no loss of data.
 */
static int table_write (FILE *fp, const struct Network *network)
{
  uint32_t mask, size, *table, i;
  
  mask = ntohl (network->xformmask);
  size = squish (mask, mask) + 1;
  
  table = table_compress (network->table, mask);
  fprintf (fp, "\n%x\n", ntohl (network->subnet));
  fprintf (fp, "%x\n", ntohl (network->netmask));
  fprintf (fp, "%x\n", mask);
  for (i = 0; i < size; i++) {
    fprintf (fp, "%x\n", squish (ntohl (table[i]), mask));
  }
  free (table);
  
  if (ferror (fp)) {
    return (0);
  }
  return (1);
}

/*
 * This reads in the table written with table_write, reversing it as it goes
 */
static int table_read (FILE *fp, struct Network *network, int reverse)
{
  uint32_t i, size, temp, mask, *table;
  
  fscanf (fp, "%x", &temp);
  network->subnet = htonl (temp);
  fscanf (fp, "%x", &temp);
  network->netmask = htonl (temp);
  fscanf (fp, "%x", &mask);
  network->xformmask = htonl (mask);
  
  size = squish (mask, mask) + 1;
  table = (uint32_t *)malloc (size * sizeof(uint32_t));
  
  for (i = 0; i < size; i++) {
    fscanf (fp, "%x", &temp);
    if (reverse) {
      table[temp] = htonl (unsquish (i, mask));
    } else {
      table[i] = htonl (unsquish (temp, mask));
    }
  }
  
  network->table = table_expand (table, mask);
  free (table);

  if (ferror (fp)) {
    return (0);
  }
  return (1);
}

/*
 * Tell me the most significant 1 in mask
 */
static int mask_bits (uint32_t mask)
{
  int i, bits = 0;
  
  for (i = 0; i < 32; i++) {
    if (mask & (0x1 << i)) {
      bits = i;
    }
  }
  
  return (bits);
}

/*
 * If you don't recognize this, you shouldn't be reading this source.  ;-)
 */
static void swap (uint32_t *table, uint32_t x, uint32_t y) {
  uint32_t temp;
  
  temp = table[x];
  table[x] = table[y];
  table[y] = temp;
}

/*
 * A simple randomization function that shuffles entries 1 .. size - 2
 * of the given table.  It leaves the first and last entries for the reasons
 * discussed in the accompanying README file.
 */
static void shuffle (uint32_t *table, uint32_t size) {
  uint32_t i, j, newpos;
  
  srand (time (NULL));
  for (i = 0; i < 3; i++) {
    for (j = 1; j < size - 1; j++) {
      newpos = 1 + (int)((double)(size - 2) * rand() / (RAND_MAX + 1.0));
      swap (table, j, newpos);
    }
  }
}
