/****************************************************************************
 *
 * This code is shamelessly ripped from Dr. Ostermann's source code examples,
 * from the file ~sdo/polltest/polltest.c.  Don't talk to me if it sucks. ;-)
 * 
 * Thanks, Dr. Ostermann.
 * 
 * I fixed some const problems.  I admit.  I changed it.  Now you can talk to
 * me if you don't like any of the consts.
 * 
 ***************************************************************************/

#ifndef TIMEVAL_H
#define TIMEVAL_H

#include <sys/time.h>

void tvsub( struct timeval *tdiff, const struct timeval *t1, const struct timeval *t0);
int tvgreater( const struct timeval *tleft, const struct timeval *tright);

#endif /* TIMEVAL_H */
