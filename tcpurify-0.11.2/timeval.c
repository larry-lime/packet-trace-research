/****************************************************************************
 *
 * This code is shamelessly ripped from Dr. Ostermann's source code examples,
 * from the file ~sdo/polltest/polltest.c.  Don't talk to me if it sucks. ;-)
 * 
 * Thanks, Dr. Ostermann.
 * 
 ***************************************************************************/

#include "timeval.h"

void
tvsub(
    struct timeval *tdiff,
    const struct timeval *pt1,
    const struct timeval *pt0)
{
  
        tdiff->tv_sec = pt1->tv_sec - pt0->tv_sec;
        tdiff->tv_usec = pt1->tv_usec - pt0->tv_usec;
        if (tdiff->tv_usec < 0)
                tdiff->tv_sec--, tdiff->tv_usec += 1000000;
}

int
tvgreater(
    const struct timeval *ptleft,
    const struct timeval *ptright)
{
    struct timeval tdiff;
 
    tvsub(&tdiff,ptleft,ptright);
 
    return(tdiff.tv_sec >= 0);
}
