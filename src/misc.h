/* misc.h - Header file */
#ifndef MISC_H
#define MISC_H

#include "ftpmap.h"

/* prototypes */
void die(int,char*, ...);
void ftpmap_draw(int,int);
void ftpmap_genchars(int,char*,int);
void * xmalloc(size_t);
void sigalrm(int);

#endif /*MISC_H*/
