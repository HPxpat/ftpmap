/* misc.h - Header file */
#ifndef MISC_H
#define MISC_H

#include "ftpmap.h"

#define KB_PREFIX   "KB"
#define MB_PREFIX   "MB"
#define GB_PREFIX   "GB"
#define TB_PREFIX   "TB"

/* prototypes */
void die(int,char*, ...);
void ftpmap_draw(int,int);
void ftpmap_genchars(int,char*,int);
void * xmalloc(size_t);
void sigalrm(int);
char * calc_bytes_size(size_t); 
char * fret(char *, ...);

#endif /*MISC_H*/
