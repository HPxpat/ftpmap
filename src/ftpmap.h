
/* ftpmap.h - the FTP-Map project header */

#ifndef FTPMAP_H
#define FTPMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>

#define MAX_STR 256
#define MAX_ANSWER  1024
#define FTP_DEFAULT_SERVER  "localhost"
#define FTP_DEFAULT_PORT    "21"
#define FTP_DEFAULT_USER    "anonymous"
#define FTP_DEFAULT_PASSWORD    "NULL"

/* Databases */
#define DB_EXPLOITDB    "../db/ftp-exploit-db"
#define DB_VERSIONS    "../db/ftp-versions-db"

int fd;
int dfd;

typedef struct {
    FILE *fid;
    FILE *loggerfp;
    char ip_addr[MAX_STR];
    char unsoftware[MAX_STR];
    char *answer;
    char *server;
    char *port;
    char *user;
    char *password;
    char *cmd;
    char *loggerfile;
    char *path;
    int dataport;
    int scan_mode;
    /* Flags */
    int versiondetected;
    int fingerprinthasmatch;
    int skipfingerprint;
    int forcefingerprint;
    int nolog;
    int code;
 } ftpmap_t;

typedef struct {
    char fversion[MAX_STR];
    char fsoftware[MAX_STR];
    char software[MAX_STR];
    char version[MAX_STR];
    char fisoftware[MAX_STR];
} detect_t;

typedef struct {
    char exploit[MAX_STR];
    int id;
} exploit_t;

void ftpmap_init(ftpmap_t *ftpmap);
void ftpmap_end(ftpmap_t *ftpmap, detect_t *detect, exploit_t *exploit);
void print_version(int c);
void print_usage(int ex);
void print_startup(ftpmap_t *ftpmap);
void ftpmap_detect_version_by_banner(ftpmap_t *ftpmap, detect_t *detect);
void ftpmap_findexploit(ftpmap_t *ftpmap, detect_t *detect, exploit_t *exploit);
int ftpmap_compar(const void *a_, const void *b_);
void ftpmap_sendcmd(ftpmap_t *ftpmap);
void ftpmap_calc_data_port(ftpmap_t *ftpmap);
char * ftpmap_getanswer(ftpmap_t*);
char * ftpmap_getanswer_long(FILE *, ftpmap_t *);

#endif /*FTPMAP_H*/
