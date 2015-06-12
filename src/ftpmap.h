
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

typedef struct {
    FILE *fid;
    FILE *loggerfp;
    char ip_addr[MAX_STR];
    char *answer;
    char *server;
    char *port;
    char *user;
    char *password;
    char *cmd;
    char *passwords;
    char *loggerfile;
    /* Flags */
    int versiondetected;
    int fingerprinthasmatch;
    int skipfingerprint;
    int forcefingerprint;
    int loginonly;
    int fuzzer;
    int fuzzerbufferlength;
    int fuzzerloginfirst;
    unsigned int fuzzerchar;
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

void ftpmap_detect_version_by_banner(ftpmap_t*,detect_t*);
void ftpmap_init(ftpmap_t*);
void print_usage(int);
void print_version(int);
void sigalrm(int);

#endif /*FTPMAP_H*/
