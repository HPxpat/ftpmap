/*  ftpmap.c - the FTP-Map project
 
  Copyright 2001-2015 The FTP-Map developers.

*/
/*
  FTP-Map is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  FTP-Map is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "ftpmap.h"
#include "testcmds.h"
#include "fingerprints.h"
#include "tcp.h"
#include "misc.h"
#include "logger.h"
#include "client.h"

void ftpmap_init(ftpmap_t *ftpmap) {
    ftpmap->port   = strdup(FTP_DEFAULT_PORT);
    ftpmap->user = strdup(FTP_DEFAULT_USER);
    ftpmap->password = strdup(FTP_DEFAULT_PASSWORD);
    ftpmap->fuzzerbufferlength = 256;
    ftpmap->fuzzerloginfirst = 1;
}

void ftpmap_end(ftpmap_t *ftpmap, detect_t *detect, exploit_t *exploit) {
    fprintf(ftpmap->fid, "QUIT\r\n");
    fclose(ftpmap->fid); 
    if ( ftpmap->scan_mode ) {
        printf("\n.:: Scan for: %s complete ::.\n", ftpmap->ip_addr);
        printf("\n:!: Please send the fingerprint to hypsurus@mail.ru to improve FTP-Map.\n\n");  
    }
    logger_close(ftpmap);
    free(ftpmap);
    free(detect);
    free(exploit);
}

void print_version(int c) {
        printf("Copyright FTP-Map %s (c) 2015 FTP-Map developers.\n"
                "\n-=[ Compiled in: %s %s\n"
                "-=[ Bug reports/help to: hypsurus@mail.ru\n",VERSION, 
                __DATE__, __TIME__);

        exit(c);
}
void print_usage(int ex) {
    printf("Usage: ftpmap -s [host] [OPTIONS]...\n\n"
          "Options:\n"
          "\t--scan, -S                 - Start FTP scan.\n"
          "\t--server, -s <host>        - The FTP server.\n"
          "\t--port, -P <port>          - The FTP port (default: 21).\n"
          "\t--user, -u <user>          - FTP user (default: anonymous).\n"
          "\t--password, -p <password>  - FTP password (default: NULL). \n"
          "\t--execute, -x <cmd>        - Run command on the FTP server.\n"
          "\t--nofingerprint, -n        - Do not generate fingerprint.\n"
          "\t--login, -A                - Only login, print output and quit.\n"
          "\t--force, -F                - Force to generate fingerprint.\n"
          "\t--output, -o <file>        - output file.\n"
          "\t--list, -L <path>          - Get list of files and folders on the FTP server.\n"
          "\t--delete <path>            - Delete files/folders on the server.\n"
          "\t--last-modified, -m <file> - Returns the last-modified time of the given file\n"
          "\n\nFuzzer Options:\n"
          "\t--fuzzer, -f               - Use the Fuzzer.\n"
          "\t--fuzzerlength,-b <length> - Buffer length to send. (default: 256)\n"
          "\t--fuzzer-nologin, -l       - Do not login.\n"
         "\n\nGeneral Options:\n"
          "\t--version, -v              - Show version information and quit.\n"
          "\t--help, -h                 - Show help and quit.\n"
          "\nPlease send bug reports/help to hypsurus@mail.ru\n"
          "License GPLv2: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>.\n");
    exit(ex);
}

void print_startup(ftpmap_t *ftpmap) {
    /*printf("%s", ftpmap_ascii);*/
    logger_write(ftpmap, "\n:: Starting FTP-Map %s - Scanning (%s:%s)...\n\n", VERSION, ftpmap->ip_addr, ftpmap->port);
}

char * ftpmap_getanswer(ftpmap_t *ftpmap) {
    static char answer[MAX_ANSWER];
    char *s = NULL;    

    *answer = 0;
 
    signal(SIGALRM, sigalrm);
    alarm(5);
    while (fgets(answer, sizeof answer, ftpmap->fid) != NULL) {
        if (strtol(answer, &s, 10) != 0 && s != NULL) {
            if (isspace(*s)) {
                return answer;
            }
        }
    }
    if (*answer == 0) {        
        ftpmap_reconnect(ftpmap,1);
    }

    return answer;
}

char * ftpmap_getanswer_long(ftpmap_t *ftpmap) {
    static char ret[MAX_ANSWER];
    char answer[MAX_ANSWER];

    signal(SIGALRM, sigalrm);
    alarm(5);
    
    while (fgets(answer, sizeof answer, ftpmap->fid) != NULL) {
        strncat(ret, answer, strlen(answer));  
    }
    if (*answer == 0) {        
        ftpmap_reconnect(ftpmap,1);
    }

    return ret;
}


void ftpmap_detect_version_by_banner(ftpmap_t *ftpmap, detect_t *detect) {
    FILE *fp;
    char v[MAX_STR];
    char vv[MAX_STR];

    logger_write(ftpmap,":: Trying to detect FTP server by banner...\n");

    if (( fp = fopen(DB_VERSIONS, "r")) == NULL )
         die(1, "Failed to open: %s. Did you try: \"make install\" ?.", DB_VERSIONS);

   sprintf(vv, "%s%s", detect->software, detect->version);

    while (( fgets(v, sizeof(v), fp)) != NULL ) {
        strtok(v, "\n");
        if ( !strcasecmp(v, vv)) {
            logger_write(ftpmap,":: FTP server running: %s\n", v);
            logger_write(ftpmap,":: No need to generate fingerprint. (use -F to disable this)\n");
            ftpmap->versiondetected = 1;
            ftpmap->skipfingerprint = 1;
            break;
        }
    }
}

int ftpmap_login(ftpmap_t *ftpmap, detect_t *detect, int v) {
    
    ftpmap->answer = ftpmap_getanswer(ftpmap);

    if ( v )
        logger_write(ftpmap,":: FTP Banner: %s", ftpmap->answer);

    sscanf(ftpmap->answer, "220 %s %s", detect->software, detect->version);

    if ( v )
        logger_write(ftpmap,":: Trying to login with: %s:%s\n", ftpmap->user, ftpmap->password);

    fprintf(ftpmap->fid, "USER %s\r\n",ftpmap->user);
    ftpmap->answer = ftpmap_getanswer(ftpmap);

    if ( ftpmap->answer == 0 )
        ftpmap_reconnect(ftpmap,1);

    if ( *ftpmap->answer == '2' )
        return 0;
    
    fprintf(ftpmap->fid, "PASS %s\r\n",ftpmap->password);
    ftpmap->answer = ftpmap_getanswer(ftpmap);  

    if ( ftpmap->answer == 0 )
        ftpmap_reconnect(ftpmap,1);

    if ( *ftpmap->answer == '2' ) {
        if ( v )
            logger_write(ftpmap,":: %s", ftpmap->answer);
        return 0;
    }

    if ( v )
        logger_write(ftpmap,":: %s", ftpmap->answer);
    return -1;
}

void ftpmap_findexploit(ftpmap_t *ftpmap, detect_t *detect, exploit_t *exploit) {
    FILE *fp;
    char l[MAX_STR];
    int cexploit = 0;

    if ( detect->fisoftware )
        sscanf(detect->fisoftware, "%s %s", detect->fsoftware, detect->fversion);

    if (( fp = fopen(DB_EXPLOITDB, "r")) == NULL )
        die(1, "Failed to open: %s. Did you try: \"make install\" ?.", DB_EXPLOITDB);


    logger_write(ftpmap,":: Searching exploits...\n");
    while (( fgets(l, sizeof(l), fp)) != NULL ) {
        sscanf(l, "%d,%[^\n]s", &exploit->id, exploit->exploit);
        
        if ( ftpmap->versiondetected ) {
            /* First search exploits by banner */
            if ( strstr(exploit->exploit, detect->software) && strstr(exploit->exploit, detect->version)) {
                ftpmap_draw(0x2d, strlen(exploit->exploit));
                logger_write(ftpmap,"\n|%8s|\n", exploit->exploit);
                ftpmap_draw(0x2d, strlen(exploit->exploit));
                logger_write(ftpmap,"|http://exploit-db.com/download/%d|\n", exploit->id); 
                ftpmap_draw(0x2d, 35);
                putchar(0x0a);
                cexploit++;
            }
        }

        else if ( ftpmap->fingerprinthasmatch ) {
            /* Second search exploit by fingerprint */
            if ( strstr(exploit->exploit,detect->fsoftware) && strstr(exploit->exploit,detect->fversion)) { 
                ftpmap_draw(0x2d, strlen(exploit->exploit));
                logger_write(ftpmap,"\n|%8s|\n", exploit->exploit);
                ftpmap_draw(0x2d, strlen(exploit->exploit));
                logger_write(ftpmap,"|http://exploit-db.com/download/%d|\n", exploit->id); 
                ftpmap_draw(0x2d, 35);
                putchar(0x0a);
                cexploit++;
            }
        }
    }

    if ( cexploit == 0 )
        logger_write(ftpmap,":: FTP-Map didn't find any exploits for %s\n", ftpmap->server);
}

int ftpmap_updatestats(const unsigned long sum, int testnb) {
    FP *f = fingerprints;
    int nf = sizeof fingerprints / sizeof fingerprints[0];
    long long err;
    
    do {
        err = (signed long long) f->testcase[testnb] - (signed long long) sum;
        if (err < 0LL) {
            err = -err;
        }
        if (err > 0LL) {
            f->err += (unsigned long) err;
        }
        f++;
        nf--;
    } while (nf != 0);
    return 0;
}

const char * seqidx2difficultystr(const unsigned long long idx) {
    return  (idx < 100ULL)? "Trivial joke" : (idx < 1000ULL)? "Easy" : (idx < 4000ULL)? "Medium" : (idx < 8000ULL)? "Formidable" : (idx < 16000ULL)? "Worthy challenge" : "Good luck!";
}

int ftpmap_findseq(ftpmap_t *ftpmap) {
    char *answer;
    int a, b, c, d, e, f;
    unsigned int port[5];
    unsigned int rndports[10000];
    int n = 0;
    unsigned long long dif = 0ULL;
    long portdif;
    int timedep = 0;
            
    srand(time(NULL));
    do {
        rndports[n] = 1024 + 
            (int) ((1.0 * (65536 - 1024) * rand()) / (RAND_MAX + 1.0));
        n++;
    } while (n < (sizeof rndports / sizeof rndports[0]));
    
    n = 0;
    do {
        fprintf(ftpmap->fid, "PASV\r\n");
        answer = ftpmap_getanswer(ftpmap);
        if (*answer != '2') {
            noseq:                        
            logger_write(ftpmap,":: Unable to determine FTP port sequence numbers\n");
            return -1;
        }
        while (*answer != 0 && *answer != '(') {
            answer++;
        }
        if (*answer != '(') {
            goto noseq;
        }
        answer++;    
        if (sscanf(answer, "%u,%u,%u,%u,%u,%u", &a, &b, &c, &d, &e, &f) < 6) {
            goto noseq;
        }
        port[n] = e * 256U + f;
        n++;
    } while (n < (sizeof port / sizeof port[0]));
    logger_write(ftpmap,":: FTP port sequence numbers : \n");
    n = 0;
    do {
        logger_write(ftpmap,":: %u, ", port[n]);
        if (n != 0) {
            portdif = (long) port[n] - (long) port[n - 1];
            if (portdif < 0L) {
                portdif = -portdif;
            }
            dif += (unsigned long long) portdif;        
        }
        {
            int n2 = 0;
            
            do {
                if (rndports[n2] == port[n]) {
                    timedep++;
                    break;
                }
                n2++;
            } while (n2 < (sizeof rndports / sizeof rndports[0]));
        }        
        n++;
    } while (n < (sizeof port / sizeof port[0]));
    if (timedep > 2) {
        logger_write(ftpmap,"\t::: POSSIBLE TRIVIAL TIME DEPENDENCY - INSECURE :::\n");
    }
    dif /= (sizeof port / sizeof port[0] - 1);
    logger_write(ftpmap,"\n:: Difficulty = %llu (%s)\n", dif, seqidx2difficultystr(dif));
    return 0;
}

int ftpmap_compar(const void *a_, const void *b_) {
    const FP *a = (const FP *) a_;
    const FP *b = (const FP *) b_;
    
    if (a->err != b->err) {
        return a->err - b->err;
    }
    return strcasecmp(b->software, a->software);
}

int ftpmap_findwinner(ftpmap_t *ftpmap, detect_t *detect) {
    FP *f = fingerprints;
    int nb = sizeof fingerprints / sizeof fingerprints[0];
    int nrep = 0;
    double max,maxerr;
    const char *olds = NULL;

    logger_write(ftpmap,":: This may be running :\n\n");
    qsort(fingerprints, sizeof fingerprints / sizeof fingerprints[0],
          sizeof fingerprints[0], ftpmap_compar);
    maxerr = (double) fingerprints[nb - 1].err;
    do {        
        max = ((double) f->err * 100.0) / maxerr;

        if (olds == NULL || strcasecmp(olds, f->software) != 0) {
            olds = f->software;
            ftpmap_draw(0x2d, 30);
            logger_write(ftpmap,"%d) %s - %.2g%%\n", nrep+1, f->software, max);
            nrep++;            
        }
        if ( nrep == 1 )
            sprintf(detect->fisoftware, "%s", f->software);
        if ( max <= 7.0 && nrep == 1 )
            ftpmap->fingerprinthasmatch = 1;
        if (nrep > 2) {
            break;
        }
        f++;
        nb--;
    } while (nb != 0);
    ftpmap_draw(0x2d, 30);
    putchar(0x0a);
    return 0;    
}

unsigned long ftpmap_checksum(const char *s) {
    unsigned long checksum = 0UL;

    while (*s != 0) {
        checksum += (unsigned char) *s++;
    }
    return checksum;
}

int ftpmap_fingerprint(ftpmap_t *ftpmap, detect_t *detect) {
    char *answer = NULL;
    const char **cmd;
    unsigned long sum;
    int testnb = 0, progress = 0, max = 0;
    FILE *fp;
    char filename[MAX_STR];

    sprintf(filename, "%s-fingerprint.log", ftpmap->ip_addr);

    if (( fp = fopen(filename, "w+")) == NULL )
        die(1, "Failed to write fingerprint log file.");

    logger_write(ftpmap,":: Trying to detect FTP server by fingerprint...\n");
    cmd = testcmds;
    max = 141;

    fprintf(fp, "# Generated by FTP-Map\n# Please send this fingerprint to hypsurus@mail.ru with the name of the server and version.\n\n\n# Fingerprint:\n\n");
    fprintf(fp, "{\n\t0UL, \"%s %s\",{\n", detect->software, detect->version);
    while (*cmd != NULL) {
        fprintf(ftpmap->fid, "%s\r\n", *cmd);
        fflush(ftpmap->fid);
        answer = ftpmap_getanswer(ftpmap);
        if (answer == NULL) {
            sum = 0UL;
        } else {
            sum = ftpmap_checksum(answer);
        }

        printf(":: Generating fingerprint [%d%%]\r", progress * 100 / max );
        fprintf(fp, "%lu,", sum);
        fflush(stdout);
        ftpmap_updatestats(sum, testnb);
        testnb++;                    
        cmd++;
        progress++;
    }
    fprintf(fp, "\n\t}\n},");
    logger_write(ftpmap,":: Fingerprint saved: %s\n", filename);
    fclose(fp);
    putchar(0x0a);
    return 0;
}

void ftpmap_sendcmd(ftpmap_t *ftpmap) {
    char *answer = NULL;
    const char **lptr = NULL;
    int shorto = 1;

    logger_write(ftpmap,":: Sending cmd: %s.\n", ftpmap->cmd);
    fprintf(ftpmap->fid, "%s\r\n", ftpmap->cmd);

    for ( lptr = long_output_cmds; *lptr; lptr++ ) {
        if ( strcasecmp(*lptr, ftpmap->cmd) == 0 ) {
           logger_write(ftpmap,"::: Retrieving data for %s...\n\n", ftpmap->cmd);
            answer = ftpmap_getanswer_long(ftpmap);
            shorto = 0;
            break;
        }

    }
    if ( shorto )
        answer = ftpmap_getanswer(ftpmap);
    logger_write(ftpmap,"%s", answer);
}

void ftpmap_fuzz(ftpmap_t *ftpmap, detect_t *detect) {
    char buffer[ftpmap->fuzzerbufferlength];
    char *answer = NULL;
    const char **ptr = NULL;
    int progress = 0, max = 141;

    if ( ftpmap->fuzzerloginfirst )
        ftpmap_login(ftpmap, detect, 0);
    ftpmap_genchars(0x41, buffer, ftpmap->fuzzerbufferlength);

    logger_write(ftpmap,":: Starting the fuzzer on: %s\n", ftpmap->ip_addr);
    for ( ptr = testcmds; *ptr; ptr++ ) {
        logger_write(ftpmap,":: Fuzzing the target => %s+0x41 * %d (%d%%)\n",  *ptr, ftpmap->fuzzerbufferlength, progress * 100 / max);
        if ((ftpmap_reconnect(ftpmap,0) == -1 )) {
                stop:
                    logger_write(ftpmap,"\n:: Connection Error: \n=> CMD: %s\n=> Buffer Length: %d\n", *ptr, strlen(buffer));
                    break;
        }
        answer = ftpmap_getanswer(ftpmap);
        if ( answer == 0 ) {
            if ((ftpmap_reconnect(ftpmap,0) < 0 ))
                goto stop;
        }

        fprintf(ftpmap->fid, "%s %s\r\n",*ptr, buffer);

        answer = ftpmap_getanswer(ftpmap);
        if ( answer == 0 ) {
            if ((ftpmap_reconnect(ftpmap,0) < 0 ))
                goto stop;
        }

        progress++;
    }
    fclose(ftpmap->fid);
}

void ftpmap_calc_data_port(ftpmap_t *ftpmap) {
    char *answer = NULL, *actualstr = NULL;
    char str[MAX_STR];
    int h1 = 0, h2 = 0, h3 = 0, h4 = 0, p1 = 0, p2 = 0;

    /* You must call this function after ftpmap_login() */
    fprintf(ftpmap->fid, "PASV\r\n");
    answer = ftpmap_getanswer(ftpmap);
   
    /* Not logged in or worng command*/
    if ( *answer == '5' ) {
        logger_write(ftpmap,"%s", answer);
        return;
    }
    
    sprintf(str, "%s", (actualstr = strstr(answer, "(")));
    sscanf(str, " (%d,%d,%d,%d,%d,%d)", &h1,&h2,&h3,&h4,&p1,&p2);
    /*h1.h2.h3.h4 - the server IP address*/
    ftpmap->dataport = p1*256+p2;
}

int main(int argc, char **argv) {
    int opt = 0, long_index = 0;
    ftpmap_t *ftpmap = xmalloc(sizeof (*ftpmap));
    detect_t *detect = xmalloc(sizeof (*detect));
    exploit_t *exploit = xmalloc(sizeof (*exploit));

    ftpmap_init(ftpmap);

    static struct option long_options[] = {
        {"server", required_argument, 0, 's'},
        {"scan", no_argument, 0, 'S'},
        {"port",   required_argument, 0, 'P'},
        {"user",   required_argument, 0, 'u'},
        {"password", required_argument, 0, 'p'},
        {"execute", required_argument, 0, 'x'},
        {"last-modified", required_argument, 0, 'm'},
        {"fuzzer", no_argument, 0, 'f'},
        {"fuzzerlength", required_argument, 0, 'b'},
        {"fuzzer-nologin", no_argument, 0, 'l'},
        {"login", no_argument, 0, 'A'},
        {"force", no_argument, 0, 'F'},
        {"output", required_argument, 0, 'o'},
        {"nofingerprint", no_argument, 0, 'n'},
        {"list", required_argument, 0, 'L'},
        {"delete", required_argument, 0, 'D'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
    };

    while (( opt = getopt_long(argc, argv, "s:P:u:p:x:b:flhvnAo:FL:D:m:S", 
                    long_options, &long_index)) != -1 ) {
            switch(opt) {
                case 's':
                        ftpmap->server = strdup(optarg);
                        break;
                case 'S':
                        ftpmap->scan_mode = 1;
                        break;
                case 'P':
                        ftpmap->port = strdup(optarg);
                        break;
                case 'u':
                        ftpmap->user = strdup(optarg);
                        break;
                case 'p':
                        ftpmap->password = strdup(optarg);
                        break;
                case 'x':
                        ftpmap->cmd = strdup(optarg);
                        break;
                case 'f':
                        ftpmap->fuzzer = 1;
                        break;
                case 'b':
                        ftpmap->fuzzerbufferlength = atoi(optarg);
                        break;
                case 'l':
                        ftpmap->fuzzerloginfirst = 0;
                        break;
                case 'A':
                        ftpmap->loginonly = 1;
                        break;
                case 'F':
                        ftpmap->forcefingerprint = 1;
                        break;
                case 'o':
                        ftpmap->loggerfile = strdup(optarg);
                        break;
                case 'n':
                        ftpmap->skipfingerprint = 1;
                        break;
                case 'L':
                        ftpmap->listpath = strdup(optarg);
                        break;
                case 'D':
                        ftpmap->deletepath = strdup(optarg);
                        break;
                case 'm':
                        ftpmap->mdtmpath = strdup(optarg);
                        break;
                case 'h':
                        print_usage(0);
                case 'v':
                        print_version(0);
                default:
                        print_usage(0);
             }
        }
    
    if ( ftpmap->server == NULL ) {
        printf("Error: Please tell me what server has to be probed (-s <host>)\n\n");
        print_usage(1);
    }
 
    logger_open(ftpmap);
    ftpmap_reconnect(ftpmap,1); 
 
    if ( ftpmap->fuzzer ) {
        ftpmap_fuzz(ftpmap,detect);
        goto end;
    }

    if ( ftpmap->scan_mode )
        print_startup(ftpmap);

    ftpmap_login(ftpmap, detect,1);
    
    if ( ftpmap->listpath ) {
        ftpmap_getlist(ftpmap);
        goto end;
    }

    if ( ftpmap->deletepath ) {
        ftpmap_delete(ftpmap);
        goto end;
    }

    if ( ftpmap->mdtmpath ) {
        ftpmap_mdtm(ftpmap);
        goto end;
    }

    if ( ftpmap->loginonly )
        goto end;

    if ( ftpmap->cmd ) {
        ftpmap_sendcmd(ftpmap);
        goto end;
    }

    /* scanning starts from here */
    if ( ftpmap->scan_mode ) {
        ftpmap_detect_version_by_banner(ftpmap,detect);

        if ( ftpmap->skipfingerprint == 0 || ftpmap->forcefingerprint ) {
            ftpmap_fingerprint(ftpmap, detect);
            ftpmap_findwinner(ftpmap,detect);
        }
    
        ftpmap_findexploit(ftpmap,detect,exploit);
        ftpmap_findseq(ftpmap);

    }

    end:
        ftpmap_end(ftpmap, detect, exploit);
    
    return 0;
}

