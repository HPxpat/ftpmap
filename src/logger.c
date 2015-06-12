/* logger.c - log output. */

#include "logger.h"
#include "misc.h"

void logger_open(ftpmap_t *ftpmap) {
    char filename[MAX_STR];
    sprintf(filename, "%s.__log", ftpmap->server);

    if ( ftpmap->loggerfile == NULL )
        ftpmap->loggerfile = strdup(filename);

    if (( ftpmap->loggerfp = fopen(ftpmap->loggerfile, "w+")) == NULL )
        die(1, "Unable to write log file: %s", ftpmap->loggerfile);
}

void logger_write(ftpmap_t *ftpmap, char *format, ...) {
    va_list li;
    char s[MAX_STR];

    va_start(li, format);
    vsprintf(s, format, li);
    va_end(li);

    printf("%s", s);
    fprintf(ftpmap->loggerfp, "[LOG] %s", s);
    bzero(s, sizeof(s));

}

void logger_close(ftpmap_t *ftpmap) {
    fclose(ftpmap->loggerfp);
    fprintf(stdout, ":: Saved log file: %s\n", ftpmap->loggerfile);
}
