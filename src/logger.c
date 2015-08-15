/* logger.c - log output. 

  Copyright (c) Hypsurus <hypsurus@mail.ru>

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


#include "logger.h"
#include "misc.h"

void logger_open(ftpmap_t *ftpmap) {
    char filename[MAX_STR];
    sprintf(filename, "%s.log", ftpmap->server);

    if ( ftpmap->loggerfile == NULL )
        ftpmap->loggerfile = strdup(filename);

    if ( ftpmap->nolog == 0 ) {
        if (( ftpmap->loggerfp = fopen(ftpmap->loggerfile, "w+")) == NULL )
            die(1, "Unable to write log file: %s", ftpmap->loggerfile);
    }
}

void logger_write(ftpmap_t *ftpmap, char *format, ...) {
    va_list li;
    char s[MAX_STR];

    va_start(li, format);
    vsprintf(s, format, li);
    va_end(li);

    printf("%s", s);
    if ( ftpmap->nolog == 0 )
        fprintf(ftpmap->loggerfp, "%s", s);

}

void logger_close(ftpmap_t *ftpmap) {
    fclose(ftpmap->loggerfp);
    fprintf(stdout, ":: Saved log file: %s\n", ftpmap->loggerfile);
}
