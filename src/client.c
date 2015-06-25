/* client.c - FTP client stuff 
 *
  Copyright (c) Hypsurus

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

#include "client.h"
#include "logger.h"
#include "misc.h"
#include "tcp.h"

void ftpmap_getlist(ftpmap_t *ftpmap) {
    FILE *fid;
    char buffer[MAX_STR];
    char *answer = NULL;
    
    logger_write(ftpmap,":: Trying to receive LIST..\n\n");
    fid = ftpmap_data_tunnel(ftpmap);
    fprintf(ftpmap->fid, "LIST %s\r\n", ftpmap->listpath);
    answer = ftpmap_getanswer(ftpmap);

    signal(SIGALRM, sigalrm);
    alarm(5);

    while ( (fgets(buffer, sizeof(buffer), fid)) != NULL ) {
        logger_write(ftpmap,"%s", buffer);
    }
    logger_write(ftpmap,":: End of output\n");
}

void ftpmap_delete(ftpmap_t *ftpmap) {
    char *answer = NULL;

    fprintf(ftpmap->fid, "DELE %s\r\n", ftpmap->deletepath);
    answer = ftpmap_getanswer(ftpmap);
    if ( *answer == 0 )
        return;
    logger_write(ftpmap,":: %s", answer);
}

void ftpmap_mdtm(ftpmap_t *ftpmap) {
    char *answer = NULL;

    fprintf(ftpmap->fid, "MDTM %s\r\n", ftpmap->mdtmpath);
    answer = ftpmap_getanswer(ftpmap);
    if ( *answer == 0 )
        return;

    logger_write(ftpmap,":: %s",answer);
}


