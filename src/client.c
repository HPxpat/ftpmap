/* client.c - FTP client stuff 
 *
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

#include "client.h"
#include "logger.h"
#include "misc.h"
#include "tcp.h"

void ftpmap_getlist(ftpmap_t *ftpmap) {
    FILE *fid;
    char buffer[MAX_STR];
    char *answer = NULL;
    
    printf(":: Getting LIST..\n\n");
    fid = ftpmap_data_tunnel(ftpmap);
    fprintf(ftpmap->fid, "LIST %s\r\n", ftpmap->path);
    answer = ftpmap_getanswer(ftpmap);

    signal(SIGALRM, sigalrm);
    alarm(5);

    while ( (fgets(buffer, sizeof(buffer), fid)) != NULL ) {
        printf("%s", buffer);
    }
    printf("\n:: End of output\n");
}

int ftpmap_fsize(ftpmap_t *ftpmap) {
    char *answer = NULL;
    int size = 0;
    char code[MAX_STR];

    fprintf(ftpmap->fid, "SIZE %s\r\n", ftpmap->path); 
    sscanf( ftpmap_getanswer(ftpmap), "%s %d", code, &size);

    return size;
}

void ftpmap_download(ftpmap_t *ftpmap) {
    int fsize = ftpmap_fsize(ftpmap);
    int dsize = 0, rsize = 0;
    FILE *fd, *file;
    char *filename = NULL;
    char *answer = NULL;
    char buffer[MAX_STR];

    filename =  (strrchr(ftpmap->path, '/'))+1;

    if (( file = fopen(filename, "w")) == NULL )
        die(1, "Failed to write %s.", ftpmap->path);

    fd = ftpmap_data_tunnel(ftpmap);
    fprintf(ftpmap->fid, "RETR %s\r\n", ftpmap->path);
    answer = ftpmap_getanswer(ftpmap);

    if ( *answer == 0 )
        return;

    while (( rsize = fread(buffer, 1, sizeof(buffer), fd)) > 0 ) {
        if ( buffer[rsize +1] == '\r' )
            buffer[rsize +1] = '\0';       
        dsize += fwrite(buffer, 1, rsize, file);
        printf(":-: Downloading %s %s/%s ...\r",ftpmap->path,calc_bytes_size(dsize), 
                calc_bytes_size(fsize));
        fflush(stdout);
    }
    printf("\n:-: File saved: %s\n", filename);
    fclose(file);
}

void ftpmap_delete(ftpmap_t *ftpmap) {
    char *answer = NULL;

    fprintf(ftpmap->fid, "DELE %s\r\n", ftpmap->path);
    answer = ftpmap_getanswer(ftpmap);
    if ( *answer == 0 )
        return;
    printf(":: %s", answer);
}

void ftpmap_mdtm(ftpmap_t *ftpmap) {
    char *answer = NULL;

    fprintf(ftpmap->fid, "MDTM %s\r\n", ftpmap->path);
    answer = ftpmap_getanswer(ftpmap);
    if ( *answer == 0 )
        return;

    printf(":: %s",answer);
}


