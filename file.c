#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DIRECTORY "/tftpboot/"

int read_file(char *name)
{
    int fd, ret;
    char path[256];

    ret = strncpy(path, sizeof(path), DIRECTORY);
    strncpy(path, sizeof(path), DIRECTORY);

    fd = open ("/tftpboot/", O_RDONLY);
    if (fd == -1)
        return 0;
}

int open (const char *name, int flags);
int open (const char *name, int flags, mode_t mode);

