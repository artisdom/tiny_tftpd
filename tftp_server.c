#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#define err printf
//#define dbg printf
#define dbg

#define TFTPD_PORT 69

#define OP_RRQ   1
#define OP_WRQ   2
#define OP_DATA  3
#define OP_ACK   4
#define OP_ERROR 5
#define OP_OACK  6

//#define PREFIX "/tftpboot/"
#define PREFIX "/configs/test/"

#define BLOCK_SIZE 512

int open_file(char *filename, int *fd, int *fd_opened)
{
    int ret;
    char path[64];

    snprintf(path, sizeof(path), PREFIX"%s", filename);
    ret = open (path, O_RDONLY);
    if (ret == -1) {
        perror("open");
        return -1;
    }

    *fd = ret;
    *fd_opened = 1;
    return 0;
}

void close_file(int *fd, int *fd_opened)
{
    close(*fd);
    *fd = 0;
    *fd_opened = 0;
}

static int block_num = 0;
static int is_eof = 0;

int send_one_block(int sk, struct sockaddr_in *dst, socklen_t slen, int fd, short number)
{
    char buf[BLOCK_SIZE + 4] = { 0x00, 0x03 }, *p;
    ssize_t ret;
    int len;

    p = buf + 2;
    *(short *)p = htons(number);

    p += 2;
    len = BLOCK_SIZE;

    while (len != 0 && (ret = read(fd, p, len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            perror ("read");
            break;
        }
        len -= ret;
        p += ret;
    }

    len = p - buf;
    if (ret == 0)
        is_eof = 1;

    ret = sendto(sk, buf, len, 0, (struct sockaddr *)dst, slen);
    if (ret == -1) {
        perror("sendto");
        return -1;
    } else
        dbg("sent %d bytes.\n", (int)ret);

    return 0;
}

static int fd, fd_opened;
static char filename[64];

int process_tftp(char *buf, int len, int sk, struct sockaddr_in *dst, socklen_t slen)
{
    short opcode = ntohs(*(short *)buf);
    int ack;

    switch (opcode) {
    case OP_RRQ:
        if (strcmp(filename, buf + 2)) {
            if (filename[0] != 0) {
                close_file(&fd, &fd_opened);
                is_eof = 0;
                block_num = 0;
            }
        } else {
            break;
        }
        strcpy(filename, buf + 2);
        printf("filename: %s\n", filename);
        open_file(filename, &fd, &fd_opened);
        send_one_block(sk, dst, slen, fd, 1);
        block_num = 1;
        break;
    case OP_ACK:
        ack = ntohs(*(short *)(buf + 2));
        dbg("%d ", ack);
        if (is_eof) {
            printf("TFTP finished.\n");
            return 0;
        }
        if (ack == block_num) {
            send_one_block(sk, dst, slen, fd, ack + 1);
            block_num++;
        }
        break;
    case OP_ERROR:
        err("TFTP error, error code: %d, msg: %s\n", ntohs(*(short *)(buf + 2)), buf + 4);
        break;
    default:
        err("Unknown opcode: %d\n", opcode);
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int ret, sk;
    char rx_buf[1024];
    struct sockaddr_in bind_addr, dst_addr;
    socklen_t slen = sizeof(struct sockaddr_in);

    if ((sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket");
        return -1;
    }

    memset(&bind_addr, 0, sizeof(struct sockaddr_in));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(TFTPD_PORT);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sk, (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) == -1) {
        perror("socket");
        return -1;
    }

    while (1) {
        ret = recvfrom(sk, rx_buf, sizeof(rx_buf), 0, (struct sockaddr *)&dst_addr, &slen);
        if (ret == -1) {
            perror("recvfrom");
            return -1;
        } else
            dbg("recv %d bytes from %s:%d.\n", ret, inet_ntoa(dst_addr.sin_addr), ntohs(dst_addr.sin_port));
        process_tftp(rx_buf, ret, sk, &dst_addr, slen);
    }
    return 0;
}
