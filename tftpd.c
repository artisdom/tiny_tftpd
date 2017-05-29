#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include "tftp.h"

#define err printf
#define dbg printf

#define TFTPD_PORT 69
#define MAXSIZE 1024

void print_packet(struct tftp *t)
{
    switch(t->opcode){
    case OP_DATA:
        printf("DATA - Opcode %d\tBlock: %d\nData Length: %d\nData:\n%.*s\n",
               t->opcode,
               t->body.data.block_num,
               (int)t->body.data.length,
               (int)t->body.data.length,
               t->body.data.data
               );
        break;
    case OP_WRQ:
        printf("WRQ :\tOpcode: %d\tFile: %s\tMode:%s\n", 
               t->opcode,
               t->body.rwrq.filename, t->body.rwrq.mode);
        break;
    case OP_RRQ:
        printf("RRQ :\tOpcode: %d\tFile: %s\tMode:%s\n", 
               t->opcode,
               t->body.rwrq.filename, t->body.rwrq.mode);
        break;
    case OP_ACK:
        printf("ACK :\tOpcode: %d\t Block: %d", 
               t->opcode,
               t->body.ack.block_num);
        break;
    case OP_ERROR:
        printf("ERROR :\tOpcode: %d\nError Code: %d\tMsg: %s", 
               t->opcode,
               t->body.error.error_code,
               t->body.error.errmsg);
        break;
    }
}

int parse_buf(struct tftp *t, char *buf, int len)
{
    t->opcode = ntohs(*((short *) buf));

    switch(t->opcode){
    case OP_RRQ:
    case OP_WRQ:
        {
            t->body.rwrq.blksize = 512;
            char * fname = buf + 2;
            char * mode = fname + strlen(fname) + 1;
            t->body.rwrq.filename = malloc(sizeof(char) * strlen(fname)+1);
            strcpy( t->body.rwrq.filename, fname);
            t->body.rwrq.mode = malloc(sizeof(char) * strlen(fname)+1);
            strcpy(t->body.rwrq.mode, mode);
            return t;
        }
    case OP_DATA:
        {
            t->body.data.block_num = ntohs(* ((uint16_t*) (buf + 2)));
            t->body.data.len = len - 4;
            t->body.data.data = malloc(sizeof(char) * t->body.data.len);
            memcpy(t->body.data.data, (buf + 4), t->body.data.len);
            return t;
        }
    case OP_ACK:
        {
            t->body.ack.block_num = ntohs(* ((uint16_t*) (buf + 2)));
            return t;
        }
    case OP_ERROR:
        {
        }
    default:
        t->opcode = -1;
        return t;
    }
}

void send_file(struct tftp * request, int sock) {
    //RRQ
    char * fname = request->body.rwrq.filename;

    FILE *rfile = fopen(fname, "r");
    if(rfile == NULL){
        switch(errno){
        case EACCES:
            send_error(E_ACCESS, strerror(errno), sock);
            exit(EXIT_FAILURE);
        case ENOENT:
            send_error(E_NOFILE, strerror(errno), sock);
            exit(EXIT_FAILURE);
        default:
            send_error(100 + errno, strerror(errno), sock);
            diep("fopen");
        }
    }
    puts("File Open");
    //send_ack(0, sock);

    int bsize = request->body.rwrq.blksize;

    int block = 1;
    size_t actual;
    char *read_buf = malloc(bsize);
    size_t extra = 0;
    char * ebuf;
    do {

        struct tftp data_p;
        if(extra){

            char * new_data = malloc(bsize-extra);
            actual = fread(new_data, sizeof(char), bsize - extra, rfile);

            atona(&new_data, &actual);

            read_buf =  realloc(read_buf, actual + extra);

            memcpy(read_buf, ebuf, extra);
            memcpy(read_buf + extra, new_data, actual);

            actual = extra + actual;

            free(new_data);
            free(ebuf);
            extra = 0;
        } else {
            actual = fread(read_buf, sizeof(char), bsize, rfile);

            if(strcasecmp(request->body.rwrq.mode, "netascii") == 0){
                atona(&read_buf, &actual);
            }
        }
        if(actual > bsize){
            extra = actual - bsize;
            actual = bsize;
            ebuf = malloc(extra);
            memset(ebuf, 0, extra);
            memcpy(ebuf, read_buf+bsize, extra);
        }

        data_p.opcode = OP_DATA;
        data_p.body.data.block_num = block;
        data_p.body.data.length = actual;
        data_p.body.data.data = read_buf;
        char * sbuf;
        size_t sbuf_size = prepare_packet(&data_p, &sbuf);

        char bsent = 0;
        int retries = 0;
        while(bsent == 0){
            printf("Sent Block %d\n", block);
            send(sock, sbuf, sbuf_size, 0);


            char ack_buf[10];

            usleep(200);
            printf("sleep 200 microseconds.\n");
            size_t recvd = recv(sock, ack_buf, 10, 0);

            if(recvd == -1 && errno == EAGAIN){
                if(retries >= 8){
                    puts("timeout exit");
                    exit(EXIT_FAILURE);
                }
                printf("retrying %d more times.\n", 8 -retries);
                retries++;
                continue;
            }

            struct tftp *ack = parse_buffer(ack_buf, recvd);
            if(ack->opcode == OP_ACK && ack->body.ack.block_num == block){
                puts("Ack");
                bsent = 1; 
            }   
            packet_free(ack);
        }
        free(sbuf);

        block++;
    } while (actual == bsize);
    free(read_buf);
    fclose(rfile);
}

int process_req(struct tftp *t, struct sockaddr_in *caddr)
{
    int sk;
    struct sockaddr_in saddr;

    memset((char *)&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(0);
    saddr.sin_addr.s_addr = INADDR_ANY;

    if ((sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket");
        return -1;
    }
    if (bind(sk, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        perror("bind");
        return -1;
    }
    if (connect(sk, (struct sockaddr *)caddr, sizeof(struct sockaddr_in)) == -1) {
        perror("connect");
        return -1;
    }
    //if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,  sizeof tv)) diep("setsockopt");

    switch(t->opcode){
    case OP_WRQ:
        {
            puts("Receiving File");
            //receive_file(t, handler_sock);
        }
        break;
    case OP_RRQ:
        {
            puts("Sending File");
            send_file(t, handler_sock);
        }
        break;
    default:
        {
            //send_error(4, "Invalid Opcode", handler_sock);
            exit(EXIT_FAILURE);
        }
    }

}

int serve_tftp(int sk)
{
    char buf[MAXSIZE];
    ssize_t ret;
    struct sockaddr_in caddr;
    socklen_t slen = sizeof(struct sockaddr_in);
    struct tftp t;
    //pid_t pid;

    ret = recvfrom(sk, buf, MAXSIZE, 0, (struct sockaddr *)&caddr, &slen);
    printf("Rx %d from %s:%d\n", sk, inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));

    ret = parse_buf(&t, buf, ret);

    print_packet(&t);
    ret = process_req(&t, &caddr);
    /*
    pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        printf("child of %d\n", getppid());
    }
    */
}

int main(int argc, char *argv[])
{
    int ret, sk;
    fd_set fds;
    struct sockaddr_in saddr, caddr;

    if ((sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket");
        return -1;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(TFTPD_PORT);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sk, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) == -1) {
        perror("socket");
        return -1;
    }

    FD_ZERO(&fds);
    FD_SET(sk, &fds);

    ret = select(sk + 1, &fds, NULL, NULL, NULL);
    if(ret == -1) {
        perror("select");
    } else if (ret > 0) {
        if(FD_ISSET(sk, &fds)) {
            need_exit = transfer_byte(STDIN_FILENO, comfd, 1);
        }
    }

    return 0;
}
