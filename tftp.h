#define OP_RRQ   1
#define OP_WRQ   2
#define OP_DATA  3
#define OP_ACK   4
#define OP_ERROR 5
#define OP_OACK  6

#define E_UNDEF  0   // Not defined, see error message (if any).
#define E_NOFILE 1   // File not found.
#define E_ACCESS 2   // Access violation.
#define E_DISK   3   // Disk full or allocation exceeded.
#define E_OP     4   // Illegal TFTP operation.
#define E_TIP    5   // Unknown transfer ID.
#define E_EXISTS 6   // File already exists.
#define E_USER   7   // No such user.

struct tftp {
    short opcode;
    union body {
        struct {
            char *filename;
            char *mode;
            int blksize;
        } rwrq;
        struct {
            short block_num;
            int length;
            char * data;
        } data;
        struct {
            short block_num;
        } ack;
        struct {
            short error_code;
            char *errmsg;
        } error;
    } body;
};

int parse_buffer(struct tftp *t, char *buf, int len);
