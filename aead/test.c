/*
 * Copyright (C) 2015  Tadeusz Struk
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Based on AF_ALG test code by Herbert Xu
 */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#define SOL_ALG 279

#define SPLICE_F_GIFT    (0x08)    /* pages passed in are a gift */
struct sockaddr_alg {
    __u16    salg_family;
    __u8    salg_type[14];
    __u32    salg_feat;
    __u32    salg_mask;
    __u8    salg_name[64];
};
struct af_alg_iv {
    __u32    ivlen;
    __u8    iv[0];
};
/* Socket options */
#define ALG_SET_KEY           1
#define ALG_SET_IV            2
#define ALG_SET_OP            3
#define ALG_SET_AEAD_ASSOCLEN 4
#define ALG_SET_AEAD_AUTHSIZE 5

/* Operations */
#define ALG_OP_DECRYPT        0
#define ALG_OP_ENCRYPT        1

#define INFLIGTHS 128
#define TO_SEND (INFLIGTHS * 1024 * (1024 / INFLIGTHS))

static char buf_out[INFLIGTHS][80 + 24 + 20] = {0};

static char *key = "\x08\x00\x01\x00\x00\x00\x00\x10"
                   "\x11\x22\x33\x44\x55\x66\x77\x88"
                   "\x99\xaa\xbb\xcc\xdd\xee\xff\x11"
                   "\x22\x33\x44\x55"
                   "\x90\xd3\x82\xb4\x10\xee\xba\x7a"
                   "\xd9\x38\xc4\x6c\xec\x1a\x82\xbf";

static unsigned int klen = 8 + 20 + 16;

static char *iv = "\xe9\x6e\x8c\x08\xab\x46\x57\x63"
                  "\xfd\x09\x8d\x45\xdd\x3f\xf8\x93";

static char *input  = "\x00\x00\x43\x21\x00\x00\x00\x01"
                      "\xe9\x6e\x8c\x08\xab\x46\x57\x63"
                      "\xfd\x09\x8d\x45\xdd\x3f\xf8\x93"
                      "\x08\x00\x0e\xbd\xa7\x0a\x00\x00"
                      "\x8e\x9c\x08\x3d\xb9\x5b\x07\x00"
                      "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                      "\x10\x11\x12\x13\x14\x15\x16\x17"
                      "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
                      "\x20\x21\x22\x23\x24\x25\x26\x27"
                      "\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
                      "\x30\x31\x32\x33\x34\x35\x36\x37"
                      "\x01\x02\x03\x04\x05\x06\x07\x08"
                      "\x09\x0a\x0b\x0c\x0d\x0e\x0e\x01";

static const unsigned int alen = 24;
static const unsigned int ilen = 80 + 20 + 24;

static char *result = "\x00\x00\x43\x21\x00\x00\x00\x01"
                      "\xe9\x6e\x8c\x08\xab\x46\x57\x63"
                      "\xfd\x09\x8d\x45\xdd\x3f\xf8\x93"
                      "\xda\x72\x31\xc6\xb2\xe4\xa2\x7c"
                      "\x62\xe2\x83\x54\x0d\xf4\xa2\x0c"
                      "\x1e\x54\x8e\x2b\x5d\x95\xa0\x3d"
                      "\xb0\x16\x2a\x3b\x98\x14\xad\x27"
                      "\xcc\x5e\x61\x3c\x9d\x7d\x99\xee"
                      "\xe2\x9d\xa0\x87\xe9\x86\x7f\x62"
                      "\x29\x9a\x31\xd4\x1e\x26\xaa\x4d"
                      "\x66\x37\xf0\x34\x06\x6c\xe3\x30"
                      "\x72\xce\xd9\xda\xbf\x73\x2c\x21"
                      "\x85\x2f\x04\xd6\xe9\xed\xf9\x83"
                      "\x71\x41\xa0\x8c\x7e\x84\x4c\xf2"
                      "\x3b\xad\x17\xb7\x8b\x91\x10\x69"
                      "\xdd\xde\x3a\x26";

static const unsigned int rlen = 80 + 20 + 24;

static inline int io_setup(unsigned n, aio_context_t *ctx)
{
    return syscall(__NR_io_setup, n, ctx);
}

static inline int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

static inline int io_read(aio_context_t ctx, long n,  struct iocb **iocb)
{
    return syscall(__NR_io_submit, ctx, n, iocb);
}

static inline int io_getevents(aio_context_t ctx, long min, long max,
            struct io_event *events, struct timespec *timeout)
{
    return syscall(__NR_io_getevents, ctx, min, max, events, timeout);
}

static inline int eventfd(int n)
{
    return syscall(__NR_eventfd, n);
}

int efd;
unsigned int received, retrys, fdnotset, ring_fulls, failed;
aio_context_t aio_ctx;
struct io_event events[INFLIGTHS];

static void dump(char *mem, unsigned int len)
{
        unsigned int i;

	printf("addr: %p, len %d \n", mem, len);
        for (i = 0; i < len ; i++)
        {
                if (!(i % 0x10))
                        printf("0x%04x: ", i);

                if (i < len)
                        printf("%02x ", 0xff & *(mem + i));

		if (i && !((i + 1) % 0x10))
			printf("\n");
        }
	printf("===================\n");
}

static void poll_data(int t_out)
{
    struct timespec timeout;
    struct timeval tv;
    fd_set rfds;
    u_int64_t eval = 0;
    static u_int64_t resps = 0;
    int r;
    struct iocb *cb;

    FD_ZERO(&rfds);
    FD_SET(efd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = t_out;

    r = select(efd + 1, &rfds, NULL, NULL, &tv);
    if (r == -1) {
        printf("Select Error: %d\n", errno);
        return;
    } else if (FD_ISSET(efd, &rfds)) {
        if (read(efd, &eval, sizeof(eval)) != sizeof(eval)) {
            printf("efd read error\n");
            return;
        }
        resps += eval;
        if (resps > INFLIGTHS / 2) {
            timeout.tv_sec = 0;
            timeout.tv_nsec = 0;
            while (resps) {
                r = io_getevents(aio_ctx, 1, resps, events, &timeout);
                if (r > 0) {
                    int y;

                    for (y = 0; y < r; y++) {
                        cb = (void*) events[y].obj;
                        cb->aio_fildes = 0;
                        if (events[y].res == -EBUSY)
                            ring_fulls++;
                        else if (events[y].res < 0) {
                            printf("req %d failed with %d\n", received + y, events[y].res);
                            failed++;
                        } else if (memcmp(cb->aio_buf, result, rlen)) {
                            printf("req %d invalid output\n", received + y);
			    dump(cb->aio_buf, rlen);
                            failed++;
			}
                    }
                } else if (r < 0) {
                    printf("io_getevents Error: %d\n", errno);
                    return;
                } else {
                    retrys++;
                }
                resps -= r;
                received += r;
            }
        }
    } else {
        fdnotset++;
    }
}

static int crypt_kernel(int zcp)
{
    int opfd;
    int tfmfd;
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authenc(hmac(sha1),cbc(aes))"
    };
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(4) + CMSG_SPACE(20)] = {};
    struct aes_iv {
        __u32 len;
        __u8 iv[16];
    } *iv;
    struct iovec iov;
    int pipes[2];

    struct iocb *cb;
    struct iocb cbt[INFLIGTHS];
    int r, i, wait = 0;

    pipe(pipes);
    memset(cbt, 0, sizeof(cbt));
    efd = eventfd(0);
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (!tfmfd) {
        printf("socket error\n");
        return -1;
    }
    r = bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0) {
        printf("bind error %d\n", errno);
        return -1;
    }
    r = setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, klen);
    if (r < 0) {
        printf("sock opt setkey error %d\n", errno);
        return -1;
    }
    r = setsockopt(tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 20);
    if (r < 0) {
        printf("sock opt setauthsize error %d\n", errno);
        return -1;
    }
    opfd = accept(tfmfd, NULL, 0);
    if (!opfd) {
        printf("accept error\n");
        return -1;
    }

    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(__u32 *)CMSG_DATA(cmsg) = alen;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    iv = (void *)CMSG_DATA(cmsg);
    iv->len = 16;
    memcpy(iv->iv, iv, 16);

    iov.iov_base = input;
    iov.iov_len = ilen;
    msg.msg_flags = MSG_MORE;

    aio_ctx = 0;
    r = io_setup(INFLIGTHS, &aio_ctx);
    if (r < 0) {
        printf("io_setup error\n");
        return -1;
    }
    for (i = 0; i < TO_SEND; i++) {
        if (zcp) {
            msg.msg_iovlen = 0;
            msg.msg_iov = NULL;

            r = sendmsg(opfd, &msg, 0);
            if (r < 0 && errno != EMSGSIZE)
                printf("sendmsg returned Error: %d r = %d\n", errno, r);

            r = vmsplice(pipes[1], &iov, 1, SPLICE_F_GIFT);
            if (r < 0)
                printf("vmsplice returned Error: %d\n", errno);

            r = splice(pipes[0], NULL, opfd, NULL, ilen, 0);
            if (r < 0)
                printf("splice returned Error: %d\n", errno);
        } else {
            msg.msg_iovlen = 1;
            msg.msg_iov = &iov;
            r = sendmsg(opfd, &msg, rlen);
            if (r < 0)
                printf("sendmsg returned Error: %d\n", errno);
        }

        cb = &cbt[i % INFLIGTHS];
        while (cb->aio_fildes) {
            wait++;
            poll_data(10);
            cb = &cbt[i % INFLIGTHS];
        }

        memset(cb, '\0', sizeof(*cb));
        cb->aio_fildes = opfd;
        cb->aio_lio_opcode = IOCB_CMD_PREAD;
        cb->aio_buf = (unsigned long)buf_out[i % INFLIGTHS];
        cb->aio_offset = 0;
        cb->aio_data = i;
        cb->aio_nbytes = rlen;
        cb->aio_flags = IOCB_FLAG_RESFD;
        cb->aio_resfd = efd;
        r = io_read(aio_ctx, 1, &cb);
        if (r != 1) {
            if (r < 0) {
                printf("io_read Error: %d\n", errno);
                return -1;
            } else {
                printf("Could not sumbit AIO read\n");
                return -1;
            }
        }
        if (i && (i % (INFLIGTHS / 2)) == 0)
            poll_data(1);
    }
    while (received != TO_SEND) {
        r = io_getevents(aio_ctx, 1, TO_SEND - received, events, NULL);
        if (r > 0)
            received += r;

    }
    printf("Finished - retrys: %d, fdnotset: %d, wait: %d, ringfulls: %d, failed: %d\n",
           retrys, fdnotset, wait, ring_fulls, failed);
    close(efd);
    close(opfd);
    close(tfmfd);
    close(pipes[0]);
    close(pipes[1]);
    io_destroy(aio_ctx);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        printf("doing zero copy, ");
        printf("\n");
        crypt_kernel(1);
    }
    else {
        printf("doing copy, ");
        printf("\n");
        crypt_kernel(0);
    }
    return 0;
}
