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

#define PKGSIZE (4096 * 2)

#ifdef UNALIGNED
#define BUFFSIZE (PKGSIZE * 2)
#define OUT_OFFSET 2128;
#define IN_OFFSET 256;
#else
#define BUFFSIZE PKGSIZE
#define OUT_OFFSET 0;
#define IN_OFFSET 0;
#endif

#define INFLIGTHS 64
#define TO_SEND (1024 * 1024)

static char buf[BUFFSIZE] __attribute__((__aligned__(BUFFSIZE)));
static char *buf_out = buf;

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
                        else if (events[y].res != 0) {
                            printf("req %d failed with %d\n", received + y, events[y].res);
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

static int crypt_kernel(const char *key, char *oiv, int zcp)
{
    int opfd;
    int tfmfd;
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = "cbc(aes)"
    };
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {};
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
    bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
    setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, 16);
    opfd = accept(tfmfd, NULL, 0);

    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    iv = (void *)CMSG_DATA(cmsg);
    iv->len = 16;
    memcpy(iv->iv, oiv, 16);

    iov.iov_base = buf + IN_OFFSET;
    iov.iov_len = PKGSIZE;
    msg.msg_flags = MSG_MORE;

    aio_ctx = 0;
    r = io_setup(INFLIGTHS, &aio_ctx);
    if (r < 0) {
        perror("io_setup error");
        return -1;
    }
    for (i = 0; i < TO_SEND; i++) {
        if (zcp) {
            msg.msg_iovlen = 0;
            msg.msg_iov = NULL;

            r = sendmsg(opfd, &msg, 0);
            if (r < 0)
                printf("sendmsg returned Error: %d\n", errno);

            r = vmsplice(pipes[1], &iov, 1, SPLICE_F_GIFT);
            if (r < 0)
                printf("vmsplice returned Error: %d\n", errno);

            r = splice(pipes[0], NULL, opfd, NULL, PKGSIZE, 0);
            if (r < 0)
                printf("splice returned Error: %d\n", errno);
        } else {
            msg.msg_iovlen = 1;
            msg.msg_iov = &iov;
            r = sendmsg(opfd, &msg, PKGSIZE);
            if (r < 0)
                printf("zero cp sendmsg returned Error: %d\n", errno);
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
        cb->aio_buf = (unsigned long)buf_out + OUT_OFFSET;
        cb->aio_offset = 0;
        cb->aio_data = i;
        cb->aio_nbytes = PKGSIZE;
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
    const char key[16] =
        "\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
        "\x51\x2e\x03\xd5\x34\x12\x00\x06";
    char iv[16] =
        "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30"
        "\xb4\x22\xda\x80\x2c\x9f\xac\x41";

    memcpy(buf, "Single block msg", 16);

    if (argc == 2) {
        printf("doing zero copy, ");
#ifdef UNALIGNED
        printf("unaligned");
#else
        printf("aligned");
#endif
        printf("\n");
        crypt_kernel(key, iv, 1);
    }
    else {
        printf("doing copy, ");
#ifdef UNALIGNED
        printf("unaligned");
#else
        printf("aligned");
#endif
        printf("\n");
        crypt_kernel(key, iv, 0);
    }
    return 0;
}
