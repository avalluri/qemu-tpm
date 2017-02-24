/*
 * TPM utility functions
 *
 *  Copyright (c) 2010 - 2015 IBM Corporation
 *  Authors:
 *    Stefan Berger <stefanb@us.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#include "qemu/osdep.h"
#include "tpm_util.h"
#include "tpm_int.h"
#include "tpm_ioctl.h"
#include "qemu/error-report.h"

#define DEBUG_TPM 0

#define DPRINTF(fmt, ...) do { \
    if (DEBUG_TPM) { \
        fprintf(stderr, fmt, ## __VA_ARGS__); \
    } \
} while (0)

static unsigned long ioctl_to_cmd(unsigned long ioctlnum)
{
    /* the ioctl number contains the command number - 1 */
    return ((ioctlnum >> _IOC_NRSHIFT) & _IOC_NRMASK) + 1;
}

int tpm_util_ctrlcmd(int fd, unsigned long cmd, void *msg, size_t msg_len_in,
                   size_t msg_len_out)
{
    int n;

    uint32_t cmd_no = cpu_to_be32(ioctl_to_cmd(cmd));
    struct iovec iov[2] = {
        { .iov_base = &cmd_no, .iov_len = sizeof(cmd_no), },
        { .iov_base = msg, .iov_len = msg_len_in, },
    };

    if ((n = writev(fd, iov, 2)) > 0) {
        if (msg_len_out > 0) {
	    n = read(fd, msg, msg_len_out);
	    /* simulate ioctl return value */
	    if (n > 0) {
	        n = 0;
	    }
        } else {
	    /* simulate ioctl return value */
	    n = 0;
        }
    }
    return n;
}

int tpm_util_unixio_connect(const char *unix_path)
{
    int fd = -1;

    if (unix_path) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd > 0) {
            struct sockaddr_un addr;

            if (strlen(unix_path) + 1 > sizeof(addr.sun_path)) {
                DPRINTF("Socket path is too long.");
                return -1;
            }

            addr.sun_family = AF_UNIX;
            strcpy(addr.sun_path, unix_path);

            if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(fd);
                return -1;
            }
        }

        if (fd < 0) {
            DPRINTF("Could not connect using socket.");
        }
    }

    return fd;
}

/*
 * A basic test of a TPM device. We expect a well formatted response header
 * (error response is fine) within one second.
 */
static int tpm_util_test(int fd,
                         unsigned char *request,
                         size_t requestlen,
                         uint16_t *return_tag)
{
    struct tpm_resp_hdr *resp;
    fd_set readfds;
    int n;
    struct timeval tv = {
        .tv_sec = 1,
        .tv_usec = 0,
    };
    unsigned char buf[1024];

    n = write(fd, request, requestlen);
    if (n < 0) {
        return errno;
    }
    if (n != requestlen) {
        return EFAULT;
    }

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    /* wait for a second */
    n = select(fd + 1, &readfds, NULL, NULL, &tv);
    if (n != 1) {
        return errno;
    }

    n = read(fd, &buf, sizeof(buf));
    if (n < sizeof(struct tpm_resp_hdr)) {
        return EFAULT;
    }

    resp = (struct tpm_resp_hdr *)buf;
    /* check the header */
    if (be32_to_cpu(resp->len) != n) {
        return EBADMSG;
    }

    *return_tag = be16_to_cpu(resp->tag);

    return 0;
}

/*
 * Probe for the TPM device in the back
 * Returns 0 on success with the version of the probed TPM set, 1 on failure.
 */
int tpm_util_test_tpmdev(int tpm_fd, TPMVersion *tpm_version)
{
    /*
     * Sending a TPM1.2 command to a TPM2 should return a TPM1.2
     * header (tag = 0xc4) and error code (TPM_BADTAG = 0x1e)
     *
     * Sending a TPM2 command to a TPM 2 will give a TPM 2 tag in the
     * header.
     * Sending a TPM2 command to a TPM 1.2 will give a TPM 1.2 tag
     * in the header and an error code.
     */
    const struct tpm_req_hdr test_req = {
        .tag = cpu_to_be16(TPM_TAG_RQU_COMMAND),
        .len = cpu_to_be32(sizeof(test_req)),
        .ordinal = cpu_to_be32(TPM_ORD_GetTicks),
    };

    const struct tpm_req_hdr test_req_tpm2 = {
        .tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
        .len = cpu_to_be32(sizeof(test_req_tpm2)),
        .ordinal = cpu_to_be32(TPM2_CC_ReadClock),
    };
    uint16_t return_tag;
    int ret;

    /* Send TPM 2 command */
    ret = tpm_util_test(tpm_fd, (unsigned char *)&test_req_tpm2,
                        sizeof(test_req_tpm2), &return_tag);
    /* TPM 2 would respond with a tag of TPM2_ST_NO_SESSIONS */
    if (!ret && return_tag == TPM2_ST_NO_SESSIONS) {
        *tpm_version = TPM_VERSION_2_0;
        return 0;
    }

    /* Send TPM 1.2 command */
    ret = tpm_util_test(tpm_fd, (unsigned char *)&test_req,
                        sizeof(test_req), &return_tag);
    if (!ret && return_tag == TPM_TAG_RSP_COMMAND) {
        *tpm_version = TPM_VERSION_1_2;
        /* this is a TPM 1.2 */
        return 0;
    }

    *tpm_version = TPM_VERSION_UNSPEC;

    return 1;
}
