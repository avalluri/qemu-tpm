/*
 *  emulator TPM driver
 *
 *  Copyright (c) 2010 - 2013 IBM Corporation
 *  Authors:
 *    Stefan Berger <stefanb@us.ibm.com>
 *
 *  Copyright (C) 2011 IAIK, Graz University of Technology
 *    Author: Andreas Niederl
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
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/sockets.h"
#include "sysemu/tpm_backend.h"
#include "tpm_int.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "sysemu/tpm_backend_int.h"
#include "tpm_tis.h"
#include "tpm_util.h"
#include "tpm_ioctl.h"
#include "qapi/error.h"

#define DEBUG_TPM 0

#define DPRINTF(fmt, ...) do { \
    if (DEBUG_TPM) { \
        fprintf(stderr, fmt, ## __VA_ARGS__); \
    } \
} while (0);

#define TYPE_TPM_EMULATOR "emulator"
#define TPM_EMULATOR(obj) \
    OBJECT_CHECK(TPMEmulatorState, (obj), TYPE_TPM_EMULATOR)

static const TPMDriverOps tpm_emulator_driver;

/* data structures */
typedef struct TPMEmulatorThreadParams {
    TPMState *tpm_state;

    TPMRecvDataCB *recv_data_callback;
    TPMBackend *tb;
} TPMEmulatorThreadParams;

typedef struct TPMEmulatorState {
    TPMBackend parent;

    TPMBackendThread tbt;
    TPMEmulatorThreadParams tpm_thread_params;

    char *tpmstatedir;
    char *emulator_path;
    int tpm_fd;
    int tpm_ctrl_fd;
    bool tpm_executing;
    bool tpm_op_canceled;
    bool startup_failed;

    TPMVersion tpm_version;
    ptm_cap caps; /* capabilities of the TPM */
    uint8_t cur_locty_number; /* last set locality */
} TPMEmulatorState;

#define TPM_DEFAULT_EMULATOR "swtpm"
#define TPM_EUMLATOR_IMPLEMENTS_ALL_CAPS(S, cap) (((S)->caps & (cap)) == (cap))

/* functions */

static void tpm_emulator_cancel_cmd(TPMBackend *tb);

static uint32_t tpm_emulator_get_size_from_buffer(const uint8_t *buf)
{
    struct tpm_resp_hdr *resp = (struct tpm_resp_hdr *)buf;

    return be32_to_cpu(resp->len);
}

/*
 * Write an error message in the given output buffer.
 */
static void tpm_write_fatal_error_response(uint8_t *out, uint32_t out_len)
{
    if (out_len >= sizeof(struct tpm_resp_hdr)) {
        struct tpm_resp_hdr *resp = (struct tpm_resp_hdr *)out;

        resp->tag = cpu_to_be16(TPM_TAG_RSP_COMMAND);
        resp->len = cpu_to_be32(sizeof(struct tpm_resp_hdr));
        resp->errcode = cpu_to_be32(TPM_FAIL);
    }
}

static bool tpm_emulator_is_selftest(const uint8_t *in, uint32_t in_len)
{
    struct tpm_req_hdr *hdr = (struct tpm_req_hdr *)in;

    if (in_len >= sizeof(*hdr)) {
        return (be32_to_cpu(hdr->ordinal) == TPM_ORD_ContinueSelfTest);
    }

    return false;
}

static int tpm_emulator_unix_tx_bufs(TPMEmulatorState *tpm_pt,
                                     const uint8_t *in, uint32_t in_len,
                                     uint8_t *out, uint32_t out_len,
                                     bool *selftest_done)
{
    int ret;
    bool is_selftest;
    const struct tpm_resp_hdr *hdr;

    tpm_pt->tpm_op_canceled = false;
    tpm_pt->tpm_executing = true;
    *selftest_done = false;

    is_selftest = tpm_emulator_is_selftest(in, in_len);

    ret = tpm_util_unix_write(tpm_pt->tpm_fd, in, in_len);
    if (ret != in_len) {
        if (!tpm_pt->tpm_op_canceled || errno != ECANCELED) {
            error_report("tpm_emulator: error while transmitting data "
                         "to TPM: %s (%i)",
                         strerror(errno), errno);
        }
        goto err_exit;
    }

    tpm_pt->tpm_executing = false;

    ret = tpm_util_unix_read(tpm_pt->tpm_fd, out, out_len);
    if (ret < 0) {
        if (!tpm_pt->tpm_op_canceled || errno != ECANCELED) {
            error_report("tpm_emulator: error while reading data from "
                         "TPM: %s (%i)",
                         strerror(errno), errno);
        }
    } else if (ret < sizeof(struct tpm_resp_hdr) ||
               tpm_emulator_get_size_from_buffer(out) != ret) {
        ret = -1;
        error_report("tpm_emulator: received invalid response "
                     "packet from TPM");
    }

    if (is_selftest && (ret >= sizeof(struct tpm_resp_hdr))) {
        hdr = (struct tpm_resp_hdr *)out;
        *selftest_done = (be32_to_cpu(hdr->errcode) == 0);
    }

err_exit:
    if (ret < 0) {
        tpm_write_fatal_error_response(out, out_len);
    }

    tpm_pt->tpm_executing = false;

    return ret;
}

static int tpm_emulator_unix_transfer(TPMEmulatorState *tpm_pt,
                                      const TPMLocality *locty_data,
                                      bool *selftest_done)
{
    return tpm_emulator_unix_tx_bufs(tpm_pt,
                                     locty_data->w_buffer.buffer,
                                     locty_data->w_offset,
                                     locty_data->r_buffer.buffer,
                                     locty_data->r_buffer.size,
                                     selftest_done);
}

static int tpm_emulator_set_locality(TPMEmulatorState *tpm_pt,
                                     uint8_t locty_number)
{
    ptm_loc loc;

    if (tpm_pt->cur_locty_number != locty_number) {
        DPRINTF("tpm-eulator: setting locality : 0x%x", locty_number);
        loc.u.req.loc = cpu_to_be32(locty_number);
        if (tpm_util_ctrlcmd(tpm_pt->tpm_ctrl_fd, PTM_SET_LOCALITY, &loc,
                             sizeof(loc), sizeof(loc)) < 0) {
            error_report("tpm-eulator: could not set locality : %s",
                         strerror(errno));
            return -1;
        }
        loc.u.resp.tpm_result = be32_to_cpu(loc.u.resp.tpm_result);
        if (loc.u.resp.tpm_result != 0) {
            error_report("tpm-eulator: TPM result for set locality : 0x%x",
                         loc.u.resp.tpm_result);
            return -1;
        }
        tpm_pt->cur_locty_number = locty_number;
    }
    return 0;
}


static void tpm_emulator_worker_thread(gpointer data,
                                       gpointer user_data)
{
    TPMEmulatorThreadParams *thr_parms = user_data;
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(thr_parms->tb);
    TPMBackendCmd cmd = (TPMBackendCmd)data;
    TPMState *tpm_state = thr_parms->tpm_state;
    TPMLocality *locty_data = NULL;
    bool selftest_done = false;
    
    DPRINTF("tpm_emulator: processing command type %d\n", cmd);

    switch (cmd) {
    case TPM_BACKEND_CMD_PROCESS_CMD:
        locty_data = tpm_state->locty_data;
        if (tpm_emulator_set_locality(tpm_pt, tpm_state->locty_number) < 0) {
            tpm_write_fatal_error_response(locty_data->r_buffer.buffer,
                                           locty_data->r_buffer.size);
            break;
        }

        tpm_emulator_unix_transfer(tpm_pt, locty_data, &selftest_done);
        thr_parms->recv_data_callback(tpm_state, tpm_state->locty_number,
                                      selftest_done);
        break;
    case TPM_BACKEND_CMD_INIT:
    case TPM_BACKEND_CMD_END:
    case TPM_BACKEND_CMD_TPM_RESET:
        /* nothing to do */
        break;
    }
}

/*
 * Gracefully shut down the external unixio TPM
 */
static void tpm_emulator_shutdown(TPMEmulatorState *tpm_pt)
{
    ptm_res res;

    if (tpm_util_ctrlcmd(tpm_pt->tpm_ctrl_fd, PTM_SHUTDOWN, &res, 0,
                         sizeof(res)) < 0) {
        error_report("tpm-eulator: Could not cleanly shut down the TPM: %s",
                     strerror(errno));
    } else if (res != 0) {
        error_report("tpm-eulator: TPM result for sutdown: 0x%x",
                     be32_to_cpu(res));
    }
}

static int tpm_emulator_probe_cabs(TPMEmulatorState *tpm_pt)
{
    if (tpm_util_ctrlcmd(tpm_pt->tpm_ctrl_fd, PTM_GET_CAPABILITY,
                         &tpm_pt->caps, 0, sizeof(tpm_pt->caps)) < 0) {
        error_report("tpm-eulator: probing failed : %s", strerror(errno));
        return -1;
    }

    tpm_pt->caps = be64_to_cpu(tpm_pt->caps);
 
    DPRINTF("capbilities : 0x%lx\n", tpm_pt->caps);

    return 0;
}

static int tpm_emulator_check_caps(TPMEmulatorState *tpm_pt)
{
    ptm_cap caps = 0;
    const char *tpm = NULL;

    /* check for min. required capabilities */
    switch (tpm_pt->tpm_version) {
    case TPM_VERSION_1_2:
        caps = PTM_CAP_INIT | PTM_CAP_SHUTDOWN | PTM_CAP_GET_TPMESTABLISHED |
               PTM_CAP_SET_LOCALITY;
        tpm = "1.2";
        break;
    case TPM_VERSION_2_0:
        caps = PTM_CAP_INIT | PTM_CAP_SHUTDOWN | PTM_CAP_GET_TPMESTABLISHED |
               PTM_CAP_SET_LOCALITY | PTM_CAP_RESET_TPMESTABLISHED;
        tpm = "2";
        break;
    case TPM_VERSION_UNSPEC:
        error_report("tpm-eulator: %s: TPM version has not been set", __func__);
        return -1;
    }

    if (!TPM_EUMLATOR_IMPLEMENTS_ALL_CAPS(tpm_pt, caps)) {
        error_report("tpm-eulator: TPM does not implement minimum set of "
                     "required capabilities for TPM %s (0x%x)", tpm,
                     (int)caps);
        return -1;
    }

    return 0;
}

static int tpm_emulator_init_tpm(TPMEmulatorState *tpm_pt, bool is_resume)
{
    ptm_init init;
    ptm_res res;

    if (is_resume) {
        init.u.req.init_flags = cpu_to_be32(PTM_INIT_FLAG_DELETE_VOLATILE);
    }

    if (tpm_util_ctrlcmd(tpm_pt->tpm_ctrl_fd, PTM_INIT, &init, sizeof(init),
                         sizeof(init)) < 0) {
        error_report("tpm-eulator: could not send INIT: %s",
                     strerror(errno));
        return -1;
    }

    if ((res = be32_to_cpu(init.u.resp.tpm_result)) != 0) {
        error_report("tpm-eulator: TPM result for PTM_INIT: 0x%x", res);
        return -1;
    }

    return 0;
}

/*
 * Start the TPM (thread). If it had been started before, then terminate
 * and start it again.
 */
static int tpm_emulator_startup_tpm(TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);

    /* terminate a running TPM */
    tpm_backend_thread_end(&tpm_pt->tbt);

    tpm_backend_thread_create(&tpm_pt->tbt,
                              tpm_emulator_worker_thread,
                              &tpm_pt->tpm_thread_params);

    tpm_emulator_init_tpm(tpm_pt, false);

    return 0;
}

static void tpm_emulator_reset(TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);

    DPRINTF("tpm_emulator: CALL TO TPM_RESET!\n");

    tpm_emulator_cancel_cmd(tb);

    tpm_backend_thread_end(&tpm_pt->tbt);

    tpm_pt->startup_failed = false;
}

static int tpm_emulator_init(TPMBackend *tb, TPMState *tpm_state,
                             TPMRecvDataCB *recv_data_cb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);

    tpm_pt->tpm_thread_params.tpm_state = tpm_state;
    tpm_pt->tpm_thread_params.recv_data_callback = recv_data_cb;
    tpm_pt->tpm_thread_params.tb = tb;

    return 0;
}

static bool tpm_emulator_get_tpm_established_flag(TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);
    ptm_est est;

    if (tpm_util_ctrlcmd(tpm_pt->tpm_ctrl_fd, PTM_GET_TPMESTABLISHED, &est, 0,
                         sizeof(est)) < 0) {
        error_report("tpm-eulator: Could not get the TPM established flag: %s",
                     strerror(errno));
        return false;
    }

    return (est.u.resp.bit != 0);
}

static int tpm_emulator_reset_tpm_established_flag(TPMBackend *tb,
                                                   uint8_t locty)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);
    ptm_reset_est reset_est;
    ptm_res res;

    /* only a TPM 2.0 will support this */
    if (tpm_pt->tpm_version == TPM_VERSION_2_0) {
        reset_est.u.req.loc = cpu_to_be32(tpm_pt->cur_locty_number);

        if (tpm_util_ctrlcmd(tpm_pt->tpm_ctrl_fd, PTM_RESET_TPMESTABLISHED,
                                 &reset_est, sizeof(reset_est),
                                 sizeof(reset_est)) < 0) {
            error_report("tpm-eulator: Could not reset the establishment bit: "
                          "%s", strerror(errno));
            return -1;
        }
        
        if ((res = be32_to_cpu(reset_est.u.resp.tpm_result)) != 0) {
            error_report("tpm-eulator: TPM result for rest establixhed flag: "
                         "0x%x", res);
            return -1;
        }
    }

    return 0;
}

static bool tpm_emulator_get_startup_error(TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);

    return tpm_pt->startup_failed;
}

static size_t tpm_emulator_realloc_buffer(TPMSizedBuffer *sb)
{
    size_t wanted_size = 4096; /* Linux tpm.c buffer size */

    if (sb->size != wanted_size) {
        sb->buffer = g_realloc(sb->buffer, wanted_size);
        sb->size = wanted_size;
    }
    return sb->size;
}

static void tpm_emulator_deliver_request(TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);

    tpm_backend_thread_deliver_request(&tpm_pt->tbt);
}

static void tpm_emulator_cancel_cmd(TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);
    ptm_res res;

    /*
     * As of Linux 3.7 the tpm_tis driver does not properly cancel
     * commands on all TPM manufacturers' TPMs.
     * Only cancel if we're busy so we don't cancel someone else's
     * command, e.g., a command executed on the host.
     */
    if (tpm_pt->tpm_executing) {
        if (TPM_EUMLATOR_IMPLEMENTS_ALL_CAPS(tpm_pt, PTM_CAP_CANCEL_TPM_CMD)) {
            if (tpm_util_ctrlcmd(tpm_pt->tpm_ctrl_fd, PTM_CANCEL_TPM_CMD, &res,
                                 0, sizeof(res)) < 0) {
                error_report("tpm-eulator: Could not cancel command: %s",
                             strerror(errno));
            } else if (res != 0) {
                error_report("tpm-eulator: Failed to cancel TPM: 0x%x", 
                             be32_to_cpu(res));
            } else {
                tpm_pt->tpm_op_canceled = true;
            }
        }
    }
}

static const char *tpm_emulator_create_desc(void)
{
    return "TPM emulator backend driver";
}

static TPMVersion tpm_emulator_get_tpm_version(TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);

    return tpm_pt->tpm_version;
}

static int tpm_emulator_handle_device_opts(QemuOpts *opts, TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);
    const char *value;

    value = qemu_opt_get(opts, "tpmstatedir");
    if (!value) {
        error_report("tpm-eulator: Missing tpm state directory");
        goto err_free_parameters;
    }
    tpm_pt->tpmstatedir = g_strdup(value);

    value = qemu_opt_get(opts, "path");
    if (!value) {
        value = TPM_DEFAULT_EMULATOR;
    }
    tpm_pt->emulator_path = g_strdup(value);

    if ((tpm_pt->tpm_fd = qemu_open("/tmp/swtpm", O_CREAT, 0755)) < 0) {
        error_report("Cannot access TPM server using '%s': %s",
                          tb->path, strerror(errno));
        goto err_free_parameters;
    }

    tpm_pt->cur_locty_number = ~0;
    if (tpm_emulator_probe_cabs(tpm_pt)) {
        goto err_close_tpm;
    }
    /* init TPM for probing */
    if (tpm_emulator_init_tpm(tpm_pt, false)) {
        goto err_close_tpm;
    }

    if (tpm_util_test_tpmdev(tpm_pt->tpm_fd, &tpm_pt->tpm_version)) {
        error_report("'%s' is not a TPM device.", tb->path);
        goto err_close_tpm;
    }

    if (tpm_emulator_check_caps(tpm_pt)) {
        goto err_close_tpm;
    }

    return 0;

 err_close_tpm:
    tpm_emulator_shutdown(tpm_pt);

    qemu_close(tpm_pt->tpm_fd);
    tpm_pt->tpm_fd = -1;
    qemu_close(tpm_pt->tpm_ctrl_fd);
    tpm_pt->tpm_ctrl_fd = -1;

 err_free_parameters:
    g_free(tb->path);
    tb->path = NULL;

    return 1;
}

static TPMBackend *tpm_emulator_create(QemuOpts *opts, const char *id)
{
    Object *obj = object_new(TYPE_TPM_EMULATOR);
    TPMBackend *tb = TPM_BACKEND(obj);

    tb->id = g_strdup(id);
    /* let frontend set the fe_model to proper value */
    tb->fe_model = -1;

    tb->ops = &tpm_emulator_driver;

    if (tpm_emulator_handle_device_opts(opts, tb)) {
        goto err_exit;
    }

    return tb;

err_exit:
    g_free(tb->id);

    return NULL;
}

static void tpm_emulator_destroy(TPMBackend *tb)
{
    TPMEmulatorState *tpm_pt = TPM_EMULATOR(tb);

    tpm_emulator_cancel_cmd(tb);

    tpm_backend_thread_end(&tpm_pt->tbt);

    tpm_emulator_shutdown(tpm_pt);

    qemu_close(tpm_pt->tpm_fd);
    qemu_close(tpm_pt->tpm_ctrl_fd);
    g_free(tpm_pt->tpmstatedir);
    g_free(tpm_pt->emulator_path);
 
    g_free(tb->id);
}

static const QemuOptDesc tpm_emulator_cmdline_opts[] = {
    TPM_STANDARD_CMDLINE_OPTS,
    {
        .name = "cancel-path",
        .type = QEMU_OPT_STRING,
        .help = "Sysfs file entry for canceling TPM commands",
    },
    {
        .name = "path",
        .type = QEMU_OPT_STRING,
        .help = "Path to TPM device on the host",
    },
    { /* end of list */ },
};

static const TPMDriverOps tpm_emulator_driver = {
    .type                     = TPM_TYPE_PASSTHROUGH,
    .opts                     = tpm_emulator_cmdline_opts,
    .desc                     = tpm_emulator_create_desc,
    .create                   = tpm_emulator_create,
    .destroy                  = tpm_emulator_destroy,
    .init                     = tpm_emulator_init,
    .startup_tpm              = tpm_emulator_startup_tpm,
    .realloc_buffer           = tpm_emulator_realloc_buffer,
    .reset                    = tpm_emulator_reset,
    .had_startup_error        = tpm_emulator_get_startup_error,
    .deliver_request          = tpm_emulator_deliver_request,
    .cancel_cmd               = tpm_emulator_cancel_cmd,
    .get_tpm_established_flag = tpm_emulator_get_tpm_established_flag,
    .reset_tpm_established_flag = tpm_emulator_reset_tpm_established_flag,
    .get_tpm_version          = tpm_emulator_get_tpm_version,
};

static void tpm_emulator_inst_init(Object *obj)
{
}

static void tpm_emulator_inst_finalize(Object *obj)
{
}

static void tpm_emulator_class_init(ObjectClass *klass, void *data)
{
    TPMBackendClass *tbc = TPM_BACKEND_CLASS(klass);

    tbc->ops = &tpm_emulator_driver;
}

static const TypeInfo tpm_emulator_info = {
    .name = TYPE_TPM_EMULATOR,
    .parent = TYPE_TPM_BACKEND,
    .instance_size = sizeof(TPMEmulatorState),
    .class_init = tpm_emulator_class_init,
    .instance_init = tpm_emulator_inst_init,
    .instance_finalize = tpm_emulator_inst_finalize,
};

static void tpm_emulator_register(void)
{
    type_register_static(&tpm_emulator_info);
    tpm_register_driver(&tpm_emulator_driver);
}

type_init(tpm_emulator_register)

