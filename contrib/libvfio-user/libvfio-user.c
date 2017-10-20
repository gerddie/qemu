/*
 * Vfio User library
 *
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * Authors:
 *  Marc-André Lureau <mlureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

/* this code avoids GLib dependency */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/mman.h>

#include "qemu/compiler.h"
#include "qemu/atomic.h"

#include "libvfio-user.h"
#include "vfio-user.h"

/* usually provided by GLib */
#ifndef MIN
#define MIN(x, y) ({                            \
            typeof(x) _min1 = (x);              \
            typeof(y) _min2 = (y);              \
            (void) (&_min1 == &_min2);          \
            _min1 < _min2 ? _min1 : _min2; })
#endif

#define LIBVFIO_USER_DEBUG 1

#define DPRINT(...)                             \
    do {                                        \
        if (LIBVFIO_USER_DEBUG) {              \
            fprintf(stderr, __VA_ARGS__);        \
        }                                       \
    } while (0)

static const char *
vu_request_to_string(unsigned int req)
{
#define REQ(req) [req] = #req
    static const char *vu_request_str[] = {
        REQ(VFIO_USER_REQ_NONE),
        REQ(VFIO_USER_REQ_DEV_GET_INFO),
        REQ(VFIO_USER_REQ_DEV_GET_REGION_INFO),
        REQ(VFIO_USER_REQ_DEV_GET_IRQ_INFO),
        REQ(VFIO_USER_REQ_DEV_RESET),
        REQ(VFIO_USER_REQ_MAX),
    };
#undef REQ

    if (req < VFIO_USER_REQ_MAX) {
        return vu_request_str[req];
    } else {
        return "unknown";
    }
}

static void
vu_panic(VuDev *dev, const char *msg, ...)
{
    char *buf = NULL;
    va_list ap;

    va_start(ap, msg);
    if (vasprintf(&buf, msg, ap) < 0) {
        buf = NULL;
    }
    va_end(ap);

    dev->broken = true;
    dev->panic(dev, buf);
    free(buf);

    /* FIXME: find a way to call virtio_error? */
}

static int
vu_dev_get_info(VuDev *dev, vfio_user_msg_t *vmsg)
{
    int ret = dev->iface->get_device_info(dev, &vmsg->payload.device_info);

    vmsg->size = sizeof(vmsg->payload.device_info);

    return ret;
}

static int
vu_dev_get_region_info(VuDev *dev, vfio_user_msg_t *vmsg)
{
    int ret;

    if (vmsg->size != sizeof(vmsg->payload.u32)) {
        goto err;
    }

    ret = dev->iface->get_region_info(dev, vmsg->payload.u32,
                                      &vmsg->payload.region_info);

    vmsg->size = sizeof(vmsg->payload.region_info);

    return ret;

err:
    vu_panic(dev, "failed to get region info");
    return -EINVAL;
}

static bool
vu_dev_get_irq_info(VuDev *dev, vfio_user_msg_t *vmsg)
{
    if (vmsg->size != sizeof(vmsg->payload.u32) ||
        dev->iface->get_irq_info(dev, vmsg->payload.u32,
                                 &vmsg->payload.irq_info) < 0) {
        vu_panic(dev, "failed to get irq info");
    }

    vmsg->size = sizeof(vmsg->payload.irq_info);

    return true;
}

static bool
vu_dev_reset(VuDev *dev, vfio_user_msg_t *vmsg)
{
    return dev->iface->reset(dev);
}

static void
vmsg_close_fds(vfio_user_msg_t *vmsg)
{
    int i;

    for (i = 0; i < vmsg->fd_num; i++) {
        close(vmsg->fds[i]);
    }
    vmsg->fd_num = 0;
}

static bool
vu_process_message(VuDev *dev, vfio_user_msg_t *vmsg)
{
    /* Print out generic part of the request. */
    DPRINT("================ vfio-user message ================\n");
    DPRINT("Request: %s (%d)\n", vu_request_to_string(vmsg->request),
           vmsg->request);
    DPRINT("Flags:   0x%x\n", vmsg->flags);
    DPRINT("Size:    %d\n", vmsg->size);

    if (vmsg->fd_num) {
        int i;
        DPRINT("Fds:");
        for (i = 0; i < vmsg->fd_num; i++) {
            DPRINT(" %d", vmsg->fds[i]);
        }
        DPRINT("\n");
    }

    switch (vmsg->request) {
    case VFIO_USER_REQ_DEV_GET_INFO:
        return vu_dev_get_info(dev, vmsg);
    case VFIO_USER_REQ_DEV_GET_REGION_INFO:
        return vu_dev_get_region_info(dev, vmsg);
    case VFIO_USER_REQ_DEV_GET_IRQ_INFO:
        return vu_dev_get_irq_info(dev, vmsg);
    case VFIO_USER_REQ_DEV_RESET:
        return vu_dev_reset(dev, vmsg);
    default:
        vmsg_close_fds(vmsg);
        vu_panic(dev, "Unhandled request: %d", vmsg->request);
    }

    return false;
}

static bool
vu_message_read(VuDev *dev, vfio_user_msg_t *vmsg)
{
    char control[CMSG_SPACE(VFIO_USER_MAX_FDS * sizeof(int))] = { };
    struct iovec iov = {
        .iov_base = (char *)vmsg,
        .iov_len = VFIO_USER_HDR_SIZE,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    size_t fd_size;
    struct cmsghdr *cmsg;
    int rc, fd = dev->sock;

    do {
        rc = recvmsg(fd, &msg, 0);
    } while (rc < 0 && (errno == EINTR || errno == EAGAIN));

    if (rc < 0) {
        vu_panic(dev, "Error while recvmsg: %s", strerror(errno));
        return false;
    }

    vmsg->fd_num = 0;
    for (cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            fd_size = cmsg->cmsg_len - CMSG_LEN(0);
            vmsg->fd_num = fd_size / sizeof(int);
            memcpy(vmsg->fds, CMSG_DATA(cmsg), fd_size);
            break;
        }
    }

    if (vmsg->size > sizeof(vmsg->payload)) {
        vu_panic(dev, "Invalid message size: %" PRIu32, vmsg->size);
        goto fail;
    }

    if (vmsg->size) {
        do {
            rc = read(fd, &vmsg->payload, vmsg->size);
        } while (rc < 0 && (errno == EINTR || errno == EAGAIN));

        if (rc <= 0) {
            vu_panic(dev, "Error while reading: %s", strerror(errno));
            goto fail;
        }

        if (rc != vmsg->size) {
            vu_panic(dev, "Error while reading");
            goto fail;
        }
    }

    return true;

fail:
    vmsg_close_fds(vmsg);

    return false;
}

static bool
vu_message_write(VuDev *dev, vfio_user_msg_t *vmsg)
{
    int rc, fd = dev->sock;
    uint8_t *p = (uint8_t *)vmsg;

    do {
        rc = write(fd, p, VFIO_USER_HDR_SIZE);
    } while (rc < 0 && (errno == EINTR || errno == EAGAIN));

    do {
        rc = write(fd, p + VFIO_USER_HDR_SIZE, vmsg->size);
    } while (rc < 0 && (errno == EINTR || errno == EAGAIN));

    if (rc <= 0) {
        vu_panic(dev, "Error while writing: %s", strerror(errno));
        return false;
    }

    return true;
}

bool
vu_dispatch(VuDev *dev)
{
    vfio_user_msg_t vmsg = { 0, };

    if (!vu_message_read(dev, &vmsg)) {
        return false;
    }

    vmsg.reply = vu_process_message(dev, &vmsg);

    if (!vu_message_write(dev, &vmsg)) {
        return false;
    }

    return true;
}

void
vu_init(VuDev *dev,
        int socket,
        vu_panic_cb panic,
        vu_set_watch_cb set_watch,
        vu_remove_watch_cb remove_watch,
        const VuDevIface *iface)
{
    assert(dev);
    assert(socket >= 0);
    assert(panic);
    assert(set_watch);
    assert(remove_watch);
    assert(iface);

    *dev = (VuDev) {
        .sock = socket,
        .panic = panic,
        .set_watch = set_watch,
        .remove_watch = remove_watch,
        .iface = iface,
    };
}

void vu_deinit(VuDev *dev)
{
    assert(dev);
}
