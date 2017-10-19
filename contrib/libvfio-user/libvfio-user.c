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

#define LIBVFIO_USER_DEBUG 0

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

bool
vu_dispatch(VuDev *dev)
{
    VhostUserMsg vmsg = { 0, };
    int reply_requested;

    if (!vu_message_read(dev, dev->sock, &vmsg)) {
        return false;
    }

    reply_requested = vu_process_message(dev, &vmsg);
    if (!reply_requested) {
        return true;
    }

    if (!vu_message_write(dev, dev->sock, &vmsg)) {
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
    };
}

void vu_deinit(VuDev *dev)
{

}
