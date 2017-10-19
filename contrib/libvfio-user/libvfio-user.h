/*
 * libvfio-user library
 *
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * Authors:
 *  Marc-André Lureau <mlureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#ifndef LIBVFIO_USER_H
#define LIBVFIO_USER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/poll.h>
#include "standard-headers/linux/virtio_ring.h"
#include <linux/vfio.h>

typedef struct VuDev VuDev;

typedef struct VuDevIface {
    int         (*get_device_info)              (VuDev *dev,
                                                 struct vfio_device_info *info);
    ssize_t     (*read)                         (VuDev *dev,
                                                 char *buf,
                                                 size_t count,
                                                 off_t *ppos);
    ssize_t     (*write)                        (VuDev *dev,
                                                 const char *buf,
                                                 size_t count,
                                                 off_t *ppos);
    int         (*get_region_info)              (VuDev *dev,
                                                 int index,
                                                 struct vfio_region_info *info);
    int         (*get_irq_info)                 (VuDev *dev,
                                                 uint32_t index,
                                                 struct vfio_irq_info *info);
    int         (*set_irqs)                     (VuDev *dev,
                                                 uint32_t index,
                                                 uint32_t start,
                                                 int *fds,
                                                 size_t nfds,
                                                 uint32_t flags);
    int         (*reset)                        (VuDev *dev);
} VuDevIface;

enum VuWatchCondtion {
    VU_WATCH_IN = POLLIN,
    VU_WATCH_OUT = POLLOUT,
    VU_WATCH_PRI = POLLPRI,
    VU_WATCH_ERR = POLLERR,
    VU_WATCH_HUP = POLLHUP,
};

typedef void (*vu_panic_cb) (VuDev *dev, const char *err);
typedef void (*vu_watch_cb) (VuDev *dev, int condition, void *data);
typedef void (*vu_set_watch_cb) (VuDev *dev, int fd, int condition,
                                 vu_watch_cb cb, void *data);
typedef void (*vu_remove_watch_cb) (VuDev *dev, int fd);

struct VuDev {
    int sock;
    bool broken;

    /* @set_watch: add or update the given fd to the watch set,
     * call cb when condition is met */
    vu_set_watch_cb set_watch;

    /* @remove_watch: remove the given fd from the watch set */
    vu_remove_watch_cb remove_watch;

    /* @panic: encountered an unrecoverable error, you may try to
     * re-initialize */
    vu_panic_cb panic;
    const VuDevIface *iface;
};

/**
 * vu_init:
 * @dev: a VuDev context
 * @socket: the socket connected to vfio-user master
 * @panic: a panic callback
 * @set_watch: a set_watch callback
 * @remove_watch: a remove_watch callback
 * @iface: a VuDevIface structure with vfio-user device callbacks
 *
 * Intializes a VuDev vfio-user context.
 **/
void vu_init(VuDev *dev,
             int socket,
             vu_panic_cb panic,
             vu_set_watch_cb set_watch,
             vu_remove_watch_cb remove_watch,
             const VuDevIface *iface);


/**
 * vu_deinit:
 * @dev: a VuDev context
 *
 * Cleans up the VuDev context
 */
void vu_deinit(VuDev *dev);

/**
 * vu_dispatch:
 * @dev: a VuDev context
 *
 * Process one vhost-user message.
 *
 * Returns: TRUE on success, FALSE on failure.
 */
bool vu_dispatch(VuDev *dev);

#endif /* LIBVFIO_USER_H */
