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

#ifndef LIBVFIO_USER_GLIB_H
#define LIBVFIO_USER_GLIB_H

#include <glib.h>
#include "libvfio-user.h"

typedef struct VugDev {
    VuDev parent;

    GHashTable *fdmap; /* fd -> gsource */
    GSource *src;
} VugDev;

void vug_init(VugDev *dev, int socket,
              vu_panic_cb panic, const VuDevIface *iface);
void vug_deinit(VugDev *dev);

#endif /* LIBVFIO_USER_GLIB_H */
